"""Find security-relevant behaviour in JavaScript and TypeScript by reading the syntax tree.

The code is only parsed, never run. Comments do not match, and common tricks such as
`require('chi' + 'ld_process')`, `global['ev' + 'al']` and `(0, eval)(x)` are resolved
statically. Anything computed at runtime is reported as computed, not guessed at.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from typing import NamedTuple

import tree_sitter
import tree_sitter_javascript
import tree_sitter_typescript

from app.analysis.models import FindingConfidence, Severity

MAX_EVIDENCE_CHARS = 200
_MAX_EXPRESSION_DEPTH = 64
_MAX_SUBTREE_NODES = 2_000


class Signal(StrEnum):
    """A behaviour that means more in combination than on its own."""

    EXECUTION = "execution"
    PROCESS = "process"
    CREDENTIAL = "credential"
    NETWORK = "network"
    DECODE = "decode"
    OBFUSCATION = "obfuscation"


@dataclass(frozen=True)
class Hit:
    rule_id: str
    line: int
    severity: Severity
    confidence: FindingConfidence
    evidence: str
    signal: Signal | None = None


@dataclass(frozen=True)
class ScanResult:
    hits: tuple[Hit, ...]
    has_parse_errors: bool


class _Callee(NamedTuple):
    module: str | None
    name: str | None


_GLOBAL_OBJECTS = {"global", "globalThis", "window", "self"}
_PROCESS_FUNCTIONS = {
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
    "spawn",
    "spawnSync",
    "fork",
}
_VM_FUNCTIONS = {
    "runInThisContext",
    "runInNewContext",
    "runInContext",
    "compileFunction",
    "Script",
}
_NETWORK_GLOBAL_CALLS = {"fetch", "navigator.sendBeacon", "Deno.connect"}
_NETWORK_CONSTRUCTORS = {"XMLHttpRequest", "WebSocket", "EventSource"}
_NETWORK_MODULE_FUNCTIONS = {
    "http": {"request", "get"},
    "https": {"request", "get"},
    "http2": {"connect"},
    "net": {"connect", "createConnection", "Socket"},
    "tls": {"connect"},
    "dgram": {"createSocket"},
    "dns": {"lookup", "resolve", "resolve4", "resolve6", "resolveTxt"},
}
_NETWORK_LIBRARIES = {
    "axios",
    "cross-fetch",
    "got",
    "needle",
    "node-fetch",
    "request",
    "superagent",
    "undici",
    "ws",
}
_FS_READS = {
    "readFile",
    "readFileSync",
    "createReadStream",
    "open",
    "openSync",
    "copyFile",
    "copyFileSync",
    "readdir",
    "readdirSync",
}
_FS_WRITES = {
    "writeFile",
    "writeFileSync",
    "appendFile",
    "appendFileSync",
    "createWriteStream",
    "symlink",
    "symlinkSync",
}
_DECODE_ENCODINGS = {"base64", "base64url", "hex"}
_CREDENTIAL_NAME = re.compile(
    r"TOKEN|SECRET|PASSW|API_?KEY|PRIVATE|CREDENTIAL|AUTH(?!OR)|SESSION|COOKIE|"
    r"^AWS_|^NPM_|^GITHUB_|^GH_|^SSH_",
    re.I,
)
_COLLECTION_HOST = re.compile(
    r"discord(?:app)?\.com/api/webhooks|webhook\.site|pipedream\.net|requestbin|"
    r"oastify\.com|burpcollaborator\.net|interact\.sh|ngrok(?:-free)?\.(?:io|app)|"
    r"pastebin\.com|transfer\.sh|api\.telegram\.org/bot|\.onion\b",
    re.I,
)
_PUBLIC_IP_URL = re.compile(
    r"\b(?!(?:127|10|0)\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)"
    r"(?:\d{1,3}\.){3}\d{1,3}\b"
)
_RISKY_COMMAND = re.compile(
    r"(?:curl|wget|iwr|Invoke-WebRequest)\b.*(?:\||&&|;).*\b(?:sh|bash|zsh|node|python\d?|powershell|iex)\b"
    r"|base64\s+(?:-d|-D|--decode)|powershell.*-e(?:nc|ncodedcommand)?\b|/dev/tcp/|\bnc\s+-e\b",
    re.I | re.S,
)
_SECRET_PATH = re.compile(
    r"\.ssh\b|id_rsa|id_ed25519|\.npmrc|\.netrc|\.aws\b|\.git-credentials|\.docker/config|"
    r"\.kube\b|/etc/passwd|/etc/shadow|Login Data|\.pgpass|wallet\.dat|\.gnupg|"
    r"(?:^|[/\\\s])\.env(?:\.\w+)?(?:$|\s)",
)
_STARTUP_PATH = re.compile(
    r"\.bashrc|\.zshrc|\.bash_profile|\.profile\b|authorized_keys|crontab|/etc/cron|"
    r"LaunchAgents|systemd/|Start Menu",
)
_OBFUSCATOR_NAME = re.compile(r"_0x[0-9a-fA-F]{3,}")
_OBFUSCATOR_MIN_NAMES = 8
_BASE64_TEXT = re.compile(r"[A-Za-z0-9+/_-]{200,}={0,2}")
_HEX_TEXT = re.compile(r"[0-9a-fA-F]{200,}")
_MIN_ENCODED_ENTROPY = 3.5
_MIN_CHAR_CODES = 8
_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|u\{[0-9a-fA-F]{1,6}\}|[\s\S])")
_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "b": "\b", "f": "\f", "v": "\v"}
_WHITESPACE = re.compile(r"\s+")
_COLLECTED_TYPES = frozenset(
    {
        "call_expression",
        "new_expression",
        "member_expression",
        "subscript_expression",
        "string",
        "template_string",
        "import_statement",
        "variable_declarator",
        "assignment_expression",
    }
)
_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx")
_TS_SUFFIXES = (".ts", ".mts", ".cts")


def scannable_language(path: str) -> str | None:
    lowered = path.lower()
    if lowered.endswith((".d.ts", ".d.mts", ".d.cts")):
        return None
    if lowered.endswith(_JS_SUFFIXES):
        return "javascript"
    if lowered.endswith(".tsx"):
        return "tsx"
    if lowered.endswith(_TS_SUFFIXES):
        return "typescript"
    return None


@lru_cache(maxsize=3)
def _parser(language: str) -> tree_sitter.Parser:
    capsule = {
        "javascript": tree_sitter_javascript.language,
        "typescript": tree_sitter_typescript.language_typescript,
        "tsx": tree_sitter_typescript.language_tsx,
    }[language]()
    return tree_sitter.Parser(tree_sitter.Language(capsule))


def _decode_escapes(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        body = match.group(1)
        if body[0] in "xu" and len(body) > 1:
            digits = body[1:].strip("{}")
            code = int(digits, 16)
            return chr(code) if code <= 0x10FFFF else ""
        return _SIMPLE_ESCAPES.get(body, body)

    return _ESCAPE.sub(replace, text)


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum((count / len(text)) * math.log2(count / len(text)) for count in counts.values())


class _Scanner:
    def __init__(self, source: bytes, language: str) -> None:
        self.source = source
        self.tree = _parser(language).parse(source)
        self.hits: list[Hit] = []
        # local name -> module, for `const cp = require('child_process')`
        self.module_aliases: dict[str, str] = {}
        # local name -> (module, export), for `const { exec } = require('child_process')`
        self.named_imports: dict[str, tuple[str, str]] = {}
        # local name -> global, for `const e = eval`
        self.global_aliases: dict[str, str] = {}
        self.environment_aliases: set[str] = set()
        self.reported_environment: set[str] = set()

    def scan(self) -> ScanResult:
        collected = self._collect()
        for node in collected:
            if node.type in ("import_statement", "variable_declarator", "assignment_expression"):
                self._record_binding(node)
        for node in collected:
            if node.type in ("call_expression", "new_expression"):
                self._check_call(node)
            elif node.type in ("member_expression", "subscript_expression"):
                self._check_environment(node)
            elif node.type in ("string", "template_string"):
                self._check_string(node)
        hits = sorted(self.hits, key=lambda hit: (hit.line, hit.rule_id, hit.evidence))
        return ScanResult(tuple(hits), self.tree.root_node.has_error)

    def _collect(self) -> list[tree_sitter.Node]:
        """Walk without recursion, because attacker-controlled code can nest very deeply."""
        collected: list[tree_sitter.Node] = []
        obfuscated_names: set[str] = set()
        first_obfuscated: tree_sitter.Node | None = None
        stack = [self.tree.root_node]
        while stack:
            node = stack.pop()
            if node.type in _COLLECTED_TYPES:
                collected.append(node)
            elif node.type == "identifier" and node.end_byte - node.start_byte >= 5:
                name = self._text(node)
                if _OBFUSCATOR_NAME.fullmatch(name):
                    obfuscated_names.add(name)
                    first_obfuscated = first_obfuscated or node
            stack.extend(node.children)

        if len(obfuscated_names) >= _OBFUSCATOR_MIN_NAMES and first_obfuscated is not None:
            self._hit(
                "OBF-001",
                first_obfuscated,
                Severity.MEDIUM,
                FindingConfidence.HIGH,
                Signal.OBFUSCATION,
                evidence=(
                    f"{len(obfuscated_names)} identifiers such as {self._text(first_obfuscated)}"
                ),
            )
        collected.sort(key=lambda item: item.start_byte)
        return collected

    def _text(self, node: tree_sitter.Node) -> str:
        return self.source[node.start_byte : node.end_byte].decode(errors="replace")

    def _hit(
        self,
        rule_id: str,
        node: tree_sitter.Node,
        severity: Severity,
        confidence: FindingConfidence,
        signal: Signal | None = None,
        evidence: str | None = None,
    ) -> None:
        text = evidence if evidence is not None else self._text(node)
        cleaned = _WHITESPACE.sub(" ", text).strip()[:MAX_EVIDENCE_CHARS]
        self.hits.append(
            Hit(rule_id, node.start_point[0] + 1, severity, confidence, cleaned, signal)
        )

    # Static resolution of values

    def _unwrap(self, node: tree_sitter.Node) -> tree_sitter.Node:
        for _ in range(_MAX_EXPRESSION_DEPTH):
            if node.type in ("parenthesized_expression", "await_expression"):
                children = node.named_children
                if not children:
                    return node
                node = children[-1]
            elif node.type == "sequence_expression":
                # `(0, eval)(x)` calls whatever the last expression is.
                node = node.named_children[-1]
            elif node.type in ("non_null_expression", "as_expression", "satisfies_expression"):
                node = node.named_children[0]
            else:
                break
        return node

    def _static_string(self, node: tree_sitter.Node, depth: int = 0) -> str | None:
        """Return a string's value if it is fixed in the code, or None if it is computed."""
        if depth > _MAX_EXPRESSION_DEPTH:
            return None
        node = self._unwrap(node)
        if node.type == "string":
            return _decode_escapes(self._text(node)[1:-1])
        if node.type == "template_string":
            if any(child.type == "template_substitution" for child in node.children):
                return None
            return _decode_escapes(self._text(node)[1:-1])
        if node.type == "binary_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            operator = node.child_by_field_name("operator")
            if left and right and operator and operator.type == "+":
                left_text = self._static_string(left, depth + 1)
                right_text = self._static_string(right, depth + 1)
                if left_text is not None and right_text is not None:
                    return left_text + right_text
        return None

    def _subtree_strings(self, node: tree_sitter.Node) -> str:
        """Join the fixed strings inside an expression, to catch path.join(home, '.ssh')."""
        found: list[str] = []
        visited = 0
        stack = [node]
        while stack and visited < _MAX_SUBTREE_NODES:
            current = stack.pop()
            visited += 1
            if current.type == "string":
                found.append(_decode_escapes(self._text(current)[1:-1]))
            elif current.type == "template_string":
                found.extend(
                    self._text(child)
                    for child in current.children
                    if child.type == "string_fragment"
                )
            else:
                stack.extend(current.children)
        return " ".join(reversed(found))

    def _contains_decoder(self, node: tree_sitter.Node) -> bool:
        visited = 0
        stack = [node]
        while stack and visited < _MAX_SUBTREE_NODES:
            current = stack.pop()
            visited += 1
            if current.type == "call_expression" and self._is_decoder(current):
                return True
            stack.extend(current.children)
        return False

    def _is_decoder(self, call: tree_sitter.Node) -> bool:
        function = call.child_by_field_name("function")
        if function is None:
            return False
        name = self._callee(function).name
        if self._callee(function).module is not None:
            return False
        if name in ("atob", "unescape", "String.fromCharCode"):
            return True
        if name == "Buffer.from":
            arguments = self._arguments(call)
            if len(arguments) >= 2:
                encoding = self._static_string(arguments[1])
                return encoding is not None and encoding.lower() in _DECODE_ENCODINGS
        return False

    def _arguments(self, call: tree_sitter.Node) -> list[tree_sitter.Node]:
        arguments = call.child_by_field_name("arguments")
        if arguments is None or arguments.type == "template_string":
            return []
        return [child for child in arguments.named_children if child.type != "comment"]

    def _dotted_name(self, node: tree_sitter.Node, depth: int = 0) -> str | None:
        node = self._unwrap(node)
        if depth > _MAX_EXPRESSION_DEPTH:
            return None
        if node.type in ("identifier", "this", "property_identifier"):
            return self._text(node)
        if node.type == "member_expression":
            base = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            if base is None or prop is None:
                return None
            parent = self._dotted_name(base, depth + 1)
            return f"{parent}.{self._text(prop)}" if parent else None
        if node.type == "subscript_expression":
            base = node.child_by_field_name("object")
            index = node.child_by_field_name("index")
            if base is None or index is None:
                return None
            parent = self._dotted_name(base, depth + 1)
            key = self._static_string(index)
            return f"{parent}.{key}" if parent and key is not None else None
        return None

    def _module_of(self, node: tree_sitter.Node) -> str | None:
        """Return the module that an expression evaluates to, if that can be determined."""
        node = self._unwrap(node)
        if node.type == "identifier":
            return self.module_aliases.get(self._text(node))
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function is None:
                return None
            function = self._unwrap(function)
            is_loader = function.type == "import" or self._text(function) in (
                "require",
                "module.require",
            )
            arguments = self._arguments(node)
            if is_loader and arguments:
                value = self._static_string(arguments[0])
                return _normalize_module(value) if value is not None else None
        return None

    def _callee(self, function: tree_sitter.Node, depth: int = 0) -> _Callee:
        function = self._unwrap(function)
        if depth > _MAX_EXPRESSION_DEPTH:
            return _Callee(None, None)
        if function.type == "identifier":
            name = self._text(function)
            if name in self.named_imports:
                module, export = self.named_imports[name]
                return _Callee(module, export)
            if name in self.module_aliases:
                return _Callee(self.module_aliases[name], None)
            return _Callee(None, self.global_aliases.get(name, name))
        if function.type in ("member_expression", "subscript_expression"):
            base = function.child_by_field_name("object")
            prop = (
                function.child_by_field_name("property")
                if function.type == "member_expression"
                else function.child_by_field_name("index")
            )
            if base is None or prop is None:
                return _Callee(None, None)
            key = (
                self._text(prop)
                if function.type == "member_expression"
                else self._static_string(prop)
            )
            base_module = self._module_of(base)
            if base_module is None and self._unwrap(base).type in (
                "member_expression",
                "subscript_expression",
            ):
                # `fs.promises.readFile` belongs to fs.
                base_module = self._callee(base, depth + 1).module
            if base_module is not None:
                return _Callee(base_module, key)
            dotted = self._dotted_name(function)
            if dotted is None:
                return _Callee(None, None)
            root, _, rest = dotted.partition(".")
            if root in _GLOBAL_OBJECTS and rest:
                return _Callee(None, self.global_aliases.get(rest, rest))
            return _Callee(None, dotted)
        return _Callee(None, None)

    def _record_binding(self, node: tree_sitter.Node) -> None:
        if node.type == "import_statement":
            self._record_import(node)
            return
        field = "name" if node.type == "variable_declarator" else "left"
        target = node.child_by_field_name(field)
        value = node.child_by_field_name("value" if field == "name" else "right")
        if target is None or value is None:
            return
        module = self._module_of(value)
        if target.type == "identifier":
            name = self._text(target)
            if module is not None:
                self.module_aliases[name] = module
                return
            unwrapped = self._unwrap(value)
            if unwrapped.type == "identifier" and self._text(unwrapped) in ("eval", "Function"):
                self.global_aliases[name] = self._text(unwrapped)
            elif self._is_process_env(unwrapped):
                self.environment_aliases.add(name)
        elif target.type == "object_pattern" and module is not None:
            for child in target.named_children:
                if child.type == "shorthand_property_identifier_pattern":
                    self.named_imports[self._text(child)] = (module, self._text(child))
                elif child.type == "pair_pattern":
                    key = child.child_by_field_name("key")
                    local = child.child_by_field_name("value")
                    if key is not None and local is not None and local.type == "identifier":
                        self.named_imports[self._text(local)] = (module, self._text(key))

    def _record_import(self, node: tree_sitter.Node) -> None:
        source = node.child_by_field_name("source")
        if source is None:
            for child in node.named_children:
                if child.type == "import_require_clause":
                    source = child.child_by_field_name("source")
                    for name in child.named_children:
                        if name.type == "identifier" and source is not None:
                            self.module_aliases[self._text(name)] = _normalize_module(
                                self._static_string(source) or ""
                            )
            return
        value = self._static_string(source)
        if value is None:
            return
        module = _normalize_module(value)
        for child in node.named_children:
            if child.type != "import_clause":
                continue
            for clause in child.named_children:
                if clause.type == "identifier":
                    self.module_aliases[self._text(clause)] = module
                elif clause.type == "namespace_import":
                    for name in clause.named_children:
                        self.module_aliases[self._text(name)] = module
                elif clause.type == "named_imports":
                    for specifier in clause.named_children:
                        imported = specifier.child_by_field_name("name")
                        alias = specifier.child_by_field_name("alias")
                        if imported is not None:
                            local = alias if alias is not None else imported
                            self.named_imports[self._text(local)] = (module, self._text(imported))
        if module == "child_process":
            self._hit("PROC-001", node, Severity.INFO, FindingConfidence.HIGH)

    # Rules on calls

    def _check_call(self, node: tree_sitter.Node) -> None:
        is_new = node.type == "new_expression"
        function = node.child_by_field_name("constructor" if is_new else "function")
        if function is None:
            return
        arguments = self._arguments(node)
        callee = self._callee(function)

        if self._check_loader(node, function, arguments):
            return
        if callee.module == "child_process":
            self._check_process_call(node, callee, arguments)
        elif callee.module == "vm":
            if callee.name in _VM_FUNCTIONS:
                self._check_execution(node, arguments)
        elif callee.module is None and callee.name is not None:
            self._check_global_call(node, callee.name, arguments, is_new)
        if callee.module is not None:
            self._check_network(node, callee, arguments)
            self._check_filesystem(node, callee, arguments)

    def _check_loader(
        self,
        node: tree_sitter.Node,
        function: tree_sitter.Node,
        arguments: list[tree_sitter.Node],
    ) -> bool:
        function = self._unwrap(function)
        is_loader = function.type == "import" or self._text(function) in (
            "require",
            "module.require",
        )
        if not is_loader or not arguments:
            return False
        value = self._static_string(arguments[0])
        if value is not None:
            if _normalize_module(value) == "child_process":
                self._hit("PROC-001", node, Severity.INFO, FindingConfidence.HIGH)
        elif self._contains_decoder(arguments[0]):
            self._hit(
                "EXEC-005",
                node,
                Severity.HIGH,
                FindingConfidence.HIGH,
                Signal.EXECUTION,
            )
        else:
            self._hit("EXEC-004", node, Severity.LOW, FindingConfidence.MEDIUM)
        return True

    def _check_global_call(
        self, node: tree_sitter.Node, name: str, arguments: list[tree_sitter.Node], is_new: bool
    ) -> None:
        if name in ("eval", "Function") or name.endswith(".constructor.constructor"):
            self._check_execution(node, arguments)
        elif name in ("setTimeout", "setInterval") and arguments:
            if self._static_string(arguments[0]) is not None:
                self._hit("EXEC-002", node, Severity.LOW, FindingConfidence.HIGH)
        elif name == "process.binding" and arguments:
            value = self._static_string(arguments[0])
            if value in ("spawn_sync", "process_wrap", "pipe_wrap", "tcp_wrap"):
                self._hit("PROC-005", node, Severity.HIGH, FindingConfidence.HIGH, Signal.PROCESS)
        elif name in _NETWORK_GLOBAL_CALLS or (is_new and name in _NETWORK_CONSTRUCTORS):
            self._network_hit(node, arguments)
        elif name in ("atob", "String.fromCharCode", "Buffer.from"):
            self._check_decoder(node, name, arguments)

    def _check_decoder(
        self, node: tree_sitter.Node, name: str, arguments: list[tree_sitter.Node]
    ) -> None:
        if name == "String.fromCharCode":
            numeric = sum(1 for argument in arguments if argument.type == "number")
            if numeric >= _MIN_CHAR_CODES:
                self._hit("OBF-003", node, Severity.MEDIUM, FindingConfidence.MEDIUM, Signal.DECODE)
            return
        if self._is_decoder(node):
            self._hit("OBF-004", node, Severity.INFO, FindingConfidence.HIGH, Signal.DECODE)

    def _check_execution(self, node: tree_sitter.Node, arguments: list[tree_sitter.Node]) -> None:
        if arguments and all(self._static_string(item) is not None for item in arguments):
            # Function('return this')() is a common way to find the global object.
            self._hit("EXEC-002", node, Severity.LOW, FindingConfidence.HIGH)
        elif any(self._contains_decoder(item) for item in arguments):
            self._hit("EXEC-003", node, Severity.CRITICAL, FindingConfidence.HIGH, Signal.EXECUTION)
        elif arguments:
            self._hit("EXEC-001", node, Severity.MEDIUM, FindingConfidence.MEDIUM, Signal.EXECUTION)

    def _check_process_call(
        self, node: tree_sitter.Node, callee: _Callee, arguments: list[tree_sitter.Node]
    ) -> None:
        if callee.name not in _PROCESS_FUNCTIONS or not arguments:
            return
        command = " ".join(self._subtree_strings(item) for item in arguments)
        if _RISKY_COMMAND.search(command) or any(
            self._contains_decoder(item) for item in arguments
        ):
            self._hit("PROC-004", node, Severity.HIGH, FindingConfidence.HIGH, Signal.PROCESS)
        elif self._static_string(arguments[0]) is not None:
            self._hit("PROC-002", node, Severity.LOW, FindingConfidence.HIGH, Signal.PROCESS)
        else:
            self._hit("PROC-003", node, Severity.MEDIUM, FindingConfidence.MEDIUM, Signal.PROCESS)

    def _check_network(
        self, node: tree_sitter.Node, callee: _Callee, arguments: list[tree_sitter.Node]
    ) -> None:
        functions = _NETWORK_MODULE_FUNCTIONS.get(callee.module or "")
        if callee.module in _NETWORK_LIBRARIES or (
            functions is not None and callee.name in functions
        ):
            self._network_hit(node, arguments)

    def _network_hit(self, node: tree_sitter.Node, arguments: list[tree_sitter.Node]) -> None:
        destination = " ".join(self._subtree_strings(item) for item in arguments[:2])
        if _COLLECTION_HOST.search(destination) or _PUBLIC_IP_URL.search(destination):
            self._hit("NET-002", node, Severity.HIGH, FindingConfidence.HIGH, Signal.NETWORK)
        else:
            self._hit("NET-001", node, Severity.INFO, FindingConfidence.HIGH, Signal.NETWORK)

    def _check_filesystem(
        self, node: tree_sitter.Node, callee: _Callee, arguments: list[tree_sitter.Node]
    ) -> None:
        if callee.module != "fs" or not arguments:
            return
        is_write = callee.name in _FS_WRITES
        if not is_write and callee.name not in _FS_READS:
            return
        path_text = self._subtree_strings(arguments[0])
        is_secret = _SECRET_PATH.search(path_text) is not None
        is_startup = _STARTUP_PATH.search(path_text) is not None
        if is_write and (is_secret or is_startup):
            self._hit("FS-002", node, Severity.HIGH, FindingConfidence.HIGH)
        elif is_secret:
            self._hit("FS-001", node, Severity.MEDIUM, FindingConfidence.MEDIUM, Signal.CREDENTIAL)

    # Rules on the environment

    def _is_process_env(self, node: tree_sitter.Node) -> bool:
        return self._dotted_name(node) in ("process.env", "Bun.env", "Deno.env")

    def _check_environment(self, node: tree_sitter.Node) -> None:
        if self._is_process_env(node):
            self._check_whole_environment(node)
            return
        base = node.child_by_field_name("object")
        if base is None:
            return
        unwrapped = self._unwrap(base)
        is_alias = (
            unwrapped.type == "identifier" and self._text(unwrapped) in self.environment_aliases
        )
        if not is_alias and not self._is_process_env(unwrapped):
            return
        parent = node.parent
        if (
            parent is not None
            and parent.type == "assignment_expression"
            and parent.child_by_field_name("left") == node
        ):
            return
        if node.type == "member_expression":
            prop = node.child_by_field_name("property")
            name = self._text(prop) if prop is not None else None
        else:
            index = node.child_by_field_name("index")
            name = self._static_string(index) if index is not None else None
        if name is None:
            self._hit("ENV-001", node, Severity.LOW, FindingConfidence.LOW)
        else:
            self._environment_name_hit(node, name)

    def _environment_name_hit(self, node: tree_sitter.Node, name: str) -> None:
        if name in self.reported_environment:
            return
        self.reported_environment.add(name)
        if _CREDENTIAL_NAME.search(name):
            self._hit("ENV-002", node, Severity.MEDIUM, FindingConfidence.MEDIUM, Signal.CREDENTIAL)
        else:
            self._hit("ENV-001", node, Severity.INFO, FindingConfidence.HIGH)

    def _check_whole_environment(self, node: tree_sitter.Node) -> None:
        parent = node.parent
        if parent is None:
            return
        if (
            parent.type in ("member_expression", "subscript_expression")
            and parent.child_by_field_name("object") == node
        ):
            return
        if parent.type == "variable_declarator":
            target = parent.child_by_field_name("name")
            if target is not None and target.type == "object_pattern":
                for child in target.named_children:
                    if child.type == "shorthand_property_identifier_pattern":
                        self._environment_name_hit(child, self._text(child))
                    elif child.type == "pair_pattern":
                        key = child.child_by_field_name("key")
                        if key is not None:
                            self._environment_name_hit(child, self._text(key))
            return
        if parent.type in ("binary_expression", "unary_expression", "assignment_expression"):
            return
        self._hit("ENV-003", parent, Severity.MEDIUM, FindingConfidence.MEDIUM, Signal.CREDENTIAL)

    # Rules on strings

    def _check_string(self, node: tree_sitter.Node) -> None:
        text = self._static_string(node)
        if text is None or len(text) < 8:
            return
        if _COLLECTION_HOST.search(text):
            self._hit("NET-003", node, Severity.MEDIUM, FindingConfidence.HIGH, Signal.NETWORK)
        if len(text) >= 200:
            is_hex = _HEX_TEXT.fullmatch(text) is not None
            is_base64 = not is_hex and _BASE64_TEXT.fullmatch(text) is not None
            if (is_hex or is_base64) and _entropy(text) >= _MIN_ENCODED_ENTROPY:
                self._hit(
                    "OBF-002",
                    node,
                    Severity.LOW,
                    FindingConfidence.MEDIUM,
                    Signal.OBFUSCATION,
                    evidence=f"{len(text)} characters: {text[:60]}...",
                )


def _normalize_module(name: str) -> str:
    cleaned = name.removeprefix("node:")
    return "fs" if cleaned == "fs/promises" else cleaned


def scan_source(source: bytes, language: str) -> ScanResult:
    """Scan one file's bytes. They are parsed but never executed."""
    return _Scanner(source, language).scan()
