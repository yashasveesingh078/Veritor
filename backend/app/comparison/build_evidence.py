"""Work out what a repository's build produces by reading its configuration.

Everything here is static parsing. Build scripts and bundler configs are never executed,
so a config that computes its output at runtime is simply not understood, and its files
stay UNCERTAIN. Only the source repository is read: the published package is controlled
by the publisher, so it cannot vouch for its own files.
"""

import json
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from app.comparison.models import ComparisonLimits
from app.comparison.trees import FileTree, normalize_relative

COMPILERS = {"tsc", "babel", "swc"}
BUNDLERS = {
    "esbuild",
    "microbundle",
    "ncc",
    "parcel",
    "rollup",
    "rolldown",
    "rspack",
    "tsdx",
    "tsup",
    "unbuild",
    "vite",
    "webpack",
}
_DEFAULT_OUTPUT_DIRECTORIES = {
    "microbundle": "dist",
    "parcel": "dist",
    "rspack": "dist",
    "tsdx": "dist",
    "tsup": "dist",
    "unbuild": "dist",
    "vite": "dist",
    "webpack": "dist",
}
_OUTPUT_DIRECTORY_FLAGS = {"--outdir", "--out-dir", "--dir", "--dist-dir", "--output-path"}
_OUTPUT_FILE_FLAGS = {"--outfile", "--out-file", "--file"}
_SHORT_OUTPUT_FLAGS = {"-d": "directory", "-o": "either"}
_VALUE_FLAGS = {"--extensions", "--config-file"}
_OUTPUT_FILE_SUFFIXES = (".js", ".mjs", ".cjs", ".css", ".ts", ".map")
_BUILD_SCRIPT = re.compile(r"(?:build|compile|dist|bundle|prepare|prepack|prepublish)", re.I)
_COMMAND_SEPARATORS = re.compile(r"&&|\|\||;|\||(?<!\S)&(?!\S)")
_ENV_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_RUNNERS = {"npx", "pnpx", "bunx", "cross-env", "cross-env-shell", "exec"}
_SCRIPT_RUN_COMMANDS = {("npm", "run"), ("pnpm", "run"), ("yarn", "run"), ("bun", "run")}
_RUN_ALL = {"run-s", "run-p", "npm-run-all"}
_CONFIG_NAMES = {
    "rollup": "rollup.config",
    "rolldown": "rolldown.config",
    "rspack": "rspack.config",
    "tsup": "tsup.config",
    "vite": "vite.config",
    "webpack": "webpack.config",
}
_CONFIG_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")
_CONFIG_DIRECTORY = re.compile(
    r"""\b(?:outDir|outdir|dir|path)\s*:\s*(?:(?:path\.)?(?:resolve|join)\(\s*__dirname\s*,\s*)?"""
    r"""['"`]([^'"`$\[\]]+)['"`]"""
)
_CONFIG_FILE = re.compile(r"""\b(?:file|outfile)\s*:\s*['"`]([^'"`$\[\]]+)['"`]""")
_CONFIG_FILENAME = re.compile(r"""\bfilename\s*:\s*['"`]([^'"`$\[\]/]+)['"`]""")
_ENTRY_POINT_FIELDS = ("main", "module", "browser", "types", "typings", "unpkg", "jsdelivr")


@dataclass(frozen=True)
class BuildOutput:
    directory: str
    tool: str
    origin: str


@dataclass(frozen=True)
class CompilerRoot:
    tool: str
    root: str
    output_directory: str


@dataclass
class BuildProfile:
    tools: set[str] = field(default_factory=set)
    outputs: list[BuildOutput] = field(default_factory=list)
    output_files: dict[str, BuildOutput] = field(default_factory=dict)
    compiler_roots: list[CompilerRoot] = field(default_factory=list)
    # tsc with no outDir writes each file beside its source.
    tsc_emits_beside_source: str | None = None
    entry_points: dict[str, str] = field(default_factory=dict)
    files_field: list[str] = field(default_factory=list)
    gitignored_directories: set[str] = field(default_factory=set)
    unrecognized_commands: list[str] = field(default_factory=list)
    manifest_name: str | None = None
    manifest_version: str | None = None


def parse_json_with_comments(text: str) -> Any:
    """Parse tsconfig-style JSON, which allows comments and trailing commas."""
    output: list[str] = []
    position = 0
    in_string = False
    while position < len(text):
        char = text[position]
        if in_string:
            output.append(char)
            if char == "\\" and position + 1 < len(text):
                output.append(text[position + 1])
                position += 1
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
            output.append(char)
        elif text.startswith("//", position):
            end = text.find("\n", position)
            position = len(text) if end < 0 else end
            continue
        elif text.startswith("/*", position):
            end = text.find("*/", position)
            position = len(text) if end < 0 else end + 2
            continue
        else:
            output.append(char)
        position += 1
    return json.loads(_remove_trailing_commas("".join(output)))


def _remove_trailing_commas(text: str) -> str:
    output: list[str] = []
    in_string = False
    position = 0
    while position < len(text):
        char = text[position]
        if in_string:
            if char == "\\":
                output.append(text[position : position + 2])
                position += 2
                continue
            in_string = char != '"'
        elif char == '"':
            in_string = True
        elif char == ",":
            following = text[position + 1 :].lstrip()
            if following.startswith(("}", "]")):
                position += 1
                continue
        output.append(char)
        position += 1
    return "".join(output)


def _load_manifest(tree: FileTree, limits: ComparisonLimits) -> dict[str, Any] | None:
    data = tree.read("package.json", limits.max_config_bytes)
    if data is None:
        return None
    try:
        manifest = json.loads(data)
    except (ValueError, RecursionError):
        return None
    return manifest if isinstance(manifest, dict) else None


def _collect_entry_points(manifest: dict[str, Any]) -> dict[str, str]:
    found: dict[str, str] = {}

    def add(label: str, value: object) -> None:
        if isinstance(value, str):
            normalized = normalize_relative(value)
            if normalized:
                found.setdefault(normalized, label)

    def walk(label: str, value: object, depth: int = 0) -> None:
        if depth > 16:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                walk(f"{label}.{key}", item, depth + 1)
        else:
            add(label, value)

    for name in _ENTRY_POINT_FIELDS:
        walk(name, manifest.get(name))
    walk("bin", manifest.get("bin"))
    walk("exports", manifest.get("exports"))
    return found


def _command_tokens(command: str) -> list[str] | None:
    """Split one shell command, skipping environment settings and runners such as npx."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    while tokens:
        first = tokens[0]
        if _ENV_ASSIGNMENT.match(first):
            tokens = tokens[1:]
        elif posixpath.basename(first) in _RUNNERS:
            tokens = [token for token in tokens[1:] if token not in ("--no-install", "--yes", "-y")]
        else:
            break
    return tokens


def _referenced_scripts(tokens: list[str], scripts: dict[str, str]) -> list[str] | None:
    """Return the scripts a command runs, or None if it does not run any."""
    tool = posixpath.basename(tokens[0])
    if tool in _RUN_ALL:
        return [token for token in tokens[1:] if token in scripts]
    if len(tokens) >= 3 and (tool, tokens[1]) in _SCRIPT_RUN_COMMANDS:
        return [tokens[2]]
    if len(tokens) == 2 and tool in ("yarn", "pnpm", "bun") and tokens[1] in scripts:
        return [tokens[1]]
    return None


def _flag_value(tokens: list[str], position: int) -> tuple[str, str | None]:
    token = tokens[position]
    if token.startswith("--") and "=" in token:
        flag, _, value = token.partition("=")
        return flag.lower(), value
    following = tokens[position + 1] if position + 1 < len(tokens) else None
    return token.lower() if token.startswith("--") else token, following


class _ProfileBuilder:
    def __init__(self, scope: FileTree, repository: FileTree, limits: ComparisonLimits) -> None:
        self.scope = scope
        self.repository = repository
        self.limits = limits
        self.profile = BuildProfile()

    def build(self) -> BuildProfile:
        manifest = _load_manifest(self.scope, self.limits)
        self._read_gitignore()
        if manifest is None:
            return self.profile

        name, version = manifest.get("name"), manifest.get("version")
        self.profile.manifest_name = name if isinstance(name, str) else None
        self.profile.manifest_version = version if isinstance(version, str) else None
        self.profile.entry_points = _collect_entry_points(manifest)
        files = manifest.get("files")
        if isinstance(files, list):
            self.profile.files_field = [item for item in files if isinstance(item, str)]

        declared = manifest.get("scripts")
        scripts = (
            {key: value for key, value in declared.items() if isinstance(value, str)}
            if isinstance(declared, dict)
            else {}
        )
        visited: set[str] = set()
        for script in scripts:
            if _BUILD_SCRIPT.search(script):
                self._read_script(script, scripts, visited, 0)
        return self.profile

    def _read_script(
        self, name: str, scripts: dict[str, str], visited: set[str], depth: int
    ) -> None:
        if name in visited or name not in scripts or depth > self.limits.max_script_depth:
            return
        visited.add(name)
        for command in _COMMAND_SEPARATORS.split(scripts[name]):
            tokens = _command_tokens(command.strip())
            if not tokens:
                continue
            referenced = _referenced_scripts(tokens, scripts)
            if referenced is not None:
                for child in referenced:
                    self._read_script(child, scripts, visited, depth + 1)
                continue
            self._read_command(tokens, name, command.strip())

    def _read_command(self, tokens: list[str], script: str, command: str) -> None:
        tool = posixpath.basename(tokens[0])
        origin = f"package.json scripts.{script}"
        if tool not in COMPILERS and tool not in BUNDLERS:
            self.profile.unrecognized_commands.append(command[:200])
            return
        if tool == "tsc":
            self._read_tsc(tokens, origin)
            return

        self.profile.tools.add(tool)
        directories, files = self._output_flags(tokens)
        if tool in COMPILERS:
            root = _first_positional(tokens)
            for directory in directories:
                self._add_output(directory, tool, origin)
                normalized = normalize_relative(directory)
                if normalized and root is not None:
                    self.profile.compiler_roots.append(CompilerRoot(tool, root, normalized))
            for file in files:
                self._add_output_file(file, tool, origin)
            return

        for directory in directories:
            self._add_output(directory, tool, origin)
        for file in files:
            self._add_output_file(file, tool, origin)
        config_found = self._read_bundler_config(tool)
        if not directories and not files and not config_found:
            default = _DEFAULT_OUTPUT_DIRECTORIES.get(tool)
            if default is not None:
                self._add_output(default, tool, f"{origin} ({tool}'s default output directory)")

    def _output_flags(self, tokens: list[str]) -> tuple[list[str], list[str]]:
        directories: list[str] = []
        files: list[str] = []
        for position in range(1, len(tokens)):
            flag, value = _flag_value(tokens, position)
            if value is None or not tokens[position].startswith("-"):
                continue
            if flag in _OUTPUT_DIRECTORY_FLAGS or _SHORT_OUTPUT_FLAGS.get(flag) == "directory":
                directories.append(value)
            elif flag in _OUTPUT_FILE_FLAGS:
                files.append(value)
            elif _SHORT_OUTPUT_FLAGS.get(flag) == "either":
                (files if value.endswith(_OUTPUT_FILE_SUFFIXES) else directories).append(value)
        return directories, files

    def _read_tsc(self, tokens: list[str], origin: str) -> None:
        options = {token.lower() for token in tokens}
        # These commands check types, or only list settings, and produce no files.
        if options & {"--noemit", "--showconfig", "--help", "--version", "--init"}:
            return
        self.profile.tools.add("tsc")

        config_path = "tsconfig.json"
        out_dir: str | None = None
        root_dir: str | None = None
        for position in range(1, len(tokens)):
            flag, value = _flag_value(tokens, position)
            if value is None:
                continue
            if flag in ("-p", "--project", "-b", "--build"):
                if not value.startswith("-"):
                    config_path = value
            elif flag == "--outdir":
                out_dir = value
            elif flag == "--rootdir":
                root_dir = value

        options_found, config_file = self._load_tsconfig(config_path)
        if options_found.get("noEmit") is True and out_dir is None:
            return
        out_dir = out_dir or _as_text(options_found.get("outDir"))
        root_dir = root_dir or _as_text(options_found.get("rootDir"))
        source_label = origin if out_dir is None else config_file or origin

        if out_dir is None:
            if config_file is not None:
                self.profile.tsc_emits_beside_source = config_file
            return
        normalized_out = normalize_relative(out_dir)
        if normalized_out:
            self._add_output(normalized_out, "tsc", source_label)
            root = normalize_relative(root_dir) if root_dir else None
            self.profile.compiler_roots.append(
                CompilerRoot("tsc", root if root is not None else "src", normalized_out)
            )
            if root is None:
                # With no rootDir, tsc uses the sources' common directory, which is often
                # the project root.
                self.profile.compiler_roots.append(CompilerRoot("tsc", "", normalized_out))
        declaration = _as_text(options_found.get("declarationDir"))
        if declaration:
            self._add_output(declaration, "tsc", source_label)

    def _load_tsconfig(self, path: str) -> tuple[dict[str, Any], str | None]:
        """Follow `extends` within the repository. Later files override earlier ones.

        Paths in a config are relative to that config, so they are converted to paths in
        the scope as each one is read.
        """
        normalized = normalize_relative(path)
        if normalized is None:
            return {}, None
        if not normalized.endswith(".json"):
            normalized = posixpath.join(normalized, "tsconfig.json")
        prefix = f"{self.scope.directory}/" if self.scope.directory else ""
        options, found = self._read_tsconfig_chain(f"{prefix}{normalized}", set())
        return options, normalized if found else None

    def _read_tsconfig_chain(self, path: str, visited: set[str]) -> tuple[dict[str, Any], bool]:
        if path in visited or len(visited) >= 16:
            return {}, False
        visited.add(path)
        data = self.repository.read(path, self.limits.max_config_bytes)
        if data is None:
            return {}, False
        try:
            config = parse_json_with_comments(data.decode())
        except (ValueError, RecursionError):
            return {}, False
        if not isinstance(config, dict):
            return {}, False

        options: dict[str, Any] = {}
        extends = config.get("extends")
        parents = extends if isinstance(extends, list) else [extends]
        for parent in parents:
            if isinstance(parent, str) and parent.startswith("."):
                joined = normalize_relative(posixpath.join(posixpath.dirname(path), parent))
                if joined:
                    if not joined.endswith(".json"):
                        joined += ".json"
                    options.update(self._read_tsconfig_chain(joined, visited)[0])

        compiler_options = config.get("compilerOptions")
        if isinstance(compiler_options, dict):
            for key, value in compiler_options.items():
                if key in ("outDir", "rootDir", "declarationDir") and isinstance(value, str):
                    options[key] = self._scope_relative(path, value)
                else:
                    options[key] = value
        return options, True

    def _scope_relative(self, config_path: str, value: str) -> str | None:
        joined = normalize_relative(posixpath.join(posixpath.dirname(config_path), value))
        if joined is None:
            return None
        if not self.scope.directory:
            return joined
        if joined == self.scope.directory:
            return ""
        prefix = f"{self.scope.directory}/"
        return joined.removeprefix(prefix) if joined.startswith(prefix) else None

    def _read_bundler_config(self, tool: str) -> bool:
        stem = _CONFIG_NAMES.get(tool)
        if stem is None:
            return False
        for suffix in _CONFIG_SUFFIXES:
            name = f"{stem}{suffix}"
            data = self.scope.read(name, self.limits.max_config_bytes)
            if data is None:
                continue
            text = data.decode(errors="replace")
            directories = _CONFIG_DIRECTORY.findall(text)
            for directory in directories:
                self._add_output(directory, tool, name)
            for file in _CONFIG_FILE.findall(text):
                self._add_output_file(file, tool, name)
            filenames = _CONFIG_FILENAME.findall(text)
            for directory in directories:
                for filename in filenames:
                    self._add_output_file(posixpath.join(directory, filename), tool, name)
            if not directories and tool in _DEFAULT_OUTPUT_DIRECTORIES:
                default = _DEFAULT_OUTPUT_DIRECTORIES[tool]
                self._add_output(default, tool, f"{name} ({tool}'s default output directory)")
            return True
        return False

    def _add_output(self, directory: str, tool: str, origin: str) -> None:
        normalized = normalize_relative(directory)
        # An output directory of the project root would vouch for every file in the package.
        if normalized:
            self.profile.outputs.append(BuildOutput(normalized, tool, origin))

    def _add_output_file(self, path: str, tool: str, origin: str) -> None:
        normalized = normalize_relative(path)
        if normalized:
            self.profile.output_files[normalized] = BuildOutput(
                posixpath.dirname(normalized), tool, origin
            )

    def _read_gitignore(self) -> None:
        for directory_tree in (self.scope, self.repository):
            data = directory_tree.read(".gitignore", self.limits.max_config_bytes)
            if data is None:
                continue
            for line in data.decode(errors="replace").splitlines():
                cleaned = line.strip()
                if cleaned and not cleaned.startswith(("#", "!")) and "*" not in cleaned:
                    normalized = normalize_relative(cleaned.lstrip("/"))
                    if normalized:
                        self.profile.gitignored_directories.add(normalized)


def _first_positional(tokens: list[str]) -> str | None:
    position = 1
    while position < len(tokens):
        argument = tokens[position]
        if argument.startswith("-"):
            has_value = "=" not in argument and (
                argument.lower() in _OUTPUT_DIRECTORY_FLAGS
                or argument.lower() in _OUTPUT_FILE_FLAGS
                or argument in _SHORT_OUTPUT_FLAGS
                or argument in _VALUE_FLAGS
            )
            position += 2 if has_value else 1
            continue
        return normalize_relative(argument)
    return None


def _as_text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def collect_build_profile(
    scope: FileTree, repository: FileTree, limits: ComparisonLimits
) -> BuildProfile:
    return _ProfileBuilder(scope, repository, limits).build()
