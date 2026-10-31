"""Check npm install scripts, which run automatically with the user's permissions."""

import json
import re
from typing import Any

from app.adapters.base import PackageMetadata
from app.analysis.js_scanner import MAX_EVIDENCE_CHARS
from app.analysis.models import Finding, FindingConfidence, Severity
from app.analysis.rules import RULES

INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "preuninstall", "uninstall")
_MAX_MANIFEST_BYTES = 1024 * 1024
_RISKY_SCRIPT = re.compile(
    r"\b(?:curl|wget|iwr|Invoke-WebRequest)\b|base64\s+(?:-d|-D|--decode)|"
    r"\bnode\s+(?:-e|--eval|-p|--print)\b|\bpython\d?\s+-c\b|\b(?:ba)?sh\s+-c\b|"
    r"powershell|/dev/tcp/|\beval\b",
    re.I,
)


def load_scripts(manifest_bytes: bytes | None) -> dict[str, str] | None:
    """Return a package.json's install scripts, or None if it cannot be read."""
    if manifest_bytes is None:
        return None
    try:
        manifest: Any = json.loads(manifest_bytes)
    except (ValueError, RecursionError):
        return None
    if not isinstance(manifest, dict):
        return None
    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict):
        return {}
    return {name: scripts[name] for name in INSTALL_SCRIPTS if isinstance(scripts.get(name), str)}


def check_lifecycle(
    metadata: PackageMetadata,
    package_manifest: bytes | None,
    source_manifest: bytes | None,
    source_established: bool,
    binding_gyp_added: bool,
) -> list[Finding]:
    tarball = load_scripts(package_manifest) or {}
    registry = {
        name: metadata.scripts[name] for name in INSTALL_SCRIPTS if name in metadata.scripts
    }
    source = load_scripts(source_manifest) if source_established else None
    manifest_text = (package_manifest or b"").decode(errors="replace")
    findings: list[Finding] = []

    for name in sorted(set(tarball) | set(registry)):
        script = tarball.get(name, registry.get(name, ""))
        line = _line_of(manifest_text, name)
        if name in tarball and name in registry and tarball[name] != registry[name]:
            findings.append(
                _finding(
                    "LIFE-004",
                    line,
                    Severity.MEDIUM,
                    FindingConfidence.HIGH,
                    f"{name}: tarball {tarball[name]!r}, registry {registry[name]!r}",
                )
            )
        elif (name in tarball) != (name in registry):
            where = "tarball" if name in tarball else "registry"
            findings.append(
                _finding(
                    "LIFE-004",
                    line,
                    Severity.MEDIUM,
                    FindingConfidence.HIGH,
                    f"{name} is only in the {where}: {script!r}",
                )
            )

        if _RISKY_SCRIPT.search(script):
            findings.append(
                _finding(
                    "LIFE-005", line, Severity.HIGH, FindingConfidence.HIGH, f"{name}: {script}"
                )
            )

        if not source_established or source is None:
            findings.append(
                _finding(
                    "LIFE-007",
                    line,
                    Severity.MEDIUM,
                    FindingConfidence.MEDIUM,
                    f"{name}: {script}",
                )
            )
        elif name not in source:
            findings.append(
                _finding(
                    "LIFE-001", line, Severity.HIGH, FindingConfidence.HIGH, f"{name}: {script}"
                )
            )
        elif source[name] != script:
            findings.append(
                _finding(
                    "LIFE-002",
                    line,
                    Severity.HIGH,
                    FindingConfidence.HIGH,
                    f"{name}: source {source[name]!r}, package {script!r}",
                )
            )
        else:
            findings.append(
                _finding(
                    "LIFE-003", line, Severity.LOW, FindingConfidence.HIGH, f"{name}: {script}"
                )
            )

    if binding_gyp_added:
        findings.append(
            Finding(
                rule_id="LIFE-006",
                title=RULES["LIFE-006"].title,
                category=RULES["LIFE-006"].category,
                path="binding.gyp",
                line=1,
                severity=Severity.MEDIUM,
                confidence=FindingConfidence.HIGH,
                evidence="binding.gyp is in the package but not the source",
                recommendation=RULES["LIFE-006"].recommendation,
                runs_at_install=True,
            )
        )
    return findings


def _line_of(text: str, script_name: str) -> int:
    for number, line in enumerate(text.split("\n"), start=1):
        if f'"{script_name}"' in line:
            return number
    return 1


def _finding(
    rule_id: str, line: int, severity: Severity, confidence: FindingConfidence, evidence: str
) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        title=rule.title,
        category=rule.category,
        path="package.json",
        line=line,
        severity=severity,
        confidence=confidence,
        evidence=" ".join(evidence.split())[:MAX_EVIDENCE_CHARS],
        recommendation=rule.recommendation,
        runs_at_install=True,
    )
