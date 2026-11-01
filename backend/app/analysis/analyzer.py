"""Run the static rules over what a package adds or changes, and correlate the results.

A single API use is not evidence of malware, since most real packages read the environment
or use the network. Severity rises only for a concrete pattern, such as eval(atob(...)), or
for a combination of behaviours introduced in one file. This function blocks. Async
callers should run it with ``asyncio.to_thread``.
"""

import time
from collections import Counter
from dataclasses import dataclass

from app.adapters.base import PackageMetadata
from app.analysis.js_scanner import Hit, Signal, scan_source, scannable_language
from app.analysis.lifecycle import check_lifecycle
from app.analysis.models import (
    AnalysisGap,
    AnalysisLimits,
    AnalysisScope,
    Finding,
    FindingConfidence,
    GapReason,
    SecurityAnalysis,
    Severity,
)
from app.analysis.rules import RULES
from app.archives.models import ContentType, EntryKind, FileInventory, InventoryEntry
from app.comparison.generated import install_script_text, named_in_text
from app.comparison.models import (
    ComparisonReport,
    FileComparison,
    FileStatus,
    GeneratedClassification,
)
from app.comparison.trees import FileTree

_MANIFEST_LIMIT = 1024 * 1024
_OTHER_CODE_SUFFIXES = (".sh", ".bash", ".py", ".ps1", ".bat", ".cmd", ".rb", ".pl")
_SENSITIVE_AT_INSTALL = {Signal.EXECUTION, Signal.PROCESS, Signal.CREDENTIAL, Signal.NETWORK}
_ACTIVE_SIGNALS = {Signal.EXECUTION, Signal.PROCESS, Signal.CREDENTIAL, Signal.NETWORK}


@dataclass(frozen=True)
class _Target:
    path: str
    entry: InventoryEntry
    compare_with_source: bool
    comparison_item: FileComparison | None = None


def analyze_package(
    metadata: PackageMetadata,
    package_inventory: FileInventory,
    report: ComparisonReport | None,
    source_inventory: FileInventory | None,
    limits: AnalysisLimits | None = None,
) -> SecurityAnalysis:
    """Scan differences from the source, or the whole package when no source is established."""
    limits = limits or AnalysisLimits()
    package = FileTree(package_inventory)
    source = (
        FileTree(source_inventory, report.scope.directory)
        if report is not None and source_inventory is not None
        else None
    )
    package_manifest = package.read("package.json", _MANIFEST_LIMIT)
    install_text = install_script_text(metadata.scripts, package_manifest)

    findings: list[Finding] = []
    gaps: list[AnalysisGap] = []
    scanned = 0
    deadline = time.monotonic() + limits.deadline_seconds
    for target in _targets(package, report):
        language = scannable_language(target.path) or _script_language(target.entry)
        if language is None:
            if target.path.lower().endswith(_OTHER_CODE_SUFFIXES):
                gaps.append(
                    AnalysisGap(
                        path=target.path,
                        reason=GapReason.UNSUPPORTED_LANGUAGE,
                        detail="This code is not JavaScript or TypeScript, so it was not scanned.",
                    )
                )
            continue
        if time.monotonic() > deadline:
            gaps.append(
                AnalysisGap(
                    path=target.path,
                    reason=GapReason.DEADLINE,
                    detail="The time limit ended before this file was scanned.",
                )
            )
            continue
        scanned += 1
        findings += _scan_target(target, language, package, source, install_text, limits, gaps)

    findings += check_lifecycle(
        metadata,
        package_manifest,
        source.read("package.json", _MANIFEST_LIMIT) if source is not None else None,
        source_established=source is not None,
        binding_gyp_added=_binding_gyp_added(report),
    )
    findings.sort(key=lambda item: (-item.severity, -item.confidence, item.path, item.line))
    return SecurityAnalysis(
        scope=(
            AnalysisScope.DIFFERENCES_FROM_SOURCE
            if report is not None
            else AnalysisScope.WHOLE_PACKAGE
        ),
        files_scanned=scanned,
        findings=tuple(findings),
        gaps=tuple(sorted(gaps, key=lambda gap: (gap.path, gap.reason))),
    )


def _targets(package: FileTree, report: ComparisonReport | None) -> list[_Target]:
    if report is None:
        return [
            _Target(path, entry, False, None)
            for path, entry in sorted(package.entries.items())
            if entry.kind is EntryKind.REGULAR
        ]
    comparison_by_path = {item.path: item for item in report.files}
    targets: list[_Target] = []
    for item in report.files:
        # A renamed file has the same bytes as the source, so it contains nothing new.
        if item.status not in (FileStatus.ADDED, FileStatus.MODIFIED):
            continue
        entry = package.entries.get(item.path)
        if entry is not None and entry.kind is EntryKind.REGULAR:
            targets.append(
                _Target(
                    item.path,
                    entry,
                    item.status is FileStatus.MODIFIED,
                    comparison_by_path.get(item.path),
                )
            )
    return targets


def _script_language(entry: InventoryEntry) -> str | None:
    # Extensionless files with a shebang are often Node scripts. Others parse with errors,
    # which is reported as a gap.
    return (
        "javascript" if entry.content_type is ContentType.SCRIPT and not entry.extension else None
    )


def _binding_gyp_added(report: ComparisonReport | None) -> bool:
    if report is None:
        return False
    return any(
        item.path == "binding.gyp" and item.status is FileStatus.ADDED for item in report.files
    )


def _scan_target(
    target: _Target,
    language: str,
    package: FileTree,
    source: FileTree | None,
    install_text: str,
    limits: AnalysisLimits,
    gaps: list[AnalysisGap],
) -> list[Finding]:
    data = package.read(target.path, limits.max_file_bytes)
    if data is None:
        gaps.append(
            AnalysisGap(
                path=target.path,
                reason=GapReason.TOO_LARGE,
                detail=f"This file is over the {limits.max_file_bytes} byte limit for scanning.",
            )
        )
        return []

    result = scan_source(data, language)
    if result.has_parse_errors:
        gaps.append(
            AnalysisGap(
                path=target.path,
                reason=GapReason.PARSE_ERRORS,
                detail="Part of this file could not be parsed, so some code may have been missed.",
            )
        )

    hits = list(result.hits)
    pre_existing: list[Hit] = []
    if target.compare_with_source and source is not None:
        source_data = source.read(target.path, limits.max_file_bytes)
        if source_data is not None:
            hits, pre_existing = _split_introduced(hits, scan_source(source_data, language).hits)

    runs_at_install = named_in_text(target.path, install_text)
    is_large = len(data) >= limits.large_file_bytes
    is_suspicious_artifact = (
        target.comparison_item is not None
        and target.comparison_item.generated is not None
        and target.comparison_item.generated.classification is GeneratedClassification.SUSPICIOUS
    )
    effective_is_large = is_large and not is_suspicious_artifact
    correlated = _correlate(target.path, hits, pre_existing, effective_is_large, runs_at_install)
    findings = [
        _to_finding(target.path, hit, runs_at_install, is_suspicious_artifact) for hit in hits
    ]
    return _cap_findings(findings, limits, target.path, gaps) + correlated


def _hit_key(hit: Hit) -> tuple[str, str]:
    return hit.rule_id, hit.evidence


def _split_introduced(hits: list[Hit], source_hits: tuple[Hit, ...]) -> tuple[list[Hit], list[Hit]]:
    """Separate behaviour new to this version from code that was already in the source.

    Matching on rule and code rather than line number means that inserting a line above
    existing code does not make that code look new.
    """
    remaining = Counter(_hit_key(hit) for hit in source_hits)
    introduced: list[Hit] = []
    pre_existing: list[Hit] = []
    for hit in hits:
        key = _hit_key(hit)
        if remaining[key] > 0:
            remaining[key] -= 1
            pre_existing.append(hit)
        else:
            introduced.append(hit)
    return introduced, pre_existing


def _correlate(
    path: str,
    introduced: list[Hit],
    pre_existing: list[Hit],
    is_large: bool,
    runs_at_install: bool,
) -> list[Finding]:
    """Report combinations in one file, as long as this version introduced part of them.

    A new network call beside an old credential read matters, but a combination that is
    already in the source says nothing about this release. Co-occurrence is not proof of
    data flow, and a large bundle mixes unrelated modules, which lowers the confidence.
    """
    new_signals = {hit.signal for hit in introduced if hit.signal is not None}
    all_signals = new_signals | {hit.signal for hit in pre_existing if hit.signal is not None}

    def first_line(*signals: Signal) -> int:
        lines = [hit.line for hit in introduced if hit.signal in signals]
        return min(lines) if lines else 1

    def describe(*signals: Signal) -> str:
        return "Signals in this file: " + ", ".join(sorted(signal.value for signal in signals))

    new_rules = {hit.rule_id for hit in introduced}
    all_rules = new_rules | {hit.rule_id for hit in pre_existing}
    severity = Severity.MEDIUM if is_large else Severity.HIGH
    confidence = FindingConfidence.LOW if is_large else FindingConfidence.MEDIUM
    combinations = [
        ("CORR-001", (Signal.CREDENTIAL, Signal.NETWORK)),
        ("CORR-003", (Signal.NETWORK, Signal.PROCESS)),
        ("CORR-003", (Signal.NETWORK, Signal.EXECUTION)),
        ("CORR-002", (Signal.DECODE, Signal.EXECUTION)),
        ("CORR-002", (Signal.DECODE, Signal.PROCESS)),
    ]
    findings: list[Finding] = []
    seen_rules: set[str] = set()
    for rule_id, signals in combinations:
        if (
            rule_id in seen_rules
            or not set(signals) <= all_signals
            or not set(signals) & new_signals
        ):
            continue
        seen_rules.add(rule_id)
        # Credentials beside a known data-collection address is a concrete pattern,
        # so it does not depend on the file being small.
        concrete = rule_id == "CORR-001" and "NET-002" in all_rules
        findings.append(
            _rule_finding(
                rule_id,
                path,
                first_line(*signals),
                Severity.CRITICAL if concrete else severity,
                FindingConfidence.HIGH if concrete else confidence,
                describe(*signals),
                runs_at_install,
            )
        )

    active = all_signals & _ACTIVE_SIGNALS
    if (
        Signal.OBFUSCATION in all_signals
        and active
        and ({Signal.OBFUSCATION} | active) & new_signals
    ):
        findings.append(
            _rule_finding(
                "CORR-004",
                path,
                first_line(Signal.OBFUSCATION, *active),
                severity,
                confidence,
                describe(Signal.OBFUSCATION, *active),
                runs_at_install,
            )
        )

    sensitive = new_signals & _SENSITIVE_AT_INSTALL
    if runs_at_install and sensitive:
        findings.append(
            _rule_finding(
                "CORR-005",
                path,
                first_line(*sensitive),
                Severity.HIGH,
                FindingConfidence.HIGH,
                describe(*sensitive),
                True,
            )
        )
    return findings


def _to_finding(
    path: str, hit: Hit, runs_at_install: bool, is_suspicious_artifact: bool = False
) -> Finding:
    confidence = (
        FindingConfidence.HIGH
        if is_suspicious_artifact and hit.confidence < FindingConfidence.HIGH
        else hit.confidence
    )
    return _rule_finding(
        hit.rule_id, path, hit.line, hit.severity, confidence, hit.evidence, runs_at_install
    )


def _rule_finding(
    rule_id: str,
    path: str,
    line: int,
    severity: Severity,
    confidence: FindingConfidence,
    evidence: str,
    runs_at_install: bool,
    explanation: str | None = None,
    recommended_action: str | None = None,
) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        title=rule.title,
        category=rule.category,
        path=path,
        line=line,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        explanation=explanation or rule.explanation or rule.title,
        recommended_action=recommended_action or rule.recommended_action or rule.recommendation,
        recommendation=rule.recommendation,
        runs_at_install=runs_at_install,
    )


def _cap_findings(
    findings: list[Finding], limits: AnalysisLimits, path: str, gaps: list[AnalysisGap]
) -> list[Finding]:
    """Keep the most severe of each rule, so one bundle cannot bury everything else."""
    ordered = sorted(findings, key=lambda item: (-item.severity, -item.confidence, item.line))
    counts: Counter[str] = Counter()
    kept: list[Finding] = []
    dropped = 0
    for finding in ordered:
        counts[finding.rule_id] += 1
        if counts[finding.rule_id] <= limits.max_findings_per_rule_per_file:
            kept.append(finding)
        else:
            dropped += 1
    if dropped:
        gaps.append(
            AnalysisGap(
                path=path,
                reason=GapReason.FINDINGS_CAPPED,
                detail=f"{dropped} further findings from rules already listed were not recorded.",
            )
        )
    return kept
