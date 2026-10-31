"""Combine the evidence into a deterministic, explainable risk score.

Every point comes from a listed factor, so the score can be recomputed by hand. It ranks
what to review first. It does not decide whether a package is malicious. Hard evidence
sets a minimum level that mitigating factors cannot lower.
"""

from collections import Counter, defaultdict
from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.models import (
    Finding,
    FindingConfidence,
    SecurityAnalysis,
    Severity,
)
from app.archives.models import ContentType, EntryKind, FileInventory
from app.archives.models import FindingKind as InventoryFindingKind
from app.comparison.models import (
    ComparisonReport,
    FileComparison,
    FileStatus,
    GeneratedClassification,
    ScopeMethod,
)
from app.provenance.models import ProvenanceResult, ProvenanceStatus
from app.source.models import Confidence, MatchStatus, SourceMatch, UncertainReason

MAX_SCORE = 100
_LEVEL_THRESHOLDS = ((70, "CRITICAL"), (45, "HIGH"), (20, "MEDIUM"), (0, "LOW"))
_SEVERITY_POINTS = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 6,
    Severity.HIGH: 18,
    Severity.CRITICAL: 40,
}
_CONFIDENCE_PERCENT = {
    FindingConfidence.LOW: 40,
    FindingConfidence.MEDIUM: 70,
    FindingConfidence.HIGH: 100,
}
_MAX_POINTS_PER_RULE = 40
_MAX_FINDING_POINTS = 75
_MAX_COMBINATION_POINTS = 15
_MAX_API_USE_POINTS = 12
_CONCRETE_RULES = frozenset(
    {"EXEC-003", "EXEC-005", "PROC-004", "PROC-005", "NET-002", "FS-002", "OBF-001", "CORR-005"}
)
_NATIVE_BINARIES = {ContentType.ELF, ContentType.MACH_O, ContentType.PE}
_CODE_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".sh", ".py")
_PROVENANCE_CREDIT = -10
_MAX_FACTOR_EVIDENCE = 5


class RiskLevel(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


class FactorCategory(StrEnum):
    SOURCE_MATCH = "source_match"
    COMPARISON = "comparison"
    ARTIFACT = "artifact"
    FINDINGS = "findings"
    PROVENANCE = "provenance"


class Completeness(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"


class RiskFactor(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    category: FactorCategory
    points: int = Field(description="Points this added to the score. Negative points reduce it.")
    explanation: str
    evidence: tuple[str, ...] = ()


class LevelFloor(BaseModel):
    model_config = ConfigDict(frozen=True)

    level: RiskLevel
    reason: str


class RiskAssessment(BaseModel):
    model_config = ConfigDict(frozen=True)

    score: int = Field(ge=0, le=MAX_SCORE)
    level: RiskLevel
    completeness: Completeness
    factors: tuple[RiskFactor, ...]
    floors: tuple[LevelFloor, ...] = Field(
        description="Hard evidence that sets a minimum level, whatever the score."
    )
    limitations: tuple[str, ...] = Field(description="What this assessment could not establish.")
    statement: str = (
        "A heuristic for prioritizing review, based on static evidence. It is not a verdict: "
        "a high score does not prove malice, and a low score does not prove safety."
    )


def score_release(
    match: SourceMatch,
    report: ComparisonReport | None,
    package_inventory: FileInventory,
    analysis: SecurityAnalysis,
    provenance: ProvenanceResult,
) -> RiskAssessment:
    """Score one release. The same evidence always produces the same result."""
    factors: list[RiskFactor] = []
    floors: list[LevelFloor] = []
    limitations: list[str] = []

    factors += _source_factors(match, limitations)
    if report is not None:
        factors += _comparison_factors(report, limitations)
    factors += _artifact_factors(package_inventory, floors)
    factors += _finding_factors(analysis.findings, floors)
    factors += _provenance_factors(provenance, floors, limitations)

    if analysis.gaps:
        limitations.append(
            f"{len(analysis.gaps)} static analysis gap(s): some code was not fully analyzed."
        )

    factors = sorted(factors, key=lambda factor: (-abs(factor.points), factor.id))
    score = max(0, min(MAX_SCORE, sum(factor.points for factor in factors)))
    level = max(
        [_level_for(score), *(floor.level for floor in floors)], key=lambda item: item.value
    )
    return RiskAssessment(
        score=score,
        level=level,
        completeness=Completeness.PARTIAL if limitations else Completeness.COMPLETE,
        factors=tuple(factors),
        floors=tuple(floors),
        limitations=tuple(limitations),
    )


def _level_for(score: int) -> RiskLevel:
    for threshold, name in _LEVEL_THRESHOLDS:
        if score >= threshold:
            return RiskLevel[name]
    return RiskLevel.LOW


def _factor(
    factor_id: str,
    category: FactorCategory,
    points: int,
    explanation: str,
    evidence: list[str] | None = None,
) -> RiskFactor:
    return RiskFactor(
        id=factor_id,
        category=category,
        points=points,
        explanation=explanation,
        evidence=tuple((evidence or [])[:_MAX_FACTOR_EVIDENCE]),
    )


def _source_factors(match: SourceMatch, limitations: list[str]) -> list[RiskFactor]:
    category = FactorCategory.SOURCE_MATCH
    if match.status is MatchStatus.MATCHED:
        if match.confidence is Confidence.HIGH:
            return []
        if match.confidence is Confidence.MEDIUM:
            return [
                _factor("SOURCE_MEDIUM", category, 3, f"Medium-confidence: {match.explanation}")
            ]
        return [_factor("SOURCE_LOW", category, 8, f"Low-confidence: {match.explanation}")]

    limitations.append("No source commit was established, so nothing was compared with source.")
    if match.reason is UncertainReason.LOOKUP_FAILED:
        return [
            _factor(
                "SOURCE_LOOKUP_FAILED",
                category,
                5,
                f"The source could not be checked, which may be temporary: {match.explanation}",
            )
        ]
    if match.reason is UncertainReason.RECORDED_COMMIT_CONFLICTS_WITH_TAG:
        return [
            _factor(
                "SOURCE_CONFLICT",
                category,
                8,
                f"Often harmless, but the code can't be traced to source: {match.explanation}",
            )
        ]
    return [
        _factor(
            "SOURCE_UNCERTAIN",
            category,
            12,
            f"The package can't be traced to a source commit: {match.explanation}",
        )
    ]


def _scaled(count: int, each: int, cap: int) -> int:
    return min(count * each, cap)


def _uncertain(item: FileComparison) -> bool:
    return (
        item.generated is not None
        and item.generated.classification is GeneratedClassification.UNCERTAIN
    )


def _comparison_factors(report: ComparisonReport, limitations: list[str]) -> list[RiskFactor]:
    category = FactorCategory.COMPARISON
    factors: list[RiskFactor] = []
    added_code = [
        item.path
        for item in report.files
        if item.status is FileStatus.ADDED
        and _uncertain(item)
        and item.path.lower().endswith(_CODE_SUFFIXES)
    ]
    if added_code:
        factors.append(
            _factor(
                "ADDED_CODE_UNEXPLAINED",
                category,
                _scaled(len(added_code), 2, 12),
                f"{len(added_code)} added code file(s) have no build evidence. Custom builds can "
                "cause this, so it's capped low.",
                added_code,
            )
        )
    modified = [
        item.path
        for item in report.files
        if item.status is FileStatus.MODIFIED
        and _uncertain(item)
        and item.path != "package.json"
        and item.path.lower().endswith(_CODE_SUFFIXES)
        and not item.diff.only_line_endings_differ
    ]
    if modified:
        factors.append(
            _factor(
                "SOURCE_FILE_MODIFIED",
                category,
                _scaled(len(modified), 5, 20),
                f"{len(modified)} code file(s) differ from the source, with no build evidence.",
                modified,
            )
        )
    executable_changes = [item.path for item in report.files if item.executable_bit_changed]
    if executable_changes:
        factors.append(
            _factor(
                "EXECUTABLE_BIT_CHANGED",
                category,
                _scaled(len(executable_changes), 3, 9),
                f"{len(executable_changes)} file(s) changed whether they are executable.",
                executable_changes,
            )
        )
    if report.scope.method is ScopeMethod.UNRESOLVED:
        limitations.append("The package's location in its repository could not be determined.")
        factors.append(
            _factor(
                "SCOPE_UNRESOLVED",
                category,
                5,
                "The part of the repository that holds this package could not be determined.",
            )
        )
    if report.scope.manifest_version_matches is False:
        factors.append(
            _factor(
                "SOURCE_VERSION_MISMATCH",
                category,
                3,
                "The repository's package.json has a different version at the matched commit.",
            )
        )
    if report.scope.manifest_name_matches is False:
        factors.append(
            _factor(
                "SOURCE_NAME_MISMATCH",
                category,
                8,
                "The repository's package.json names a different package at the matched commit.",
            )
        )
    binaries = [
        item
        for item in report.files
        if item.status in (FileStatus.ADDED, FileStatus.BINARY_DIFFERENT, FileStatus.MODIFIED)
        and item.package is not None
        and item.package.kind is EntryKind.REGULAR
        and item.package.content_type
        not in (ContentType.TEXT, ContentType.SCRIPT, ContentType.EMPTY, None)
    ]
    native = [
        item.path
        for item in binaries
        if item.package is not None and item.package.content_type in _NATIVE_BINARIES
    ]
    other = [item.path for item in binaries if item.path not in native]
    if native:
        factors.append(
            _factor(
                "NATIVE_BINARY_UNEXPLAINED",
                category,
                _scaled(len(native), 12, 30),
                f"{len(native)} native executable(s) are not in the source and can't be reviewed.",
                native,
            )
        )
    if other:
        factors.append(
            _factor(
                "BINARY_DIFFERENT",
                category,
                _scaled(len(other), 2, 10),
                f"{len(other)} other binary file(s) are added or differ from the source.",
                other,
            )
        )
    return factors


def _artifact_factors(inventory: FileInventory, floors: list[LevelFloor]) -> list[RiskFactor]:
    category = FactorCategory.ARTIFACT
    grouped: dict[InventoryFindingKind, list[str]] = defaultdict(list)
    for finding in inventory.findings:
        grouped[finding.kind].append(finding.path)
    factors: list[RiskFactor] = []
    if paths := grouped.get(InventoryFindingKind.LINK_ESCAPES_ROOT):
        factors.append(
            _factor(
                "LINK_ESCAPES_PACKAGE",
                category,
                _scaled(len(paths), 15, 30),
                f"{len(paths)} link(s) in the tarball point outside the package.",
                paths,
            )
        )
    if paths := grouped.get(InventoryFindingKind.SPECIAL_FILE):
        factors.append(
            _factor(
                "SPECIAL_FILE",
                category,
                _scaled(len(paths), 20, 40),
                f"{len(paths)} device or FIFO entries are in the tarball.",
                paths,
            )
        )
        floors.append(
            LevelFloor(level=RiskLevel.MEDIUM, reason="The tarball contains special files.")
        )
    if paths := grouped.get(InventoryFindingKind.PRIVILEGED_MODE):
        factors.append(
            _factor(
                "PRIVILEGED_MODE",
                category,
                _scaled(len(paths), 10, 20),
                f"{len(paths)} file(s) in the tarball declare setuid or setgid.",
                paths,
            )
        )
    return factors


def _finding_points(finding: Finding) -> int:
    return _SEVERITY_POINTS[finding.severity] * _CONFIDENCE_PERCENT[finding.confidence] // 100


def _finding_tier(rule_id: str) -> tuple[int, bool]:
    """Return a rule's group cap and whether repeats add full points."""
    if rule_id in _CONCRETE_RULES or rule_id.startswith("LIFE-"):
        return _MAX_FINDING_POINTS, True
    if rule_id.startswith("CORR-"):
        return _MAX_COMBINATION_POINTS, False
    return _MAX_API_USE_POINTS, True


def _rule_points(findings: list[Finding], repeats_count: bool) -> int:
    points = [_finding_points(finding) for finding in findings]
    if repeats_count:
        return min(sum(points), _MAX_POINTS_PER_RULE)
    return min(max(points) + len(points) - 1, _MAX_POINTS_PER_RULE)


def _finding_factors(findings: tuple[Finding, ...], floors: list[LevelFloor]) -> list[RiskFactor]:
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_rule[finding.rule_id].append(finding)

    raw: list[tuple[str, int, list[Finding]]] = []
    for rule_id, rule_findings in sorted(by_rule.items()):
        _, repeats_count = _finding_tier(rule_id)
        raw.append((rule_id, _rule_points(rule_findings, repeats_count), rule_findings))

    # Spend each cap on the biggest contributors, so the result is order-independent. Ordinary
    # API use and co-occurrence can raise a review priority, but only concrete patterns can
    # take a release to the top, however many files a large package has.
    remaining = _MAX_FINDING_POINTS
    group_spent: Counter[int] = Counter()
    factors: list[RiskFactor] = []
    for rule_id, points, rule_findings in sorted(raw, key=lambda item: (-item[1], item[0])):
        group_cap, _ = _finding_tier(rule_id)
        granted = min(points, remaining, max(0, group_cap - group_spent[group_cap]))
        remaining -= granted
        group_spent[group_cap] += granted
        severities = Counter(finding.severity.name for finding in rule_findings)
        summary = ", ".join(f"{count} {name}" for name, count in sorted(severities.items()))
        factors.append(
            _factor(
                f"FINDING_{rule_id}",
                FactorCategory.FINDINGS,
                granted,
                f"{rule_findings[0].title} ({summary}).",
                [f"{item.path}:{item.line}" for item in rule_findings],
            )
        )

    decisive = [
        finding
        for finding in findings
        if finding.severity >= Severity.CRITICAL and finding.confidence >= FindingConfidence.HIGH
    ]
    if decisive:
        floors.append(
            LevelFloor(
                level=RiskLevel.HIGH,
                reason=f"{decisive[0].title} at {decisive[0].path}:{decisive[0].line}.",
            )
        )
    untraceable_install = [
        finding for finding in findings if finding.rule_id in ("LIFE-001", "LIFE-005")
    ]
    if untraceable_install:
        floors.append(
            LevelFloor(
                level=RiskLevel.MEDIUM,
                reason=f"{untraceable_install[0].title}: {untraceable_install[0].evidence}",
            )
        )
    return factors


def _provenance_factors(
    provenance: ProvenanceResult, floors: list[LevelFloor], limitations: list[str]
) -> list[RiskFactor]:
    category = FactorCategory.PROVENANCE
    status = provenance.status
    if status is ProvenanceStatus.INVALID:
        floors.append(
            LevelFloor(level=RiskLevel.HIGH, reason=f"Invalid provenance: {provenance.explanation}")
        )
        return [
            _factor(
                "PROVENANCE_INVALID",
                category,
                40,
                f"An attestation exists and failed a check: {provenance.explanation}",
            )
        ]
    if status is ProvenanceStatus.UNAVAILABLE:
        return [
            _factor(
                "PROVENANCE_UNAVAILABLE",
                category,
                0,
                "No provenance was published. Most packages have none, so this adds no risk.",
            )
        ]
    if status is ProvenanceStatus.NOT_VERIFIED:
        limitations.append("An attestation exists, but it could not be verified.")
        return [
            _factor(
                "PROVENANCE_NOT_VERIFIED",
                category,
                0,
                f"No credit is given for unverified provenance: {provenance.explanation}",
            )
        ]
    if status is ProvenanceStatus.UNCERTAIN:
        limitations.append("Provenance could not be determined.")
        return [
            _factor(
                "PROVENANCE_UNCERTAIN",
                category,
                3,
                f"Provenance could not be determined: {provenance.explanation}",
            )
        ]

    factors: list[RiskFactor] = []
    wrong_repository = provenance.repository_matches_declared is False
    wrong_commit = provenance.commit_matches_source_match is False
    if wrong_repository:
        factors.append(
            _factor(
                "PROVENANCE_OTHER_REPOSITORY",
                category,
                30,
                f"Verified, but built from {provenance.source_repository}, not the declared "
                "repository. Forks and renames can cause this.",
            )
        )
        floors.append(
            LevelFloor(
                level=RiskLevel.MEDIUM,
                reason="Signed provenance names a different repository from the one declared.",
            )
        )
    if wrong_commit:
        factors.append(
            _factor(
                "PROVENANCE_OTHER_COMMIT",
                category,
                12,
                f"Verified, but built from {provenance.source_commit}, not the matched commit, so "
                "the comparison may have used the wrong source.",
            )
        )
    if not wrong_repository and not wrong_commit:
        factors.append(
            _factor(
                "PROVENANCE_VERIFIED",
                category,
                _PROVENANCE_CREDIT,
                f"Signed provenance ties this tarball to {provenance.source_repository}. This "
                "shows where it was built, not that the code is safe.",
            )
        )
    return factors
