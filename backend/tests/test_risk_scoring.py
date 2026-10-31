from pathlib import Path
from typing import Any

import pytest

from app.analysis.models import (
    AnalysisGap,
    AnalysisScope,
    Finding,
    FindingCategory,
    FindingConfidence,
    GapReason,
    SecurityAnalysis,
    Severity,
)
from app.archives.models import FileInventory
from app.comparison.compare import compare_inventories
from app.comparison.models import ComparisonReport
from app.provenance.models import ProvenanceResult, ProvenanceStatus
from app.scoring.risk import Completeness, RiskAssessment, RiskLevel, score_release
from app.source.models import Confidence, MatchStatus, SourceMatch, UncertainReason
from tests.test_comparison import TSC_SOURCE, inventory, make_metadata, manifest, matched

BASE = {"package.json": manifest(name="demo", version="1.0.0")}
UNAVAILABLE = ProvenanceResult(status=ProvenanceStatus.UNAVAILABLE, explanation="none")
VERIFIED = ProvenanceResult(
    status=ProvenanceStatus.VERIFIED,
    explanation="ok",
    signature_verified=True,
    tarball_digest_matches=True,
    source_repository="https://github.com/acme/demo",
    source_commit="a" * 40,
    repository_matches_declared=True,
    commit_matches_source_match=True,
)


def finding(
    rule_id: str = "EXEC-001",
    severity: Severity = Severity.MEDIUM,
    confidence: FindingConfidence = FindingConfidence.HIGH,
    path: str = "a.js",
    line: int = 1,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"title {rule_id}",
        category=FindingCategory.NETWORK,
        path=path,
        line=line,
        severity=severity,
        confidence=confidence,
        evidence="x",
        recommendation="y",
    )


def analysis(*findings: Finding, gaps: tuple[AnalysisGap, ...] = ()) -> SecurityAnalysis:
    return SecurityAnalysis(
        scope=AnalysisScope.DIFFERENCES_FROM_SOURCE,
        files_scanned=1,
        findings=findings,
        gaps=gaps,
    )


def empty_inventory(tmp_path: Path) -> FileInventory:
    return inventory(tmp_path, "empty", BASE)


def score(
    tmp_path: Path,
    *findings: Finding,
    provenance: ProvenanceResult = UNAVAILABLE,
    match: SourceMatch | None = None,
    report: ComparisonReport | None = None,
    package: FileInventory | None = None,
    gaps: tuple[AnalysisGap, ...] = (),
) -> RiskAssessment:
    return score_release(
        match or matched(),
        report,
        package or empty_inventory(tmp_path),
        analysis(*findings, gaps=gaps),
        provenance,
    )


def report_for(tmp_path: Path, package: dict[str, Any], source: dict[str, Any]) -> ComparisonReport:
    return compare_inventories(
        make_metadata(),
        matched(),
        inventory(tmp_path, "package", package),
        inventory(tmp_path, "source", source),
        None,
    )


def points(assessment: RiskAssessment, factor_id: str) -> int:
    return next(f.points for f in assessment.factors if f.id == factor_id)


def has_factor(assessment: RiskAssessment, factor_id: str) -> bool:
    return any(f.id == factor_id for f in assessment.factors)


def test_clean_release_scores_zero(tmp_path: Path) -> None:
    result = score(tmp_path)
    assert result.score == 0
    assert result.level is RiskLevel.LOW
    assert result.completeness is Completeness.COMPLETE


def test_score_is_the_sum_of_its_factors(tmp_path: Path) -> None:
    result = score(
        tmp_path,
        finding("NET-002", Severity.HIGH),
        finding("ENV-002", Severity.MEDIUM, FindingConfidence.MEDIUM),
    )
    assert result.score == sum(f.points for f in result.factors) == 18 + 4


def test_scoring_is_deterministic_regardless_of_order(tmp_path: Path) -> None:
    items = [
        finding("EXEC-001", Severity.MEDIUM),
        finding("ENV-002", Severity.MEDIUM),
        finding("ENV-003", Severity.MEDIUM),
        finding("CORR-001", Severity.HIGH),
    ]
    package = empty_inventory(tmp_path)
    first = score(tmp_path, *items, package=package)
    second = score(tmp_path, *reversed(items), package=package)
    assert first == second


def test_output_says_it_is_not_a_verdict(tmp_path: Path) -> None:
    assert "not a verdict" in score(tmp_path).statement


def test_missing_provenance_alone_adds_no_risk(tmp_path: Path) -> None:
    result = score(tmp_path, provenance=UNAVAILABLE)
    assert result.score == 0
    assert result.level is RiskLevel.LOW
    assert result.completeness is Completeness.COMPLETE
    assert points(result, "PROVENANCE_UNAVAILABLE") == 0


def test_invalid_provenance_has_a_floor_of_high(tmp_path: Path) -> None:
    invalid = ProvenanceResult(status=ProvenanceStatus.INVALID, explanation="tampered")
    result = score(tmp_path, provenance=invalid)
    assert points(result, "PROVENANCE_INVALID") == 40
    assert result.level is RiskLevel.HIGH


def test_unverified_provenance_earns_no_credit(tmp_path: Path) -> None:
    unverified = ProvenanceResult(status=ProvenanceStatus.NOT_VERIFIED, explanation="offline")
    item = finding("NET-002", Severity.HIGH)
    result = score(tmp_path, item, provenance=unverified)
    assert result.score == 18
    assert result.completeness is Completeness.PARTIAL


def test_uncertain_provenance_adds_little_and_is_partial(tmp_path: Path) -> None:
    uncertain = ProvenanceResult(status=ProvenanceStatus.UNCERTAIN, explanation="down")
    result = score(tmp_path, provenance=uncertain)
    assert result.score == 3
    assert result.completeness is Completeness.PARTIAL


def test_verified_provenance_reduces_score(tmp_path: Path) -> None:
    item = finding("NET-002", Severity.HIGH)
    assert score(tmp_path, item, provenance=VERIFIED).score == 8


def test_score_never_goes_below_zero(tmp_path: Path) -> None:
    assert score(tmp_path, provenance=VERIFIED).score == 0


def test_verified_provenance_cannot_lower_a_floor(tmp_path: Path) -> None:
    item = finding("EXEC-003", Severity.CRITICAL)
    result = score(tmp_path, item, provenance=VERIFIED)
    assert result.score == 30
    assert result.level is RiskLevel.HIGH


def test_critical_low_confidence_finding_sets_no_floor(tmp_path: Path) -> None:
    result = score(tmp_path, finding("EXEC-003", Severity.CRITICAL, FindingConfidence.LOW))
    assert result.floors == ()
    assert result.score == 16


def test_verified_from_other_repository_earns_no_credit_and_has_floor(tmp_path: Path) -> None:
    wrong = VERIFIED.model_copy(update={"repository_matches_declared": False})
    result = score(tmp_path, provenance=wrong)
    assert points(result, "PROVENANCE_OTHER_REPOSITORY") == 30
    assert not has_factor(result, "PROVENANCE_VERIFIED")
    assert result.level is RiskLevel.MEDIUM


def test_verified_from_other_commit_earns_no_credit(tmp_path: Path) -> None:
    wrong = VERIFIED.model_copy(update={"commit_matches_source_match": False})
    result = score(tmp_path, provenance=wrong)
    assert points(result, "PROVENANCE_OTHER_COMMIT") == 12
    assert not has_factor(result, "PROVENANCE_VERIFIED")


def test_many_isolated_api_uses_stay_low(tmp_path: Path) -> None:
    items = [
        finding(rule, Severity.MEDIUM, path=f"{index}.js")
        for index in range(200)
        for rule in ("ENV-002", "ENV-003", "EXEC-001", "PROC-003")
    ]
    result = score(tmp_path, *items)
    assert result.score == 12
    assert result.level is RiskLevel.LOW


def test_co_occurrence_alone_cannot_reach_high(tmp_path: Path) -> None:
    items = [
        finding(rule, Severity.HIGH, FindingConfidence.MEDIUM, path=f"{index}.js")
        for index in range(100)
        for rule in ("CORR-001", "CORR-002", "CORR-003", "CORR-004")
    ]
    assert score(tmp_path, *items).score == 15


def test_concrete_patterns_can_reach_critical(tmp_path: Path) -> None:
    result = score(
        tmp_path,
        finding("EXEC-003", Severity.CRITICAL),
        finding("PROC-004", Severity.HIGH),
        finding("NET-002", Severity.HIGH),
        finding("FS-002", Severity.HIGH),
    )
    assert result.level is RiskLevel.CRITICAL


def test_rule_points_are_capped(tmp_path: Path) -> None:
    items = [finding("NET-002", Severity.HIGH, line=index) for index in range(20)]
    assert points(score(tmp_path, *items), "FINDING_NET-002") == 40


def test_total_finding_points_are_capped(tmp_path: Path) -> None:
    items = [
        finding(rule, Severity.CRITICAL)
        for rule in ("EXEC-003", "EXEC-005", "PROC-004", "PROC-005")
    ]
    assert score(tmp_path, *items).score == 75


def test_score_is_capped_at_one_hundred(tmp_path: Path) -> None:
    invalid = ProvenanceResult(status=ProvenanceStatus.INVALID, explanation="x")
    items = [
        finding(rule, Severity.CRITICAL)
        for rule in ("EXEC-003", "EXEC-005", "PROC-004", "PROC-005")
    ]
    assert score(tmp_path, *items, provenance=invalid).score == 100


def test_info_findings_add_nothing_but_are_listed(tmp_path: Path) -> None:
    result = score(tmp_path, finding("NET-001", Severity.INFO))
    assert result.score == 0
    assert has_factor(result, "FINDING_NET-001")


def test_factor_evidence_points_to_files(tmp_path: Path) -> None:
    result = score(tmp_path, finding("NET-002", Severity.HIGH, path="src/x.js", line=9))
    factor = next(f for f in result.factors if f.id == "FINDING_NET-002")
    assert factor.evidence == ("src/x.js:9",)


def test_new_install_script_has_a_floor_of_medium(tmp_path: Path) -> None:
    result = score(tmp_path, finding("LIFE-001", Severity.LOW))
    assert result.level is RiskLevel.MEDIUM
    assert result.floors


@pytest.mark.parametrize(
    ("reason", "factor_id", "expected"),
    [
        (UncertainReason.NO_MATCHING_TAG, "SOURCE_UNCERTAIN", 12),
        (UncertainReason.LOOKUP_FAILED, "SOURCE_LOOKUP_FAILED", 5),
        (UncertainReason.RECORDED_COMMIT_CONFLICTS_WITH_TAG, "SOURCE_CONFLICT", 8),
    ],
)
def test_uncertain_source(
    tmp_path: Path, reason: UncertainReason, factor_id: str, expected: int
) -> None:
    match = SourceMatch(status=MatchStatus.UNCERTAIN, reason=reason, explanation="x")
    result = score(tmp_path, match=match)
    assert points(result, factor_id) == expected
    assert result.completeness is Completeness.PARTIAL
    assert result.level is RiskLevel.LOW


@pytest.mark.parametrize(
    ("confidence", "factor_id", "expected"),
    [(Confidence.MEDIUM, "SOURCE_MEDIUM", 3), (Confidence.LOW, "SOURCE_LOW", 8)],
)
def test_weaker_source_match(
    tmp_path: Path, confidence: Confidence, factor_id: str, expected: int
) -> None:
    match = matched().model_copy(update={"confidence": confidence})
    assert points(score(tmp_path, match=match), factor_id) == expected


def test_unexplained_added_code_is_capped(tmp_path: Path) -> None:
    package = {**BASE, **{f"extra{i}.js": f"const a = {i}" for i in range(50)}}
    result = score(tmp_path, report=report_for(tmp_path, package, BASE))
    assert points(result, "ADDED_CODE_UNEXPLAINED") == 12
    assert result.level is RiskLevel.LOW


def test_generated_output_adds_no_risk(tmp_path: Path) -> None:
    package = {
        "package.json": manifest(name="demo", version="1.0.0", main="dist/index.js"),
        "dist/index.js": "export const a = 1;\n//# sourceMappingURL=index.js.map\n",
        "dist/index.js.map": '{"version":3,"sources":["../src/index.ts"],"mappings":""}',
    }
    result = score(tmp_path, report=report_for(tmp_path, package, TSC_SOURCE))
    assert not has_factor(result, "ADDED_CODE_UNEXPLAINED")


def test_modified_source_file(tmp_path: Path) -> None:
    report = report_for(tmp_path, {**BASE, "a.js": "new"}, {**BASE, "a.js": "old"})
    assert points(score(tmp_path, report=report), "SOURCE_FILE_MODIFIED") == 5


def test_native_binary_outweighs_other_binary(tmp_path: Path) -> None:
    elf = b"\x7fELF" + b"\0" * 64
    png = b"\x89PNG\r\n\x1a\n" + b"\0" * 64
    report = report_for(tmp_path, {**BASE, "a.node": elf, "b.png": png}, BASE)
    result = score(tmp_path, report=report)
    assert points(result, "NATIVE_BINARY_UNEXPLAINED") == 12
    assert points(result, "BINARY_DIFFERENT") == 2


def test_executable_bit_change(tmp_path: Path) -> None:
    package = inventory(tmp_path, "package", {**BASE, "a.sh": "x"}, modes={"a.sh": 0o755})
    source = inventory(tmp_path, "source", {**BASE, "a.sh": "x"})
    report = compare_inventories(make_metadata(), matched(), package, source, None)
    assert points(score(tmp_path, report=report), "EXECUTABLE_BIT_CHANGED") == 3


def test_link_escaping_package(tmp_path: Path) -> None:
    package = inventory(tmp_path, "linked", BASE, links={"evil": "../../../etc/passwd"})
    assert points(score(tmp_path, package=package), "LINK_ESCAPES_PACKAGE") == 15


def test_privileged_mode(tmp_path: Path) -> None:
    package = inventory(tmp_path, "setuid", {**BASE, "a": "x"}, modes={"a": 0o4755})
    assert points(score(tmp_path, package=package), "PRIVILEGED_MODE") == 10


def test_analysis_gaps_make_the_result_partial(tmp_path: Path) -> None:
    gap = AnalysisGap(path="a.js", reason=GapReason.TOO_LARGE, detail="x")
    result = score(tmp_path, gaps=(gap,))
    assert result.completeness is Completeness.PARTIAL
    assert result.limitations


@pytest.mark.parametrize(
    ("score_value", "level"),
    [
        (0, RiskLevel.LOW),
        (19, RiskLevel.LOW),
        (20, RiskLevel.MEDIUM),
        (44, RiskLevel.MEDIUM),
        (45, RiskLevel.HIGH),
        (69, RiskLevel.HIGH),
        (70, RiskLevel.CRITICAL),
    ],
)
def test_level_boundaries(score_value: int, level: RiskLevel) -> None:
    from app.scoring.risk import _level_for

    assert _level_for(score_value) is level
