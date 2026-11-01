"""Tests for TASK 10: Provenance verification and deterministic risk assessment.

Covers:
- Part A: Provenance statuses, GitHub Actions build identity, commit inspection,
  integrity metadata evaluation, and cryptographic validation guardrails.
- Part B: Deterministic 0-100 risk scoring with factors (differences, findings,
  artifact uncertainty, source confidence, provenance, lifecycle scripts),
  confidence derivation, contributing evidence, recommendations, and limitations.
"""

import hashlib
from pathlib import Path

import pytest

from app.analysis.models import (
    AnalysisGap,
    AnalysisScope,
    Finding,
    FindingConfidence,
    SecurityAnalysis,
    Severity,
)
from app.provenance.models import ProvenanceResult, ProvenanceStatus
from app.provenance.npm import (
    SignerIdentity,
    VerifiedBundle,
    _evaluate_package_integrity,
    _evaluate_signed_content,
)
from app.scoring.risk import (
    Completeness,
    RiskAssessment,
    RiskConfidence,
    RiskLevel,
    score_release,
)
from app.source.models import MatchStatus, SourceMatch, UncertainReason
from tests.test_comparison import COMMIT, inventory, make_metadata, manifest, matched

# ---------------------------------------------------------------------------
# PART A: Provenance Tests
# ---------------------------------------------------------------------------


def test_provenance_statuses_enum() -> None:
    """All 5 required statuses must be supported."""
    assert ProvenanceStatus.VERIFIED == "VERIFIED"
    assert ProvenanceStatus.NOT_VERIFIED == "NOT_VERIFIED"
    assert ProvenanceStatus.UNAVAILABLE == "UNAVAILABLE"
    assert ProvenanceStatus.INVALID == "INVALID"
    assert ProvenanceStatus.UNCERTAIN == "UNCERTAIN"


def test_provenance_cannot_claim_verified_from_metadata_alone() -> None:
    """Do not claim verification based on metadata alone."""
    with pytest.raises(ValueError, match="VERIFIED needs a checked signature"):
        ProvenanceResult(
            status=ProvenanceStatus.VERIFIED,
            explanation="Metadata claims provenance exists",
            claimed_in_metadata=True,
            signature_verified=False,  # Not cryptographically checked
            tarball_digest_matches=False,
            source_repository=None,
        )


def test_provenance_github_actions_identity_inspection(tmp_path: Path) -> None:
    """Inspects GitHub Actions build identity (issuer, repository, commit, ref, workflow)."""
    tarball_bytes = b"tarball payload for provenance inspection"
    tarball_path = tmp_path / "pkg.tgz"
    tarball_path.write_bytes(tarball_bytes)
    tarball_sha512 = hashlib.sha512(tarball_bytes).hexdigest()

    meta = make_metadata("provenance-demo")
    match = matched()

    identity = SignerIdentity(
        issuer="https://token.actions.githubusercontent.com",
        source_repository="https://github.com/acme/demo",
        source_commit=COMMIT,
        source_ref="refs/tags/v1.0.0",
        build_workflow="https://github.com/acme/demo/.github/workflows/release.yml@refs/tags/v1.0.0",
    )
    statement = {
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [
            {"name": "pkg:npm/provenance-demo@1.0.0", "digest": {"sha512": tarball_sha512}}
        ],
        "predicate": {
            "buildDefinition": {
                "resolvedDependencies": [{"uri": "git+https://x", "digest": {"gitCommit": COMMIT}}]
            }
        },
    }
    import json

    bundle = VerifiedBundle(
        payload_type="application/vnd.in-toto+json",
        payload=json.dumps(statement).encode("utf-8"),
        identity=identity,
    )

    res = _evaluate_signed_content(bundle, meta, tarball_path, match, claimed=True)
    assert res.status is ProvenanceStatus.VERIFIED
    assert res.signature_verified is True
    assert res.tarball_digest_matches is True
    assert res.oidc_issuer == "https://token.actions.githubusercontent.com"
    assert res.source_repository == "https://github.com/acme/demo"
    assert res.source_commit == COMMIT.lower()
    assert res.build_workflow == (
        "https://github.com/acme/demo/.github/workflows/release.yml@refs/tags/v1.0.0"
    )
    assert res.repository_matches_declared is True
    assert res.commit_matches_source_match is True


def test_package_integrity_metadata_evaluation(tmp_path: Path) -> None:
    """Evaluate available package integrity metadata (sha512 base64 and hex)."""
    import base64

    data = b"package archive content"
    tarball = tmp_path / "test.tgz"
    tarball.write_bytes(data)

    digest = hashlib.sha512(data).digest()
    correct_integrity = "sha512-" + base64.b64encode(digest).decode()

    meta = make_metadata("demo")
    meta.manifest["dist"] = {"integrity": correct_integrity}

    declared, matches = _evaluate_package_integrity(meta, tarball)
    assert declared == correct_integrity
    assert matches is True

    # Bad integrity
    meta.manifest["dist"] = {"integrity": "sha512-invalidbase64hash="}
    declared_bad, matches_bad = _evaluate_package_integrity(meta, tarball)
    assert declared_bad == "sha512-invalidbase64hash="
    assert matches_bad is False


# ---------------------------------------------------------------------------
# PART B: Deterministic Risk Engine Tests
# ---------------------------------------------------------------------------


def _dummy_analysis(*findings: Finding, gaps: tuple[AnalysisGap, ...] = ()) -> SecurityAnalysis:
    return SecurityAnalysis(
        scope=AnalysisScope.DIFFERENCES_FROM_SOURCE,
        files_scanned=1,
        findings=findings,
        gaps=gaps,
    )


def _make_finding(
    rule_id: str,
    severity: Severity = Severity.HIGH,
    confidence: FindingConfidence = FindingConfidence.HIGH,
    path: str = "src/index.js",
    line: int = 1,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        path=path,
        line=line,
        severity=severity,
        confidence=confidence,
        evidence="test evidence",
        explanation=f"Finding for {rule_id}",
        recommended_action="Remediate the issue",
    )


def test_risk_assessment_return_contract_completeness(tmp_path: Path) -> None:
    """Return risk level, score, contributing evidence, confidence, recommendations, limitations."""
    pkg_inv = inventory(tmp_path, "pkg", {"package.json": manifest(name="demo", version="1.0.0")})
    match = matched()
    analysis = _dummy_analysis(_make_finding("EXEC-001", Severity.HIGH))
    prov = ProvenanceResult(status=ProvenanceStatus.UNAVAILABLE, explanation="none")

    assessment: RiskAssessment = score_release(match, None, pkg_inv, analysis, prov)

    # 1. Score in 0-100 range
    assert isinstance(assessment.score, int)
    assert 0 <= assessment.score <= 100

    # 2. Risk level enum
    assert isinstance(assessment.level, RiskLevel)

    # 3. Contributing evidence
    assert isinstance(assessment.contributing_evidence, tuple)
    assert len(assessment.contributing_evidence) > 0

    # 4. Confidence
    assert isinstance(assessment.confidence, RiskConfidence)

    # 5. Recommendations
    assert isinstance(assessment.recommendations, tuple)
    assert len(assessment.recommendations) > 0

    # 6. Limitations
    assert isinstance(assessment.limitations, tuple)


def test_missing_provenance_alone_must_not_imply_maliciousness(tmp_path: Path) -> None:
    """Missing provenance alone must add 0 points and not imply maliciousness."""
    pkg_inv = inventory(
        tmp_path, "pkg_clean", {"package.json": manifest(name="demo", version="1.0.0")}
    )
    match = matched()
    analysis = _dummy_analysis()

    # Unavailable provenance
    prov = ProvenanceResult(
        status=ProvenanceStatus.UNAVAILABLE,
        explanation="This version has no published provenance. Most packages do not.",
    )
    assessment = score_release(match, None, pkg_inv, analysis, prov)

    # Score stays low, zero points added by provenance
    prov_factor = next((f for f in assessment.factors if f.id == "PROVENANCE_UNAVAILABLE"), None)
    assert prov_factor is not None
    assert prov_factor.points == 0
    assert assessment.score <= 15
    assert assessment.level is RiskLevel.LOW


def test_no_findings_must_not_imply_safety(tmp_path: Path) -> None:
    """No findings must not imply safety when other risks (e.g. untraced source) exist."""
    # Source commit could not be matched
    unmatched = SourceMatch(
        status=MatchStatus.UNCERTAIN,
        commit_sha=None,
        repository=None,
        reason=UncertainReason.LOOKUP_FAILED,
        explanation="Repository could not be resolved",
    )
    pkg_inv = inventory(
        tmp_path, "pkg_binary", {"package.json": manifest(name="demo", version="1.0.0")}
    )
    # Security analysis finds 0 findings!
    clean_analysis = _dummy_analysis()
    prov = ProvenanceResult(status=ProvenanceStatus.UNAVAILABLE, explanation="none")

    assessment = score_release(unmatched, None, pkg_inv, clean_analysis, prov)

    # Score is not 0 despite having 0 findings because source is uncertain!
    assert assessment.score > 0
    assert assessment.completeness is Completeness.PARTIAL
    assert len(assessment.limitations) > 0
    # Assessment statement clearly informs that a low score or 0 findings is not proof of safety
    assert "not a verdict" in assessment.statement


def test_unexpected_lifecycle_script_elevates_risk(tmp_path: Path) -> None:
    """Unexpected lifecycle scripts (LIFE-001 or LIFE-005) set a medium floor and add points."""
    pkg_inv = inventory(
        tmp_path, "pkg_life", {"package.json": manifest(name="demo", version="1.0.0")}
    )
    analysis = _dummy_analysis(_make_finding("LIFE-005", Severity.HIGH))
    assessment = score_release(
        matched(),
        None,
        pkg_inv,
        analysis,
        ProvenanceResult(status=ProvenanceStatus.UNAVAILABLE, explanation="none"),
    )

    assert assessment.level >= RiskLevel.MEDIUM
    assert any("lifecycle" in rec.lower() for rec in assessment.recommendations)


def test_provenance_credit_reduces_score(tmp_path: Path) -> None:
    """Verified provenance gives a deterministic credit (-10 points)."""
    pkg_inv = inventory(
        tmp_path, "pkg_prov", {"package.json": manifest(name="demo", version="1.0.0")}
    )
    analysis = _dummy_analysis(_make_finding("EXEC-001", Severity.HIGH))
    verified_prov = ProvenanceResult(
        status=ProvenanceStatus.VERIFIED,
        explanation="Verified under Sigstore",
        signature_verified=True,
        tarball_digest_matches=True,
        source_repository="https://github.com/acme/demo",
        source_commit=COMMIT,
        repository_matches_declared=True,
        commit_matches_source_match=True,
    )
    unavail_prov = ProvenanceResult(status=ProvenanceStatus.UNAVAILABLE, explanation="none")

    score_with_unavail = score_release(matched(), None, pkg_inv, analysis, unavail_prov).score
    score_with_verified = score_release(matched(), None, pkg_inv, analysis, verified_prov).score

    assert score_with_verified == score_with_unavail - 10
