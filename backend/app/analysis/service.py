import asyncio
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from app.adapters.base import PackageAdapter, PackageMetadata
from app.ai.investigator import AIInvestigator
from app.ai.models import AIInvestigationResult
from app.analysis.analyzer import analyze_package
from app.analysis.models import AnalysisLimits, SecurityAnalysis
from app.archives.extract import ExtractionLimits, extract_archive
from app.comparison.compare import compare_inventories
from app.comparison.models import ComparisonLimits, ComparisonReport
from app.provenance.models import ProvenanceResult
from app.provenance.npm import NpmProvenanceChecker
from app.scoring.risk import RiskAssessment, score_release
from app.source.github import GitHubSourceResolver
from app.source.models import MatchStatus, SourceMatch


class ReleaseAnalysis(BaseModel):
    """All evidence about one release. ``comparison`` is None if no source was established."""

    model_config = ConfigDict(frozen=True)

    metadata: PackageMetadata
    source_match: SourceMatch
    comparison: ComparisonReport | None
    security: SecurityAnalysis
    provenance: ProvenanceResult
    risk: RiskAssessment
    ai: AIInvestigationResult | None = None


async def analyze_release(
    adapter: PackageAdapter,
    resolver: GitHubSourceResolver,
    provenance_checker: NpmProvenanceChecker,
    name: str,
    version: str,
    work_dir: Path,
    extraction_limits: ExtractionLimits | None = None,
    comparison_limits: ComparisonLimits | None = None,
    analysis_limits: AnalysisLimits | None = None,
    ai_investigator: AIInvestigator | None = None,
) -> ReleaseAnalysis:
    """Retrieve and assess one release, without ever executing its code.

    With no established source commit, the package itself is still scanned, and the
    missing comparison is reflected in the score. Retrieval and extraction failures are
    raised, because without the package there is nothing to assess.
    """
    metadata = await adapter.fetch_metadata(name, version)
    match = await resolver.resolve(metadata)

    downloads = work_dir / "downloads"
    tarball = await adapter.download_artifact(metadata.artifacts[0], downloads)
    package_inventory = await asyncio.to_thread(
        extract_archive, tarball.path, work_dir / "package", extraction_limits
    )

    report: ComparisonReport | None = None
    source_inventory = None
    if match.status is MatchStatus.MATCHED:
        source_archive = await resolver.download_source(match, downloads)
        source_inventory = await asyncio.to_thread(
            extract_archive, source_archive.path, work_dir / "source", extraction_limits
        )
        report = await asyncio.to_thread(
            compare_inventories,
            metadata,
            match,
            package_inventory,
            source_inventory,
            comparison_limits,
        )

    security = await asyncio.to_thread(
        analyze_package, metadata, package_inventory, report, source_inventory, analysis_limits
    )
    provenance = await provenance_checker.check(metadata, tarball.path, match)
    risk = score_release(match, report, package_inventory, security, provenance)

    ai_result = None
    if ai_investigator is not None:
        ai_result = await ai_investigator.investigate(
            metadata, match, report, security, risk, work_dir / "package"
        )

    return ReleaseAnalysis(
        metadata=metadata,
        source_match=match,
        comparison=report,
        security=security,
        provenance=provenance,
        risk=risk,
        ai=ai_result,
    )
