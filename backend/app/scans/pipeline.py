"""End-to-end backend scan pipeline for package integrity analysis."""

import asyncio
import logging
import shutil
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from app.adapters.base import PackageAdapter
from app.ai.investigator import AIInvestigator
from app.analysis.analyzer import analyze_package
from app.analysis.models import AnalysisLimits
from app.archives.extract import ExtractionLimits, extract_archive
from app.comparison.compare import compare_inventories
from app.comparison.models import ComparisonLimits, ComparisonReport
from app.provenance.npm import NpmProvenanceChecker
from app.schemas.scans import (
    Ecosystem,
    ScanReportResponse,
    ScanStage,
    ScanState,
)
from app.scoring.risk import score_release
from app.source.github import GitHubSourceResolver
from app.source.models import MatchStatus

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[ScanStage, int, str], Awaitable[None]]


async def execute_scan_pipeline(
    scan_id: UUID,
    ecosystem: Ecosystem,
    package_name: str,
    version: str,
    work_dir: Path,
    adapter: PackageAdapter,
    resolver: GitHubSourceResolver,
    provenance_checker: NpmProvenanceChecker,
    ai_investigator: AIInvestigator,
    on_progress: ProgressCallback | None = None,
    extraction_limits: ExtractionLimits | None = None,
    comparison_limits: ComparisonLimits | None = None,
    analysis_limits: AnalysisLimits | None = None,
    clean_artifacts_on_exit: bool = True,
) -> ScanReportResponse:
    """Execute the full analysis pipeline:
    npm metadata → tarball → GitHub matching → safe extraction → inventory →
    comparison → artifact classification → security scanning → provenance →
    risk → AI → report.
    """
    started_at = datetime.now(UTC)

    async def update_progress(stage: ScanStage, percent: int, msg: str) -> None:
        if on_progress:
            await on_progress(stage, percent, msg)

    work_dir.mkdir(parents=True, exist_ok=True)
    downloads_dir = work_dir / "downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    package_dir = work_dir / "package"
    source_dir = work_dir / "source"

    try:
        # 1. Fetch metadata
        await update_progress(
            ScanStage.FETCHING_METADATA,
            10,
            f"Fetching registry metadata for {package_name}@{version}",
        )
        metadata = await adapter.fetch_metadata(package_name, version)

        # 2. GitHub matching
        await update_progress(
            ScanStage.RESOLVING_SOURCE,
            20,
            "Resolving repository and matching release commit",
        )
        match = await resolver.resolve(metadata)

        # 3. Download tarball
        await update_progress(
            ScanStage.DOWNLOADING_ARTIFACT,
            30,
            "Downloading package tarball verified against hashes",
        )
        if not metadata.artifacts:
            raise ValueError(f"No artifacts found in metadata for {package_name}@{version}")
        tarball = await adapter.download_artifact(metadata.artifacts[0], downloads_dir)

        # 4. Safe extraction of package
        await update_progress(
            ScanStage.EXTRACTING_PACKAGE,
            40,
            "Safely extracting package tarball and generating file inventory",
        )
        package_inventory = await asyncio.to_thread(
            extract_archive, tarball.path, package_dir, extraction_limits
        )

        # 5. Download and extract source if matched
        source_inventory = None
        report: ComparisonReport | None = None
        if match.status is MatchStatus.MATCHED:
            commit_prefix = match.commit_sha[:8] if match.commit_sha else "matched"
            await update_progress(
                ScanStage.DOWNLOADING_SOURCE,
                50,
                f"Downloading source archive for commit {commit_prefix}",
            )
            source_archive = await resolver.download_source(match, downloads_dir)

            await update_progress(
                ScanStage.EXTRACTING_SOURCE,
                60,
                "Safely extracting source archive and building inventory",
            )
            source_inventory = await asyncio.to_thread(
                extract_archive, source_archive.path, source_dir, extraction_limits
            )

            # 6. Comparison & artifact classification
            await update_progress(
                ScanStage.COMPARING,
                70,
                "Comparing package with source and classifying generated artifacts",
            )
            report = await asyncio.to_thread(
                compare_inventories,
                metadata,
                match,
                package_inventory,
                source_inventory,
                comparison_limits,
            )
        else:
            await update_progress(
                ScanStage.COMPARING,
                70,
                f"Skipping source comparison ({match.status.value}: {match.explanation})",
            )

        # 7. Security scanning (AST analysis)
        await update_progress(
            ScanStage.SECURITY_SCANNING,
            80,
            "Running AST security scanner on JS/TS code differences",
        )
        security = await asyncio.to_thread(
            analyze_package,
            metadata,
            package_inventory,
            report,
            source_inventory,
            analysis_limits,
        )

        # 8. Provenance verification
        await update_progress(
            ScanStage.CHECKING_PROVENANCE,
            85,
            "Verifying SLSA provenance attestation with Sigstore",
        )
        provenance = await provenance_checker.check(metadata, tarball.path, match)

        # 9. Deterministic risk scoring
        await update_progress(
            ScanStage.SCORING_RISK,
            90,
            "Computing deterministic explainable risk score and floors",
        )
        risk = score_release(match, report, package_inventory, security, provenance)

        # 10. AI investigation
        await update_progress(
            ScanStage.AI_INVESTIGATION,
            95,
            "Running AI investigator (qwen2.5-coder:7b) on findings",
        )
        ai_result = await ai_investigator.investigate(
            metadata, match, report, security, risk, package_dir
        )

        # 11. Final report assembly
        completed_at = datetime.now(UTC)
        duration = (completed_at - started_at).total_seconds()

        report_response = ScanReportResponse(
            scan_id=scan_id,
            ecosystem=ecosystem,
            package_name=package_name,
            version=version,
            status=ScanState.COMPLETED,
            metadata=metadata,
            source_match=match,
            comparison=report,
            security=security,
            provenance=provenance,
            risk=risk,
            ai=ai_result,
            created_at=started_at,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
        )

        await update_progress(ScanStage.COMPLETED, 100, "Scan completed successfully")
        return report_response

    finally:
        if clean_artifacts_on_exit:
            try:
                shutil.rmtree(work_dir, ignore_errors=True)
            except Exception as exc:
                logger.warning("Failed to clean temporary scan directory %s: %s", work_dir, exc)
