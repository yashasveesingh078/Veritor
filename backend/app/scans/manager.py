"""Scan state management and async orchestration."""

import asyncio
import logging
from datetime import UTC, datetime
from pathlib import Path
from tempfile import gettempdir
from typing import Any
from uuid import UUID, uuid4

import httpx

from app.adapters.npm import NpmAdapter
from app.ai.client import OllamaClient
from app.ai.investigator import AIInvestigator
from app.config import Settings, get_settings
from app.provenance.npm import NpmProvenanceChecker
from app.scans.models import ScanRecord
from app.scans.pipeline import execute_scan_pipeline
from app.schemas.scans import (
    Ecosystem,
    FileDiffItem,
    ScanDiffsResponse,
    ScanFilesResponse,
    ScanFindingsResponse,
    ScanReportResponse,
    ScanRequest,
    ScanStage,
    ScanState,
    ScanStatusResponse,
)
from app.source.github import GitHubSourceResolver

logger = logging.getLogger(__name__)


class ScanNotFoundError(Exception):
    """Scan ID does not exist."""


class ScanNotReadyError(Exception):
    """Scan is still in progress."""


class ScanManager:
    """Manages scan lifecycle, asynchronous execution, and persistent state."""

    def __init__(
        self,
        settings: Settings | None = None,
        base_work_dir: Path | None = None,
        adapter_factory: Any = None,
        resolver_factory: Any = None,
        checker_factory: Any = None,
        ai_investigator_factory: Any = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.base_work_dir = base_work_dir or Path(gettempdir()) / "veritor_scans"
        self._scans: dict[UUID, ScanRecord] = {}
        self._lock = asyncio.Lock()
        self._adapter_factory = adapter_factory
        self._resolver_factory = resolver_factory
        self._checker_factory = checker_factory
        self._ai_investigator_factory = ai_investigator_factory
        self._active_tasks: dict[UUID, asyncio.Task[None]] = {}

    async def create_scan(self, request: ScanRequest) -> ScanRecord:
        """Create a new scan record and trigger background processing."""
        scan_id = uuid4()
        now = datetime.now(UTC)
        record = ScanRecord(
            scan_id=scan_id,
            ecosystem=request.ecosystem,
            package_name=request.package_name,
            version=request.version,
            status=ScanState.ACCEPTED,
            stage=ScanStage.QUEUED,
            progress_percent=0,
            message="Scan accepted and queued for processing",
            created_at=now,
        )

        async with self._lock:
            self._scans[scan_id] = record

        # Launch background task
        task = asyncio.create_task(self._run_scan(scan_id))
        self._active_tasks[scan_id] = task

        logger.info(
            "Scan created scan_id=%s ecosystem=%s package=%s version=%s",
            scan_id,
            request.ecosystem.value,
            request.package_name,
            request.version,
        )
        return record

    async def _run_scan(self, scan_id: UUID) -> None:
        record = self._scans[scan_id]
        record.status = ScanState.RUNNING
        record.started_at = datetime.now(UTC)

        work_dir = self.base_work_dir / str(scan_id)
        record.work_dir = work_dir

        async def on_progress(stage: ScanStage, percent: int, msg: str) -> None:
            record.stage = stage
            record.progress_percent = percent
            record.message = msg
            logger.debug("Scan %s progress: [%s] %d%% - %s", scan_id, stage.value, percent, msg)

        try:
            if record.ecosystem is not Ecosystem.NPM:
                raise NotImplementedError(
                    f"Ecosystem {record.ecosystem.value} adapter is not implemented yet"
                )

            read_timeout = self.settings.registry_read_timeout_seconds
            async with httpx.AsyncClient(timeout=read_timeout) as client:
                adapter = (
                    self._adapter_factory(client)
                    if self._adapter_factory
                    else NpmAdapter(client, limits=self.settings.registry_limits())
                )
                resolver = (
                    self._resolver_factory(client)
                    if self._resolver_factory
                    else GitHubSourceResolver(
                        client,
                        limits=self.settings.registry_limits(),
                        token=self.settings.github_token,
                    )
                )
                checker = (
                    self._checker_factory(client)
                    if self._checker_factory
                    else NpmProvenanceChecker(client)
                )
                ai_investigator = (
                    self._ai_investigator_factory()
                    if self._ai_investigator_factory
                    else AIInvestigator(
                        OllamaClient(
                            base_url=self.settings.ollama_base_url,
                            model=self.settings.explain_model,
                        )
                    )
                )

                report = await execute_scan_pipeline(
                    scan_id=scan_id,
                    ecosystem=record.ecosystem,
                    package_name=record.package_name,
                    version=record.version,
                    work_dir=work_dir,
                    adapter=adapter,
                    resolver=resolver,
                    provenance_checker=checker,
                    ai_investigator=ai_investigator,
                    on_progress=on_progress,
                    extraction_limits=self.settings.extraction_limits(),
                    comparison_limits=self.settings.comparison_limits(),
                    analysis_limits=self.settings.analysis_limits(),
                )

            record.report = report
            record.status = ScanState.COMPLETED
            record.stage = ScanStage.COMPLETED
            record.progress_percent = 100
            record.completed_at = datetime.now(UTC)
            record.message = "Scan completed successfully"
            logger.info("Scan %s completed successfully", scan_id)

        except Exception as exc:
            logger.exception("Scan %s failed: %s", scan_id, exc)
            record.status = ScanState.FAILED
            record.stage = ScanStage.FAILED
            record.completed_at = datetime.now(UTC)
            record.error = str(exc)
            record.message = f"Scan failed: {exc}"

    def get_scan(self, scan_id: UUID) -> ScanRecord | None:
        return self._scans.get(scan_id)

    def get_status(self, scan_id: UUID) -> ScanStatusResponse:
        record = self.get_scan(scan_id)
        if record is None:
            raise ScanNotFoundError(f"Scan {scan_id} not found")
        return ScanStatusResponse(
            scan_id=record.scan_id,
            ecosystem=record.ecosystem,
            package_name=record.package_name,
            version=record.version,
            status=record.status,
            stage=record.stage,
            progress_percent=record.progress_percent,
            message=record.message,
            created_at=record.created_at,
            started_at=record.started_at,
            completed_at=record.completed_at,
            error=record.error,
        )

    def get_report(self, scan_id: UUID) -> ScanReportResponse:
        record = self.get_scan(scan_id)
        if record is None:
            raise ScanNotFoundError(f"Scan {scan_id} not found")
        if record.status in (ScanState.ACCEPTED, ScanState.RUNNING):
            raise ScanNotReadyError(f"Scan {scan_id} is still {record.status.value}")
        if record.report is not None:
            return record.report
        # If failed without report
        return ScanReportResponse(
            scan_id=record.scan_id,
            ecosystem=record.ecosystem,
            package_name=record.package_name,
            version=record.version,
            status=record.status,
            created_at=record.created_at,
            started_at=record.started_at,
            completed_at=record.completed_at,
            error=record.error,
        )

    def get_findings(self, scan_id: UUID) -> ScanFindingsResponse:
        record = self.get_scan(scan_id)
        if record is None:
            raise ScanNotFoundError(f"Scan {scan_id} not found")
        if record.status in (ScanState.ACCEPTED, ScanState.RUNNING):
            raise ScanNotReadyError(f"Scan {scan_id} is still {record.status.value}")

        report = record.report
        if report is None:
            return ScanFindingsResponse(
                scan_id=record.scan_id,
                package_name=record.package_name,
                version=record.version,
            )

        findings = list(report.security.findings) if report.security else []
        gaps = list(report.security.gaps) if report.security else []
        ai_explanations = list(report.ai.explanations) if report.ai else []
        factors = list(report.risk.factors) if report.risk else []
        floors = list(report.risk.floors) if report.risk else []
        score = report.risk.score if report.risk else None
        level = report.risk.level.name if report.risk else None

        return ScanFindingsResponse(
            scan_id=record.scan_id,
            package_name=record.package_name,
            version=record.version,
            risk_score=score,
            risk_level=level,
            findings=findings,
            ai_explanations=ai_explanations,
            gaps=gaps,
            factors=factors,
            floors=floors,
        )

    def get_files(self, scan_id: UUID) -> ScanFilesResponse:
        record = self.get_scan(scan_id)
        if record is None:
            raise ScanNotFoundError(f"Scan {scan_id} not found")
        if record.status in (ScanState.ACCEPTED, ScanState.RUNNING):
            raise ScanNotReadyError(f"Scan {scan_id} is still {record.status.value}")

        report = record.report
        summary = report.comparison.summary if report and report.comparison else None
        files = list(report.comparison.files) if report and report.comparison else []

        return ScanFilesResponse(
            scan_id=record.scan_id,
            package_name=record.package_name,
            version=record.version,
            summary=summary,
            files=files,
        )

    def get_diffs(self, scan_id: UUID, path: str | None = None) -> ScanDiffsResponse:
        record = self.get_scan(scan_id)
        if record is None:
            raise ScanNotFoundError(f"Scan {scan_id} not found")
        if record.status in (ScanState.ACCEPTED, ScanState.RUNNING):
            raise ScanNotReadyError(f"Scan {scan_id} is still {record.status.value}")

        report = record.report
        diff_items: list[FileDiffItem] = []

        if report and report.comparison:
            for file_comp in report.comparison.files:
                # If specific path requested, filter by path or package_path or source_path
                if path is not None and path not in (
                    file_comp.path,
                    file_comp.package_path,
                    file_comp.source_path,
                ):
                    continue

                if file_comp.diff.unified is not None or path is not None:
                    diff_items.append(
                        FileDiffItem(
                            path=file_comp.path,
                            status=file_comp.status.value,
                            diff_status=file_comp.diff.status.value,
                            unified=file_comp.diff.unified,
                            added_lines=file_comp.diff.added_lines,
                            removed_lines=file_comp.diff.removed_lines,
                        )
                    )

        return ScanDiffsResponse(
            scan_id=record.scan_id,
            package_name=record.package_name,
            version=record.version,
            total_diffs=len(diff_items),
            diffs=diff_items,
        )

    def get_file_diff(self, scan_id: UUID, file_id: str) -> FileDiffItem:
        record = self.get_scan(scan_id)
        if record is None:
            raise ScanNotFoundError(f"Scan {scan_id} not found")
        if record.status in (ScanState.ACCEPTED, ScanState.RUNNING):
            raise ScanNotReadyError(f"Scan {scan_id} is still {record.status.value}")

        report = record.report
        if not report or not report.comparison or not report.comparison.files:
            raise ScanNotFoundError(f"No comparison files found for scan {scan_id}")

        matched_item = None
        # Try matching by index if file_id is numeric
        if file_id.isdigit():
            idx = int(file_id)
            if 0 <= idx < len(report.comparison.files):
                matched_item = report.comparison.files[idx]

        # Otherwise match by path or normalized path
        if matched_item is None:
            for file_comp in report.comparison.files:
                if file_id in (file_comp.path, file_comp.package_path, file_comp.source_path):
                    matched_item = file_comp
                    break

        if matched_item is None:
            raise ScanNotFoundError(f"File {file_id!r} not found in scan comparison")

        return FileDiffItem(
            path=matched_item.path,
            status=matched_item.status.value,
            diff_status=matched_item.diff.status.value,
            unified=matched_item.diff.unified,
            added_lines=matched_item.diff.added_lines,
            removed_lines=matched_item.diff.removed_lines,
        )


_scan_manager: ScanManager | None = None


def get_scan_manager() -> ScanManager:
    global _scan_manager
    if _scan_manager is None:
        _scan_manager = ScanManager()
    return _scan_manager


def set_scan_manager(manager: ScanManager | None) -> None:
    global _scan_manager
    _scan_manager = manager
