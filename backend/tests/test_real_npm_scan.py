"""Live integration test for Veritor scanning a real package from npm."""

from pathlib import Path

import pytest

from app.adapters.http import RegistryLimits
from app.adapters.npm import NpmAdapter
from app.ai.client import OllamaClient
from app.ai.investigator import AIInvestigator
from app.config import get_settings
from app.provenance.npm import NpmProvenanceChecker
from app.scans.manager import ScanManager, set_scan_manager
from app.schemas.scans import Ecosystem, ScanRequest, ScanState
from app.source.github import GitHubSourceResolver

pytestmark = [pytest.mark.live, pytest.mark.anyio]


async def test_live_npm_scan_with_ollama(tmp_path: Path) -> None:
    settings = get_settings()
    limits = RegistryLimits()

    manager = ScanManager(
        settings=settings,
        base_work_dir=tmp_path / "live_scans",
        adapter_factory=lambda client: NpmAdapter(client, limits=limits),
        resolver_factory=lambda client: GitHubSourceResolver(
            client, limits=limits, token=settings.github_token
        ),
        checker_factory=lambda client: NpmProvenanceChecker(client, limits=limits),
        ai_investigator_factory=lambda: AIInvestigator(
            OllamaClient(
                base_url=settings.ollama_base_url,
                model=settings.explain_model,
                timeout_seconds=45.0,
            )
        ),
    )
    set_scan_manager(manager)

    try:
        # Scan left-pad 1.3.0 from the real npm registry
        request = ScanRequest(
            ecosystem=Ecosystem.NPM,
            package_name="left-pad",
            version="1.3.0",
        )
        record = await manager.create_scan(request)
        scan_id = record.scan_id

        # Wait for the scan to finish
        import asyncio

        for _ in range(120):
            status = manager.get_status(scan_id)
            if status.status in (ScanState.COMPLETED, ScanState.FAILED):
                break
            await asyncio.sleep(0.5)

        final_status = manager.get_status(scan_id)
        assert final_status.status is ScanState.COMPLETED, f"Scan failed: {final_status.error}"
        assert final_status.progress_percent == 100

        # Verify report
        report = manager.get_report(scan_id)
        assert report.package_name == "left-pad"
        assert report.version == "1.3.0"
        assert report.metadata is not None
        assert report.metadata.name == "left-pad"
        assert report.source_match is not None
        assert report.risk is not None
        assert report.ai is not None

        # Verify files and diffs
        files = manager.get_files(scan_id)
        assert len(files.files) > 0

        diffs = manager.get_diffs(scan_id)
        assert isinstance(diffs.diffs, list)

        # Verify single file diff endpoint
        if len(files.files) > 0:
            sample_path = files.files[0].path
            sample_diff = manager.get_file_diff(scan_id, sample_path)
            assert sample_diff.path == sample_path

        # Verify findings
        findings = manager.get_findings(scan_id)
        assert findings.package_name == "left-pad"
        assert findings.risk_score is not None

    finally:
        set_scan_manager(None)
