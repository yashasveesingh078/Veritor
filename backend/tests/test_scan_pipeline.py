"""Integration tests for the backend scan pipeline wiring."""

from pathlib import Path
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest

from app.ai.client import OllamaClient
from app.ai.investigator import AIInvestigator
from app.ai.models import AIInvestigationStatus
from app.provenance.npm import NpmProvenanceChecker
from app.scans.pipeline import execute_scan_pipeline
from app.schemas.scans import Ecosystem, ScanStage, ScanState
from tests.test_comparison import make_metadata, manifest, matched
from tests.test_provenance import FakeVerifier
from tests.test_release_analysis import FakeAdapter, FakeResolver

pytestmark = pytest.mark.anyio


async def test_full_pipeline_clean_package(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    scan_id = uuid4()
    files = {
        "package.json": manifest(name="demo-pkg", version="1.0.0"),
        "index.js": "console.log(1);",
    }

    adapter = FakeAdapter(make_metadata(name="demo-pkg"), files)
    resolver = FakeResolver(matched(), files)

    transport = httpx.MockTransport(lambda _: httpx.Response(404))
    async with httpx.AsyncClient(transport=transport) as client:
        checker = NpmProvenanceChecker(client, verifier=FakeVerifier())
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_ollama.model = "qwen2.5-coder:7b"
        investigator = AIInvestigator(client=mock_ollama)

        progress_events: list[tuple[ScanStage, int, str]] = []

        async def track_progress(stage: ScanStage, percent: int, msg: str) -> None:
            progress_events.append((stage, percent, msg))

        report = await execute_scan_pipeline(
            scan_id=scan_id,
            ecosystem=Ecosystem.NPM,
            package_name="demo-pkg",
            version="1.0.0",
            work_dir=work_dir,
            adapter=adapter,
            resolver=resolver,  # type: ignore[arg-type]
            provenance_checker=checker,
            ai_investigator=investigator,
            on_progress=track_progress,
            clean_artifacts_on_exit=True,
        )

        assert report.scan_id == scan_id
        assert report.status is ScanState.COMPLETED
        assert report.package_name == "demo-pkg"
        assert report.version == "1.0.0"
        assert report.comparison is not None
        assert report.risk is not None
        assert report.ai is not None
        assert report.ai.status is AIInvestigationStatus.SKIPPED

        # Verify progress stages were reported in order
        stages = [event[0] for event in progress_events]
        assert ScanStage.FETCHING_METADATA in stages
        assert ScanStage.RESOLVING_SOURCE in stages
        assert ScanStage.DOWNLOADING_ARTIFACT in stages
        assert ScanStage.EXTRACTING_PACKAGE in stages
        assert ScanStage.DOWNLOADING_SOURCE in stages
        assert ScanStage.EXTRACTING_SOURCE in stages
        assert ScanStage.COMPARING in stages
        assert ScanStage.SECURITY_SCANNING in stages
        assert ScanStage.CHECKING_PROVENANCE in stages
        assert ScanStage.SCORING_RISK in stages
        assert ScanStage.AI_INVESTIGATION in stages
        assert ScanStage.COMPLETED in stages

        # Check work_dir cleanup
        assert not work_dir.exists()


async def test_full_pipeline_with_security_finding_and_ai_explanation(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    scan_id = uuid4()
    # Source version has clean index.js
    source_files = {
        "package.json": manifest(name="demo-pkg", version="1.0.0"),
        "index.js": "module.exports = function() {};",
    }
    # Published tarball has injected eval in index.js
    pkg_files = {
        "package.json": manifest(name="demo-pkg", version="1.0.0"),
        "index.js": "module.exports = function() { eval(process.env.SECRET); };",
    }

    adapter = FakeAdapter(make_metadata(name="demo-pkg"), pkg_files)
    resolver = FakeResolver(matched(), source_files)

    transport = httpx.MockTransport(lambda _: httpx.Response(404))
    async with httpx.AsyncClient(transport=transport) as client:
        checker = NpmProvenanceChecker(client, verifier=FakeVerifier())

        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_ollama.model = "qwen2.5-coder:7b"
        mock_ollama.chat_json.return_value = {
            "summary": "Dynamic execution of environment secret in index.js",
            "findings_explanations": [
                {
                    "finding_ref": "FINDING-1",
                    "path": "index.js",
                    "line": 1,
                    "explanation": "Calls eval on process.env.SECRET",
                    "evidence_reference": "eval(process.env.SECRET)",
                    "behavior_analysis": "Exfiltrates or executes secrets from environment",
                    "uncertainty": "Low",
                    "recommendation": "Remove eval",
                }
            ],
            "overall_uncertainty": "Low",
            "recommendations": ["Audit index.js diff"],
        }
        investigator = AIInvestigator(client=mock_ollama)

        report = await execute_scan_pipeline(
            scan_id=scan_id,
            ecosystem=Ecosystem.NPM,
            package_name="demo-pkg",
            version="1.0.0",
            work_dir=work_dir,
            adapter=adapter,
            resolver=resolver,  # type: ignore[arg-type]
            provenance_checker=checker,
            ai_investigator=investigator,
            clean_artifacts_on_exit=True,
        )

        assert report.status is ScanState.COMPLETED
        assert report.security is not None
        rule_ids = {f.rule_id for f in report.security.findings}
        assert "EXEC-001" in rule_ids
        assert report.ai is not None
        assert report.ai.status is AIInvestigationStatus.COMPLETED
        assert len(report.ai.explanations) == 1
        assert report.ai.explanations[0].path == "index.js"
        # Deterministic risk assessment was not overwritten
        assert report.risk is not None
        assert report.risk.score > 0


async def test_full_pipeline_cleanup_on_failure(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    scan_id = uuid4()

    class FailingAdapter(FakeAdapter):
        async def fetch_metadata(self, name: str, version: str):  # type: ignore[no-untyped-def]
            raise ValueError("Simulated network outage during metadata fetch")

    adapter = FailingAdapter(make_metadata(name="demo-pkg"), {})
    resolver = FakeResolver(matched(), {})

    transport = httpx.MockTransport(lambda _: httpx.Response(404))
    async with httpx.AsyncClient(transport=transport) as client:
        checker = NpmProvenanceChecker(client, verifier=FakeVerifier())
        mock_ollama = AsyncMock(spec=OllamaClient)
        mock_ollama.model = "qwen2.5-coder:7b"
        investigator = AIInvestigator(client=mock_ollama)

        with pytest.raises(ValueError, match="Simulated network outage"):
            await execute_scan_pipeline(
                scan_id=scan_id,
                ecosystem=Ecosystem.NPM,
                package_name="demo-pkg",
                version="1.0.0",
                work_dir=work_dir,
                adapter=adapter,
                resolver=resolver,  # type: ignore[arg-type]
                provenance_checker=checker,
                ai_investigator=investigator,
                clean_artifacts_on_exit=True,
            )

        # Temporary directory must be cleaned up on failure!
        assert not work_dir.exists()
