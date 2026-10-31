"""Integration tests for the Scan REST API endpoints."""

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import httpx
import pytest

from app.ai.client import OllamaClient
from app.ai.investigator import AIInvestigator
from app.main import create_app
from app.provenance.npm import NpmProvenanceChecker
from app.scans.manager import ScanManager, set_scan_manager
from tests.test_comparison import make_metadata, manifest, matched
from tests.test_provenance import FakeVerifier
from tests.test_release_analysis import FakeAdapter, FakeResolver

pytestmark = pytest.mark.anyio


@pytest.fixture
def test_manager(tmp_path: Any) -> Iterator[ScanManager]:
    files = {
        "package.json": manifest(name="api-demo", version="1.0.0"),
        "index.js": "module.exports = function() { eval(process.env.FLAG); };",
    }
    source_files = {
        "package.json": manifest(name="api-demo", version="1.0.0"),
        "index.js": "module.exports = function() {};",
    }

    mock_ollama = AsyncMock(spec=OllamaClient)
    mock_ollama.model = "qwen2.5-coder:7b"
    mock_ollama.chat_json.return_value = {
        "summary": "Evaluates environment flag dynamically in index.js",
        "findings_explanations": [
            {
                "finding_ref": "FINDING-1",
                "path": "index.js",
                "line": 1,
                "explanation": "Dynamic eval of process.env.FLAG",
                "evidence_reference": "eval(process.env.FLAG)",
                "behavior_analysis": "Dynamic code execution at runtime",
                "uncertainty": "Low",
                "recommendation": "Remove eval",
            }
        ],
        "overall_uncertainty": "Low",
        "recommendations": ["Do not trust this version."],
    }

    manager = ScanManager(
        base_work_dir=tmp_path / "scans",
        adapter_factory=lambda _: FakeAdapter(make_metadata(name="api-demo"), files),
        resolver_factory=lambda _: FakeResolver(matched(), source_files),
        checker_factory=lambda client: NpmProvenanceChecker(client, verifier=FakeVerifier()),
        ai_investigator_factory=lambda: AIInvestigator(client=mock_ollama),
    )
    set_scan_manager(manager)
    yield manager
    set_scan_manager(None)


@pytest.fixture
def api_app(test_manager: ScanManager):  # type: ignore[no-untyped-def]
    return create_app()


async def test_scan_full_api_lifecycle(api_app: Any, test_manager: ScanManager) -> None:
    transport = httpx.ASGITransport(app=api_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. POST /api/v1/scans
        payload = {"ecosystem": "npm", "package_name": "api-demo", "version": "1.0.0"}
        post_resp = await client.post("/api/v1/scans", json=payload)
        assert post_resp.status_code == 202
        data = post_resp.json()
        assert data["status"] == "accepted"
        scan_id_str = data["scan_id"]
        scan_id = UUID(scan_id_str)

        # 2. Poll GET /api/v1/scans/{scan_id} until completed
        status_data = {}
        for _ in range(50):
            get_resp = await client.get(f"/api/v1/scans/{scan_id}")
            assert get_resp.status_code == 200
            status_data = get_resp.json()
            assert status_data["scan_id"] == scan_id_str
            assert status_data["package_name"] == "api-demo"
            assert 0 <= status_data["progress_percent"] <= 100
            if status_data["status"] in ("completed", "failed"):
                break
            await asyncio.sleep(0.05)

        assert status_data["status"] == "completed"
        assert status_data["stage"] == "completed"
        assert status_data["progress_percent"] == 100

        # 3. GET /api/v1/scans/{scan_id}/report
        report_resp = await client.get(f"/api/v1/scans/{scan_id}/report")
        assert report_resp.status_code == 200
        report = report_resp.json()
        assert report["scan_id"] == scan_id_str
        assert report["status"] == "completed"
        assert report["security"]["files_scanned"] > 0
        assert report["risk"]["score"] > 0
        assert report["ai"]["status"] == "completed"
        assert len(report["ai"]["explanations"]) == 1

        # 4. GET /api/v1/scans/{scan_id}/findings
        findings_resp = await client.get(f"/api/v1/scans/{scan_id}/findings")
        assert findings_resp.status_code == 200
        findings_data = findings_resp.json()
        assert findings_data["scan_id"] == scan_id_str
        assert findings_data["risk_score"] > 0
        assert len(findings_data["findings"]) >= 1
        assert len(findings_data["ai_explanations"]) == 1
        assert findings_data["ai_explanations"][0]["path"] == "index.js"

        # 5. GET /api/v1/scans/{scan_id}/files
        files_resp = await client.get(f"/api/v1/scans/{scan_id}/files")
        assert files_resp.status_code == 200
        files_data = files_resp.json()
        assert files_data["scan_id"] == scan_id_str
        assert len(files_data["files"]) > 0

        # 6. GET /api/v1/scans/{scan_id}/diffs
        diffs_resp = await client.get(f"/api/v1/scans/{scan_id}/diffs")
        assert diffs_resp.status_code == 200
        diffs_data = diffs_resp.json()
        assert diffs_data["scan_id"] == scan_id_str
        assert diffs_data["total_diffs"] >= 1
        assert any("eval" in (d.get("unified") or "") for d in diffs_data["diffs"])

        # 7. GET /api/v1/scans/{scan_id}/diffs?path=index.js
        filtered_diff_resp = await client.get(f"/api/v1/scans/{scan_id}/diffs?path=index.js")
        assert filtered_diff_resp.status_code == 200
        filtered_diff_data = filtered_diff_resp.json()
        assert filtered_diff_data["total_diffs"] == 1
        assert filtered_diff_data["diffs"][0]["path"] == "index.js"


async def test_scan_not_found_errors(api_app: Any, test_manager: ScanManager) -> None:
    transport = httpx.ASGITransport(app=api_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        missing_id = uuid4()
        for endpoint in ("report", "findings", "files", "diffs"):
            resp = await client.get(f"/api/v1/scans/{missing_id}/{endpoint}")
            assert resp.status_code == 404
            assert resp.json()["error"]["code"] == "not_found"

        resp = await client.get(f"/api/v1/scans/{missing_id}")
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "not_found"
