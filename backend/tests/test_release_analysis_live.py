"""Run with: pytest -q -m live -o addopts="". These contact npm, GitHub and Sigstore."""

import base64
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.adapters.http import RegistryLimits, create_registry_client
from app.adapters.npm import NpmAdapter
from app.analysis.service import ReleaseAnalysis, analyze_release
from app.provenance.models import ProvenanceStatus
from app.provenance.npm import (
    NpmProvenanceChecker,
    SignatureInvalidError,
    SigstoreBundleVerifier,
    VerificationUnavailableError,
)
from app.scoring.risk import RiskLevel
from app.source.github import GitHubSourceResolver

pytestmark = [pytest.mark.live, pytest.mark.anyio]


async def analyze(name: str, version: str, tmp_path: Path) -> ReleaseAnalysis:
    limits = RegistryLimits()
    async with create_registry_client(limits) as client:
        return await analyze_release(
            NpmAdapter(client, limits),
            GitHubSourceResolver(client, limits),
            NpmProvenanceChecker(client, limits),
            name,
            version,
            tmp_path,
        )


async def fetch_provenance_bundle(name: str, version: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(
            f"https://registry.npmjs.org/-/npm/v1/attestations/{name}@{version}"
        )
    response.raise_for_status()
    bundles: list[dict[str, Any]] = [
        item["bundle"]
        for item in response.json()["attestations"]
        if item["predicateType"].startswith("https://slsa.dev/provenance/")
    ]
    return bundles[0]


async def test_real_provenance_is_verified(tmp_path: Path) -> None:
    result = await analyze("next", "16.4.3", tmp_path)
    assert result.provenance.status is ProvenanceStatus.VERIFIED
    assert result.provenance.source_repository == "https://github.com/vercel/next.js"
    assert result.provenance.repository_matches_declared is True
    assert result.risk.level <= RiskLevel.MEDIUM


async def test_package_without_provenance_is_unavailable_and_low(tmp_path: Path) -> None:
    result = await analyze("left-pad", "1.3.0", tmp_path)
    assert result.provenance.status is ProvenanceStatus.UNAVAILABLE
    assert result.risk.score == 0
    assert result.risk.level is RiskLevel.LOW


async def test_older_attestation_format_is_not_reported_as_invalid(tmp_path: Path) -> None:
    result = await analyze("axios", "1.7.9", tmp_path)
    assert result.provenance.status is ProvenanceStatus.NOT_VERIFIED
    assert result.risk.level is RiskLevel.LOW


async def test_tampered_payload_fails_real_verification() -> None:
    bundle = await fetch_provenance_bundle("next", "16.4.3")
    envelope = bundle["dsseEnvelope"]
    statement = json.loads(base64.b64decode(envelope["payload"]))
    statement["subject"][0]["digest"]["sha512"] = "0" * 128
    envelope["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    with pytest.raises(SignatureInvalidError):
        SigstoreBundleVerifier().verify(json.dumps(bundle))


async def test_tampered_signature_fails_real_verification() -> None:
    bundle = await fetch_provenance_bundle("next", "16.4.3")
    signature = bytearray(base64.b64decode(bundle["dsseEnvelope"]["signatures"][0]["sig"]))
    signature[-1] ^= 0xFF
    bundle["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(signature).decode()
    with pytest.raises(SignatureInvalidError):
        SigstoreBundleVerifier().verify(json.dumps(bundle))


async def test_older_real_bundle_is_a_verifier_gap() -> None:
    bundle = await fetch_provenance_bundle("zod", "3.24.1")
    with pytest.raises(VerificationUnavailableError):
        SigstoreBundleVerifier().verify(json.dumps(bundle))
