import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from app.adapters.base import PackageMetadata
from app.provenance.models import ProvenanceResult, ProvenanceStatus
from app.provenance.npm import (
    BundleUnreadableError,
    NpmProvenanceChecker,
    SignatureInvalidError,
    SignerIdentity,
    SigstoreBundleVerifier,
    VerificationUnavailableError,
    VerifiedBundle,
    _decode_der_utf8,
)
from app.source.models import MatchStatus, SourceMatch, UncertainReason
from tests.test_comparison import COMMIT, make_metadata, matched

pytestmark = pytest.mark.anyio

TARBALL = b"the exact tarball bytes"
SLSA = "https://slsa.dev/provenance/v1"
ISSUER = "https://token.actions.githubusercontent.com"


def statement(**changes: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "predicateType": SLSA,
        "subject": [
            {
                "name": "pkg:npm/demo@1.0.0",
                "digest": {"sha512": hashlib.sha512(TARBALL).hexdigest()},
            }
        ],
        "predicate": {
            "buildDefinition": {
                "resolvedDependencies": [{"uri": "git+https://x", "digest": {"gitCommit": COMMIT}}]
            }
        },
    }
    return {**base, **changes}


def identity(**changes: Any) -> SignerIdentity:
    values: dict[str, Any] = {
        "issuer": ISSUER,
        "source_repository": "https://github.com/acme/demo",
        "source_commit": COMMIT,
        "source_ref": "refs/tags/v1.0.0",
        "build_workflow": "https://github.com/acme/demo/.github/workflows/r.yml@refs/tags/v1.0.0",
    }
    return SignerIdentity(**{**values, **changes})


class FakeVerifier:
    def __init__(
        self,
        result: dict[str, Any] | bytes | None = None,
        signer: SignerIdentity | None = None,
        error: Exception | None = None,
        payload_type: str = "application/vnd.in-toto+json",
    ) -> None:
        self.result = statement() if result is None else result
        self.signer = signer or identity()
        self.error = error
        self.payload_type = payload_type
        self.calls = 0

    def verify(self, bundle_json: str) -> VerifiedBundle:
        self.calls += 1
        if self.error is not None:
            raise self.error
        payload = (
            self.result if isinstance(self.result, bytes) else json.dumps(self.result).encode()
        )
        return VerifiedBundle(self.payload_type, payload, self.signer)


def attestation_document() -> dict[str, Any]:
    return {
        "attestations": [
            {"predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"},
            {"predicateType": SLSA, "bundle": {"mediaType": "x"}},
        ]
    }


def with_claim(metadata: PackageMetadata) -> PackageMetadata:
    return metadata.model_copy(
        update={"manifest": {"dist": {"attestations": {"url": "https://x", "provenance": {}}}}}
    )


async def run_check(
    tmp_path: Path,
    verifier: FakeVerifier | None = None,
    handler: Callable[[httpx.Request], httpx.Response] | None = None,
    metadata: PackageMetadata | None = None,
    match: SourceMatch | None = None,
    tarball: bytes = TARBALL,
    timeout_seconds: float = 60.0,
) -> ProvenanceResult:
    def default(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=attestation_document())

    path = tmp_path / "package.tgz"
    path.write_bytes(tarball)
    transport = httpx.MockTransport(handler or default)
    async with httpx.AsyncClient(transport=transport) as client:
        checker = NpmProvenanceChecker(
            client, verifier=verifier or FakeVerifier(), timeout_seconds=timeout_seconds
        )
        return await checker.check(metadata or make_metadata(), path, match or matched())


def not_found(_: httpx.Request) -> httpx.Response:
    return httpx.Response(404, json={"error": "not found"})


async def test_verified(tmp_path: Path) -> None:
    result = await run_check(tmp_path)
    assert result.status is ProvenanceStatus.VERIFIED
    assert result.signature_verified
    assert result.tarball_digest_matches
    assert result.source_repository == "https://github.com/acme/demo"
    assert result.source_commit == COMMIT
    assert result.oidc_issuer == ISSUER
    assert result.repository_matches_declared is True
    assert result.commit_matches_source_match is True


async def test_metadata_claim_alone_is_never_verified(tmp_path: Path) -> None:
    claimed = with_claim(make_metadata())
    verifier = FakeVerifier(error=VerificationUnavailableError("offline"))
    result = await run_check(tmp_path, verifier, metadata=claimed)
    assert result.status is ProvenanceStatus.NOT_VERIFIED
    assert result.claimed_in_metadata
    assert not result.signature_verified


async def test_claim_with_missing_attestation_is_uncertain(tmp_path: Path) -> None:
    result = await run_check(tmp_path, handler=not_found, metadata=with_claim(make_metadata()))
    assert result.status is ProvenanceStatus.UNCERTAIN


async def test_no_attestation_is_unavailable(tmp_path: Path) -> None:
    verifier = FakeVerifier()
    result = await run_check(tmp_path, verifier, handler=not_found)
    assert result.status is ProvenanceStatus.UNAVAILABLE
    assert verifier.calls == 0


async def test_only_publish_attestation_is_unavailable(tmp_path: Path) -> None:
    document = {"attestations": [{"predicateType": "https://github.com/npm/publish", "bundle": {}}]}
    result = await run_check(tmp_path, handler=lambda _: httpx.Response(200, json=document))
    assert result.status is ProvenanceStatus.UNAVAILABLE


async def test_bad_signature_is_invalid(tmp_path: Path) -> None:
    result = await run_check(tmp_path, FakeVerifier(error=SignatureInvalidError("bad")))
    assert result.status is ProvenanceStatus.INVALID
    assert not result.signature_verified


async def test_tarball_not_matching_signed_digest_is_invalid(tmp_path: Path) -> None:
    result = await run_check(tmp_path, tarball=b"different bytes")
    assert result.status is ProvenanceStatus.INVALID
    assert result.signature_verified
    assert not result.tarball_digest_matches


@pytest.mark.parametrize(
    "changes",
    [
        {"subject": [{"name": "pkg:npm/other@1.0.0", "digest": {"sha512": "a"}}]},
        {"subject": [{"name": "pkg:npm/demo@2.0.0", "digest": {"sha512": "a"}}]},
        {"subject": []},
        {"subject": "x"},
        {"predicateType": "https://example.com/other"},
    ],
)
async def test_wrong_signed_statement_is_invalid(tmp_path: Path, changes: dict[str, Any]) -> None:
    result = await run_check(tmp_path, FakeVerifier(statement(**changes)))
    assert result.status is ProvenanceStatus.INVALID


async def test_two_subjects_are_invalid(tmp_path: Path) -> None:
    subject = statement()["subject"][0]
    result = await run_check(tmp_path, FakeVerifier(statement(subject=[subject, subject])))
    assert result.status is ProvenanceStatus.INVALID


async def test_missing_digest_is_invalid(tmp_path: Path) -> None:
    changed = statement(subject=[{"name": "pkg:npm/demo@1.0.0", "digest": {"sha1": "a"}}])
    assert (await run_check(tmp_path, FakeVerifier(changed))).status is ProvenanceStatus.INVALID


@pytest.mark.parametrize("payload", [b"not json", b"[]", b"[[" * 100_000])
async def test_unreadable_signed_payload_is_invalid(tmp_path: Path, payload: bytes) -> None:
    assert (await run_check(tmp_path, FakeVerifier(payload))).status is ProvenanceStatus.INVALID


async def test_wrong_payload_type_is_invalid(tmp_path: Path) -> None:
    result = await run_check(tmp_path, FakeVerifier(payload_type="text/plain"))
    assert result.status is ProvenanceStatus.INVALID


async def test_certificate_and_statement_disagreeing_on_commit_is_invalid(tmp_path: Path) -> None:
    verifier = FakeVerifier(signer=identity(source_commit="f" * 40))
    result = await run_check(tmp_path, verifier)
    assert result.status is ProvenanceStatus.INVALID
    assert result.tarball_digest_matches


async def test_statement_without_commit_is_invalid(tmp_path: Path) -> None:
    result = await run_check(tmp_path, FakeVerifier(statement(predicate={})))
    assert result.status is ProvenanceStatus.INVALID


async def test_unrecognized_issuer_is_invalid(tmp_path: Path) -> None:
    verifier = FakeVerifier(signer=identity(issuer="https://evil.example"))
    assert (await run_check(tmp_path, verifier)).status is ProvenanceStatus.INVALID


async def test_certificate_without_repository_is_invalid(tmp_path: Path) -> None:
    verifier = FakeVerifier(signer=identity(source_repository=None))
    assert (await run_check(tmp_path, verifier)).status is ProvenanceStatus.INVALID


async def test_other_repository_is_verified_but_reported(tmp_path: Path) -> None:
    verifier = FakeVerifier(signer=identity(source_repository="https://github.com/evil/demo"))
    result = await run_check(tmp_path, verifier)
    assert result.status is ProvenanceStatus.VERIFIED
    assert result.repository_matches_declared is False
    assert "evil/demo" in result.explanation


async def test_repository_comparison_ignores_case_and_git_suffix(tmp_path: Path) -> None:
    verifier = FakeVerifier(signer=identity(source_repository="https://github.com/ACME/demo.git/"))
    assert (await run_check(tmp_path, verifier)).repository_matches_declared is True


async def test_other_commit_is_verified_but_reported(tmp_path: Path) -> None:
    other = "e" * 40
    match = matched().model_copy(update={"commit_sha": other})
    result = await run_check(tmp_path, match=match)
    assert result.status is ProvenanceStatus.VERIFIED
    assert result.commit_matches_source_match is False


async def test_uncertain_source_match_has_nothing_to_compare(tmp_path: Path) -> None:
    match = SourceMatch(
        status=MatchStatus.UNCERTAIN,
        reason=UncertainReason.NO_MATCHING_TAG,
        explanation="test",
    )
    result = await run_check(tmp_path, match=match)
    assert result.status is ProvenanceStatus.VERIFIED
    assert result.commit_matches_source_match is None


async def test_verifier_failing_to_run_is_not_verified(tmp_path: Path) -> None:
    verifier = FakeVerifier(error=VerificationUnavailableError("no trust root"))
    assert (await run_check(tmp_path, verifier)).status is ProvenanceStatus.NOT_VERIFIED


async def test_verification_timeout_is_not_verified(tmp_path: Path) -> None:
    class Slow(FakeVerifier):
        def verify(self, bundle_json: str) -> VerifiedBundle:
            import time

            time.sleep(0.2)
            return super().verify(bundle_json)

    result = await run_check(tmp_path, Slow(), timeout_seconds=0.01)
    assert result.status is ProvenanceStatus.NOT_VERIFIED


async def test_unreadable_bundle_is_uncertain(tmp_path: Path) -> None:
    result = await run_check(tmp_path, FakeVerifier(error=BundleUnreadableError("bad")))
    assert result.status is ProvenanceStatus.UNCERTAIN


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json={"attestations": "x"}),
        httpx.Response(200, json={}),
        httpx.Response(200, json={"attestations": [{"predicateType": SLSA}]}),
        httpx.Response(
            200,
            json={
                "attestations": [
                    {"predicateType": SLSA, "bundle": {}},
                    {"predicateType": SLSA, "bundle": {}},
                ]
            },
        ),
    ],
)
async def test_bad_registry_responses_are_uncertain(
    tmp_path: Path, response: httpx.Response
) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(response.status_code, content=response.content)

    assert (await run_check(tmp_path, handler=handler)).status is ProvenanceStatus.UNCERTAIN


async def test_network_failure_is_uncertain(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    assert (await run_check(tmp_path, handler=handler)).status is ProvenanceStatus.UNCERTAIN


async def test_url_comes_from_registry_constant_with_encoded_name(tmp_path: Path) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(404)

    malicious = make_metadata(name="@acme/demo").model_copy(
        update={"manifest": {"dist": {"attestations": {"url": "https://evil.example/a"}}}}
    )
    await run_check(tmp_path, handler=handler, metadata=malicious)
    assert seen == ["https://registry.npmjs.org/-/npm/v1/attestations/@acme%2Fdemo@1.0.0"]


async def test_scoped_package_name_in_statement(tmp_path: Path) -> None:
    subject = {
        "name": "pkg:npm/%40acme/demo@1.0.0",
        "digest": {"sha512": hashlib.sha512(TARBALL).hexdigest()},
    }
    result = await run_check(
        tmp_path, FakeVerifier(statement(subject=[subject])), metadata=make_metadata("@acme/demo")
    )
    assert result.status is ProvenanceStatus.VERIFIED


def test_older_bundle_format_is_a_verifier_gap_not_a_failure() -> None:
    # sigstore-python raises VerificationError for intoto entries, which once made real
    # packages such as axios look tampered with.
    bundle = {
        "verificationMaterial": {
            "tlogEntries": [{"kindVersion": {"kind": "intoto", "version": "0.0.2"}}]
        }
    }
    with pytest.raises(VerificationUnavailableError, match="intoto 0.0.2"):
        SigstoreBundleVerifier().verify(json.dumps(bundle))


def test_garbage_bundle_is_unreadable() -> None:
    with pytest.raises(BundleUnreadableError):
        SigstoreBundleVerifier().verify(json.dumps({"mediaType": "nonsense"}))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"\x0c\x03abc", "abc"),
        (b"\x0c\x81\x03abc", "abc"),
        (b"abc", None),
        (b"\x0c\x05abc", None),
        (b"", None),
        (b"\x0c\x02\xff\xff", None),
    ],
)
def test_decode_der_utf8(raw: bytes, expected: str | None) -> None:
    assert _decode_der_utf8(raw) == expected


def test_model_refuses_verified_without_proof() -> None:
    with pytest.raises(ValidationError):
        ProvenanceResult(status=ProvenanceStatus.VERIFIED, explanation="metadata says so")
    with pytest.raises(ValidationError):
        ProvenanceResult(
            status=ProvenanceStatus.VERIFIED,
            explanation="no digest",
            signature_verified=True,
            source_repository="https://github.com/a/b",
        )


def test_model_refuses_identity_on_unverified_result() -> None:
    with pytest.raises(ValidationError):
        ProvenanceResult(
            status=ProvenanceStatus.INVALID,
            explanation="x",
            source_repository="https://github.com/a/b",
        )


async def test_attestation_for_other_package_with_same_bytes_is_invalid(tmp_path: Path) -> None:
    subject = {
        "name": "pkg:npm/other@1.0.0",
        "digest": {"sha512": hashlib.sha512(TARBALL).hexdigest()},
    }
    result = await run_check(tmp_path, FakeVerifier(statement(subject=[subject])))
    assert result.status is ProvenanceStatus.INVALID
    assert "pkg:npm/other" in result.explanation
