"""Verify an npm package's SLSA provenance attestation.

A result of VERIFIED means all of these were checked:

1. The attestation's signature is valid under the public Sigstore trust root.
2. The signing certificate identifies a recognized CI provider and a source repository.
3. The signed statement names this package and version.
4. The signed statement's SHA-512 matches the tarball bytes on disk, not a registry value.
5. The commit in the signed statement agrees with the signed certificate.

It shows where the tarball was built, not that the code is safe, and a malicious project
can have valid provenance. Whether the signer is the expected repository is reported
separately, so that a valid attestation from the wrong repository stands out.
"""

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

import httpx

from app.adapters.base import PackageMetadata
from app.adapters.errors import AdapterError, RegistryNotFoundError
from app.adapters.http import RegistryLimits, fetch_json
from app.adapters.npm import REGISTRY_URL
from app.provenance.models import ProvenanceResult, ProvenanceStatus
from app.source.models import MatchStatus, SourceMatch

SLSA_PREDICATE_PREFIX = "https://slsa.dev/provenance/"
IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
TRUSTED_OIDC_ISSUERS = frozenset(
    {"https://token.actions.githubusercontent.com", "https://gitlab.com"}
)
SUPPORTED_LOG_ENTRY_KINDS = frozenset({"dsse", "hashedrekord"})
_OID_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8"
_OID_BUILD_SIGNER_URI = "1.3.6.1.4.1.57264.1.9"
_OID_SOURCE_REPOSITORY = "1.3.6.1.4.1.57264.1.12"
_OID_SOURCE_COMMIT = "1.3.6.1.4.1.57264.1.13"
_OID_SOURCE_REF = "1.3.6.1.4.1.57264.1.14"
_DER_UTF8_STRING = 0x0C
_HASH_CHUNK = 64 * 1024


class SignatureInvalidError(Exception):
    """The attestation's signature, certificate or transparency proof failed verification."""


class BundleUnreadableError(Exception):
    """The attestation is not a bundle this verifier can process."""


class VerificationUnavailableError(Exception):
    """Verification could not be run, for example because the trust root is out of reach."""


@dataclass(frozen=True)
class SignerIdentity:
    issuer: str | None
    source_repository: str | None
    source_commit: str | None
    source_ref: str | None
    build_workflow: str | None


@dataclass(frozen=True)
class VerifiedBundle:
    payload_type: str
    payload: bytes
    identity: SignerIdentity


class BundleVerifier(Protocol):
    def verify(self, bundle_json: str) -> VerifiedBundle:
        """Return the signed content, or raise one of the errors above. May block."""
        ...


def _unsupported_log_entry_kinds(bundle_json: str) -> set[str]:
    """Name transparency log entries of a kind that sigstore-python cannot verify."""
    try:
        material = json.loads(bundle_json).get("verificationMaterial")
        entries = material.get("tlogEntries")
        return {
            f"{entry['kindVersion']['kind']} {entry['kindVersion']['version']}"
            for entry in entries
            if entry["kindVersion"]["kind"] not in SUPPORTED_LOG_ENTRY_KINDS
        }
    except (AttributeError, KeyError, TypeError, ValueError):
        return set()  # Malformed bundles are rejected by the real parser.


class _NoOpPolicyWarningFilter(logging.Filter):
    """Drop sigstore's warning about the no-op policy, because it reads as if nothing is checked.

    The policy only skips matching a specific identity. Signatures, the certificate chain
    and the transparency log are still verified, and the identity is checked in this module.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        return "no-op" not in record.getMessage()


logging.getLogger("sigstore.verify.policy").addFilter(_NoOpPolicyWarningFilter())


def _decode_der_utf8(value: bytes) -> str | None:
    """Read a DER UTF8String, the encoding Fulcio uses for its newer certificate fields."""
    if len(value) < 2 or value[0] != _DER_UTF8_STRING:
        return None
    length = value[1]
    start = 2
    if length & 0x80:
        size = length & 0x7F
        length = int.from_bytes(value[2 : 2 + size])
        start = 2 + size
    if start + length != len(value):
        return None
    try:
        return value[start : start + length].decode()
    except UnicodeDecodeError:
        return None


class SigstoreBundleVerifier:
    """Verify bundles with sigstore-python against the production trust root."""

    def verify(self, bundle_json: str) -> VerifiedBundle:
        try:
            from sigstore.errors import VerificationError
            from sigstore.models import Bundle, InvalidBundle
            from sigstore.verify import Verifier, policy
        except ImportError as exc:
            raise VerificationUnavailableError("sigstore is not installed") from exc

        unsupported = _unsupported_log_entry_kinds(bundle_json)
        if unsupported:
            # Failing here matters: sigstore-python raises VerificationError for these, and
            # a gap in the verifier must not be reported as a failed attestation. A bundle
            # that lies about its kind only earns NOT_VERIFIED, which gets no credit.
            raise VerificationUnavailableError(
                "The verifier does not support this older attestation format: "
                + ", ".join(sorted(unsupported))
            )

        try:
            bundle = Bundle.from_json(bundle_json)
        except (InvalidBundle, ValueError) as exc:
            raise BundleUnreadableError(str(exc)) from exc

        try:
            verifier = Verifier.production()
        except Exception as exc:
            # The trust root is fetched over the network, with many possible failures.
            raise VerificationUnavailableError(f"Could not load the trust root: {exc}") from exc

        try:
            # The identity is checked by the caller against what is expected of this
            # package, so no policy is applied here. The certificate chain is still verified.
            payload_type, payload = verifier.verify_dsse(bundle, policy.UnsafeNoOp())
        except VerificationError as exc:
            raise SignatureInvalidError(str(exc)) from exc
        except (ValueError, TypeError) as exc:
            raise BundleUnreadableError(str(exc)) from exc

        return VerifiedBundle(
            payload_type=payload_type,
            payload=payload,
            identity=_identity_from_certificate(bundle.signing_certificate),
        )


def _identity_from_certificate(certificate: Any) -> SignerIdentity:
    values: dict[str, str | None] = {}
    for extension in certificate.extensions:
        oid = extension.oid.dotted_string
        if oid in (
            _OID_ISSUER_V2,
            _OID_BUILD_SIGNER_URI,
            _OID_SOURCE_REPOSITORY,
            _OID_SOURCE_COMMIT,
            _OID_SOURCE_REF,
        ):
            raw = getattr(extension.value, "value", None)
            values[oid] = _decode_der_utf8(raw) if isinstance(raw, bytes) else None
    return SignerIdentity(
        issuer=values.get(_OID_ISSUER_V2),
        source_repository=values.get(_OID_SOURCE_REPOSITORY),
        source_commit=values.get(_OID_SOURCE_COMMIT),
        source_ref=values.get(_OID_SOURCE_REF),
        build_workflow=values.get(_OID_BUILD_SIGNER_URI),
    )


def _sha512_of(path: Path) -> str:
    hasher = hashlib.sha512()
    with path.open("rb") as file:
        while chunk := file.read(_HASH_CHUNK):
            hasher.update(chunk)
    return hasher.hexdigest()


def _expected_purl(name: str, version: str) -> str:
    return f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='')}"


def _normalize_repository(url: str | None) -> str | None:
    if not url:
        return None
    return url.strip().rstrip("/").removesuffix(".git").lower()


def _claimed_in_metadata(metadata: PackageMetadata) -> bool:
    dist = metadata.manifest.get("dist")
    return isinstance(dist, dict) and isinstance(dist.get("attestations"), dict)


class NpmProvenanceChecker:
    def __init__(
        self,
        client: httpx.AsyncClient,
        limits: RegistryLimits | None = None,
        verifier: BundleVerifier | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self._client = client
        self._limits = limits or RegistryLimits()
        self._verifier = verifier if verifier is not None else SigstoreBundleVerifier()
        self._timeout_seconds = timeout_seconds

    async def check(
        self, metadata: PackageMetadata, tarball_path: Path, match: SourceMatch
    ) -> ProvenanceResult:
        """Check provenance for a downloaded tarball. Failures are returned, not raised."""
        claimed = _claimed_in_metadata(metadata)
        url = (
            f"{REGISTRY_URL}/-/npm/v1/attestations/"
            f"{quote(metadata.name, safe='@')}@{quote(metadata.version, safe='')}"
        )
        try:
            document = await fetch_json(self._client, url, self._limits)
        except RegistryNotFoundError:
            if claimed:
                return _result(
                    ProvenanceStatus.UNCERTAIN,
                    "Metadata lists provenance, but the registry has no attestation for it.",
                    claimed,
                )
            return _result(
                ProvenanceStatus.UNAVAILABLE,
                "This version has no published provenance. Most packages do not.",
                claimed,
            )
        except AdapterError as exc:
            return _result(
                ProvenanceStatus.UNCERTAIN, f"Could not retrieve attestations: {exc}", claimed
            )

        attestations = document.get("attestations")
        if not isinstance(attestations, list):
            return _result(
                ProvenanceStatus.UNCERTAIN, "The attestation response is malformed.", claimed
            )
        provenance = [
            item
            for item in attestations
            if isinstance(item, dict)
            and isinstance(item.get("predicateType"), str)
            and item["predicateType"].startswith(SLSA_PREDICATE_PREFIX)
        ]
        if not provenance:
            return _result(
                ProvenanceStatus.UNAVAILABLE,
                "The registry has no SLSA provenance for this version.",
                claimed,
            )
        if len(provenance) > 1:
            return _result(
                ProvenanceStatus.UNCERTAIN,
                "The registry lists several provenance attestations for this version.",
                claimed,
            )
        return await self._verify(provenance[0], metadata, tarball_path, match, claimed)

    async def _verify(
        self,
        attestation: dict[str, Any],
        metadata: PackageMetadata,
        tarball_path: Path,
        match: SourceMatch,
        claimed: bool,
    ) -> ProvenanceResult:
        bundle = attestation.get("bundle")
        if not isinstance(bundle, dict):
            return _result(ProvenanceStatus.UNCERTAIN, "The attestation has no bundle.", claimed)

        try:
            async with asyncio.timeout(self._timeout_seconds):
                verified = await asyncio.to_thread(self._verifier.verify, json.dumps(bundle))
        except SignatureInvalidError as exc:
            return _result(
                ProvenanceStatus.INVALID, f"The signature failed verification: {exc}", claimed
            )
        except BundleUnreadableError as exc:
            return _result(
                ProvenanceStatus.UNCERTAIN, f"The attestation could not be read: {exc}", claimed
            )
        except TimeoutError:
            return _result(
                ProvenanceStatus.NOT_VERIFIED, "Verification did not finish in time.", claimed
            )
        except VerificationUnavailableError as exc:
            return _result(
                ProvenanceStatus.NOT_VERIFIED,
                f"An attestation exists, but it could not be verified: {exc}",
                claimed,
            )

        return await asyncio.to_thread(
            _evaluate_signed_content, verified, metadata, tarball_path, match, claimed
        )


def _evaluate_signed_content(
    verified: VerifiedBundle,
    metadata: PackageMetadata,
    tarball_path: Path,
    match: SourceMatch,
    claimed: bool,
) -> ProvenanceResult:
    """Everything here was signed, so any disagreement is a failed attestation."""

    def invalid(explanation: str, digest_matches: bool = False) -> ProvenanceResult:
        return ProvenanceResult(
            status=ProvenanceStatus.INVALID,
            explanation=explanation,
            claimed_in_metadata=claimed,
            signature_verified=True,
            tarball_digest_matches=digest_matches,
        )

    identity = verified.identity
    if identity.issuer not in TRUSTED_OIDC_ISSUERS:
        return invalid(f"The signer's identity provider is not recognized: {identity.issuer!r}")
    if not identity.source_repository or not identity.source_commit:
        return invalid("The signing certificate does not identify a source repository and commit.")
    if verified.payload_type != IN_TOTO_PAYLOAD_TYPE:
        return invalid(f"The signed content has an unexpected type: {verified.payload_type!r}")

    try:
        statement = json.loads(verified.payload)
    except (ValueError, RecursionError):
        return invalid("The signed statement is not valid JSON.")
    if not isinstance(statement, dict):
        return invalid("The signed statement is malformed.")
    predicate_type = statement.get("predicateType")
    if not isinstance(predicate_type, str) or not predicate_type.startswith(SLSA_PREDICATE_PREFIX):
        return invalid("The signed statement is not SLSA provenance.")

    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(subjects[0], dict):
        return invalid("The signed statement does not name exactly one package.")
    subject = subjects[0]
    expected = _expected_purl(metadata.name, metadata.version)
    if subject.get("name") != expected:
        return invalid(f"The attestation is for {subject.get('name')!r}, not {expected!r}.")

    digests = subject.get("digest")
    claimed_digest = digests.get("sha512") if isinstance(digests, dict) else None
    if not isinstance(claimed_digest, str):
        return invalid("The signed statement has no SHA-512 for the package.")
    if claimed_digest.lower() != _sha512_of(tarball_path):
        return invalid("The downloaded tarball does not match the signed SHA-512.")

    signed_commit = _commit_in_statement(statement)
    if signed_commit is None or signed_commit != identity.source_commit.lower():
        return invalid("The certificate and the signed statement name different commits.", True)

    declared = metadata.repository.url if metadata.repository else None
    declared_normalized = _normalize_repository(declared)
    repository_matches = (
        _normalize_repository(identity.source_repository) == declared_normalized
        if declared_normalized
        else None
    )
    commit_matches = (
        match.commit_sha == identity.source_commit.lower()
        if match.status is MatchStatus.MATCHED
        else None
    )

    notes = ["The signature, signer identity and tarball hash all verified."]
    if repository_matches is False:
        notes.append(f"However, it was built from {identity.source_repository}, not {declared}.")
    if commit_matches is False:
        notes.append(f"However, it was built from a different commit than {match.commit_sha}.")
    return ProvenanceResult(
        status=ProvenanceStatus.VERIFIED,
        explanation=" ".join(notes),
        claimed_in_metadata=claimed,
        signature_verified=True,
        tarball_digest_matches=True,
        source_repository=identity.source_repository,
        source_commit=identity.source_commit.lower(),
        source_ref=identity.source_ref,
        build_workflow=identity.build_workflow,
        oidc_issuer=identity.issuer,
        repository_matches_declared=repository_matches,
        commit_matches_source_match=commit_matches,
    )


def _commit_in_statement(statement: dict[str, Any]) -> str | None:
    predicate = statement.get("predicate")
    definition = predicate.get("buildDefinition") if isinstance(predicate, dict) else None
    dependencies = definition.get("resolvedDependencies") if isinstance(definition, dict) else None
    if not isinstance(dependencies, list) or not dependencies:
        return None
    first = dependencies[0]
    digest = first.get("digest") if isinstance(first, dict) else None
    commit = digest.get("gitCommit") if isinstance(digest, dict) else None
    return commit.lower() if isinstance(commit, str) else None


def _result(status: ProvenanceStatus, explanation: str, claimed: bool) -> ProvenanceResult:
    return ProvenanceResult(status=status, explanation=explanation, claimed_in_metadata=claimed)


__all__ = [
    "BundleUnreadableError",
    "BundleVerifier",
    "NpmProvenanceChecker",
    "SigstoreBundleVerifier",
    "SignatureInvalidError",
    "SignerIdentity",
    "VerificationUnavailableError",
    "VerifiedBundle",
]
