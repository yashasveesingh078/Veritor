from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ProvenanceStatus(StrEnum):
    """What is known about a package's provenance.

    VERIFIED is only ever the result of checking a signature. Metadata saying that an
    attestation exists is never enough: that is NOT_VERIFIED at best.
    """

    # The Sigstore signature, the signer's identity and the tarball's hash were all checked.
    VERIFIED = "VERIFIED"
    # An attestation exists and failed a check. This is evidence of a problem.
    INVALID = "INVALID"
    # No provenance was published, as with most packages. This is not evidence of a problem.
    UNAVAILABLE = "UNAVAILABLE"
    # An attestation exists, but the verification could not be run.
    NOT_VERIFIED = "NOT_VERIFIED"
    # Whether an attestation exists or what it says could not be determined.
    UNCERTAIN = "UNCERTAIN"


class ProvenanceResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: ProvenanceStatus
    explanation: str
    claimed_in_metadata: bool = Field(
        default=False, description="Registry metadata lists provenance. This alone proves nothing."
    )
    signature_verified: bool = False
    tarball_digest_matches: bool = False
    # These come from the signed certificate, and are only set when status is VERIFIED.
    source_repository: str | None = None
    source_commit: str | None = None
    source_ref: str | None = None
    build_workflow: str | None = None
    oidc_issuer: str | None = None
    # None means there was nothing to compare with.
    repository_matches_declared: bool | None = None
    commit_matches_source_match: bool | None = None

    @model_validator(mode="after")
    def check_verified_was_really_verified(self) -> Self:
        if self.status is ProvenanceStatus.VERIFIED and not (
            self.signature_verified and self.tarball_digest_matches and self.source_repository
        ):
            raise ValueError("VERIFIED needs a checked signature, digest and signer identity")
        if self.status is not ProvenanceStatus.VERIFIED and self.source_repository is not None:
            raise ValueError("Only a VERIFIED result can report signed identity details")
        return self
