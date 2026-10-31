from enum import StrEnum
from pathlib import Path
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class MatchStatus(StrEnum):
    MATCHED = "MATCHED"
    UNCERTAIN = "UNCERTAIN"


class MatchMethod(StrEnum):
    RECORDED_COMMIT_AND_TAG = "recorded_commit_and_tag"
    PACKAGE_TAG = "package_tag"
    VERSION_TAG = "version_tag"
    RELEASE_PREFIX_TAG = "release_prefix_tag"
    RECORDED_COMMIT = "recorded_commit"
    NONE = "none"


class Confidence(StrEnum):
    """How much evidence supports the match.

    Recorded commits and tags are both controlled by the publisher, so even HIGH means
    that independent pointers agree, not that the published code matches the source.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class UncertainReason(StrEnum):
    NO_REPOSITORY = "no_repository"
    UNSUPPORTED_HOST = "unsupported_host"
    REPOSITORY_NOT_FOUND = "repository_not_found"
    NO_MATCHING_TAG = "no_matching_tag"
    AMBIGUOUS_TAGS = "ambiguous_tags"
    RECORDED_COMMIT_CONFLICTS_WITH_TAG = "recorded_commit_conflicts_with_tag"
    RECORDED_COMMIT_UNVERIFIED = "recorded_commit_unverified"
    # The only retryable reason: the evidence could not be read, rather than being absent.
    LOOKUP_FAILED = "lookup_failed"


class GitHubRepository(BaseModel):
    model_config = ConfigDict(frozen=True)

    owner: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9-]*$")
    name: str = Field(pattern=r"^[A-Za-z0-9_][A-Za-z0-9._-]*$|^\.[A-Za-z0-9._-]*[A-Za-z0-9_-]$")

    @property
    def url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}"


class SourceMatch(BaseModel):
    """The result of source discovery. An UNCERTAIN result can never carry a commit."""

    model_config = ConfigDict(frozen=True)

    status: MatchStatus
    method: MatchMethod = MatchMethod.NONE
    confidence: Confidence = Confidence.NONE
    reason: UncertainReason | None = None
    explanation: str
    repository: GitHubRepository | None = None
    directory: str | None = None
    commit_sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    tag: str | None = None
    recorded_commit: str | None = Field(
        default=None, description="The commit the package recorded, which may be unconfirmed."
    )
    tags_found: dict[str, str] = Field(
        default_factory=dict, description="Each candidate tag in the repository, with its commit."
    )
    tags_checked: tuple[str, ...] = ()

    @model_validator(mode="after")
    def check_status_is_consistent(self) -> Self:
        if self.status is MatchStatus.MATCHED:
            if (
                self.commit_sha is None
                or self.repository is None
                or self.reason is not None
                or self.method is MatchMethod.NONE
                or self.confidence is Confidence.NONE
            ):
                raise ValueError("A MATCHED result needs a commit, repository, method, confidence")
        elif (
            self.commit_sha is not None
            or self.tag is not None
            or self.reason is None
            or self.method is not MatchMethod.NONE
            or self.confidence is not Confidence.NONE
        ):
            raise ValueError("An UNCERTAIN result needs a reason and cannot select a source")
        return self


class SourceArchive(BaseModel):
    model_config = ConfigDict(frozen=True)

    repository: GitHubRepository
    commit_sha: str
    path: Path
    size_bytes: int
    sha256: str = Field(
        description="The hash observed at download. GitHub publishes none to verify against."
    )
