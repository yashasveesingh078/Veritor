import re
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

# Uppercase is allowed because legacy npm packages such as JSONStream still use it.
NPM_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*")
# https://packaging.python.org/en/latest/specifications/name-normalization/
PYPI_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")

_SEMVER_NUMBER = r"(?:0|[1-9][0-9]*)"
_SEMVER_PRERELEASE_ID = rf"(?:{_SEMVER_NUMBER}|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
# https://semver.org/
SEMVER = re.compile(
    rf"{_SEMVER_NUMBER}\.{_SEMVER_NUMBER}\.{_SEMVER_NUMBER}"
    rf"(?:-{_SEMVER_PRERELEASE_ID}(?:\.{_SEMVER_PRERELEASE_ID})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


class Ecosystem(StrEnum):
    NPM = "npm"
    PYPI = "pypi"


def _is_pep440(version: str) -> bool:
    # Version() tolerates surrounding whitespace, which is not part of a real version.
    if version != version.strip():
        return False
    try:
        Version(version)
    except InvalidVersion:
        return False
    return True


class ScanState(StrEnum):
    ACCEPTED = "accepted"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanStage(StrEnum):
    QUEUED = "queued"
    FETCHING_METADATA = "fetching_metadata"
    DOWNLOADING_ARTIFACT = "downloading_artifact"
    RESOLVING_SOURCE = "resolving_source"
    EXTRACTING_PACKAGE = "extracting_package"
    DOWNLOADING_SOURCE = "downloading_source"
    EXTRACTING_SOURCE = "extracting_source"
    COMPARING = "comparing"
    SECURITY_SCANNING = "security_scanning"
    CHECKING_PROVENANCE = "checking_provenance"
    SCORING_RISK = "scoring_risk"
    AI_INVESTIGATION = "ai_investigation"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Declared first so the validators below can read it from ValidationInfo.
    ecosystem: Ecosystem
    package_name: str = Field(min_length=1, max_length=214)
    version: str = Field(
        min_length=1,
        max_length=256,
        description="An exact published version. Ranges and tags such as 'latest' are rejected.",
    )

    @field_validator("package_name")
    @classmethod
    def validate_package_name(cls, value: str, info: ValidationInfo) -> str:
        ecosystem = info.data.get("ecosystem")
        if ecosystem is Ecosystem.NPM and not NPM_NAME.fullmatch(value):
            raise ValueError("Not a valid npm package name")
        if ecosystem is Ecosystem.PYPI and not PYPI_NAME.fullmatch(value):
            raise ValueError("Not a valid PyPI package name")
        return value

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str, info: ValidationInfo) -> str:
        ecosystem = info.data.get("ecosystem")
        if ecosystem is Ecosystem.NPM and not SEMVER.fullmatch(value):
            raise ValueError("Not an exact semantic version")
        if ecosystem is Ecosystem.PYPI and not _is_pep440(value):
            raise ValueError("Not a valid PEP 440 version")
        return value


class ScanResponse(BaseModel):
    scan_id: UUID
    status: Literal["accepted"] = Field(
        default="accepted",
        description="The request passed validation.",
    )
    ecosystem: Ecosystem
    package_name: str
    version: str


class ScanStatusResponse(BaseModel):
    scan_id: UUID
    ecosystem: Ecosystem
    package_name: str
    version: str
    status: ScanState
    stage: ScanStage
    progress_percent: int = Field(ge=0, le=100)
    message: str
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None


class FileDiffItem(BaseModel):
    path: str
    status: str
    diff_status: str
    unified: str | None = None
    added_lines: int | None = None
    removed_lines: int | None = None


class ScanDiffsResponse(BaseModel):
    scan_id: UUID
    package_name: str
    version: str
    total_diffs: int
    diffs: list[FileDiffItem]


class ScanFilesResponse(BaseModel):
    scan_id: UUID
    package_name: str
    version: str
    summary: Any | None = None
    files: list[Any] = []


class ScanFindingsResponse(BaseModel):
    scan_id: UUID
    package_name: str
    version: str
    risk_score: int | None = None
    risk_level: str | None = None
    findings: list[Any] = []
    ai_explanations: list[Any] = []
    gaps: list[Any] = []
    factors: list[Any] = []
    floors: list[Any] = []


class ScanReportResponse(BaseModel):
    scan_id: UUID
    ecosystem: Ecosystem
    package_name: str
    version: str
    status: ScanState
    metadata: Any | None = None
    source_match: Any | None = None
    comparison: Any | None = None
    security: Any | None = None
    provenance: Any | None = None
    risk: Any | None = None
    ai: Any | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    error: str | None = None
