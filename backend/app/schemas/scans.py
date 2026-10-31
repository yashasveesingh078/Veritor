import re
from enum import StrEnum
from typing import Literal
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
        description="The request passed validation. No analysis is performed yet.",
    )
    ecosystem: Ecosystem
    package_name: str
    version: str
