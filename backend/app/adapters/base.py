from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from app.schemas.scans import Ecosystem

HashAlgorithm = Literal["sha512", "sha384", "sha256", "sha1"]


class DependencyKind(StrEnum):
    RUNTIME = "runtime"
    DEVELOPMENT = "development"
    PEER = "peer"
    OPTIONAL = "optional"
    BUNDLED = "bundled"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class Dependency(_FrozenModel):
    name: str
    specifier: str | None
    kind: DependencyKind


class SourceRepository(_FrozenModel):
    declared: str = Field(description="The repository value exactly as the publisher declared it.")
    url: str | None = Field(description="An https URL, or None if it could not be normalized.")
    directory: str | None = None


class ArtifactHash(_FrozenModel):
    algorithm: HashAlgorithm
    hex_digest: str = Field(pattern=r"^[0-9a-f]+$")


class ArtifactInfo(_FrozenModel):
    url: str
    filename: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+~-]*$")
    hashes: tuple[ArtifactHash, ...]
    declared_integrity: str | None = None


class PackageMetadata(_FrozenModel):
    """Registry metadata for one exact version.

    Everything except the artifact hashes is declared by the publisher. It is untrusted
    and may differ from the files inside the artifact.
    """

    ecosystem: Ecosystem
    name: str
    version: str
    description: str | None
    license: str | None
    homepage: str | None
    repository: SourceRepository | None
    source_commit: str | None
    published_at: datetime | None
    dependencies: tuple[Dependency, ...]
    scripts: dict[str, str]
    has_install_script: bool
    entry_points: dict[str, JsonValue]
    artifacts: tuple[ArtifactInfo, ...]
    manifest: dict[str, JsonValue] = Field(
        repr=False, description="The complete version document from the registry."
    )


class DownloadedArtifact(_FrozenModel):
    path: Path
    size_bytes: int
    sha256: str
    verified_algorithms: tuple[HashAlgorithm, ...] = Field(
        description="The published hashes the file matched. sha1 alone is weak evidence."
    )


class PackageAdapter(ABC):
    """Retrieves metadata and artifacts from one package ecosystem.

    Implementations must treat all retrieved content as untrusted data. They must never
    install, import, unpack or execute a package, or run its lifecycle scripts.
    Failures are reported as ``AdapterError`` subclasses.
    """

    ecosystem: ClassVar[Ecosystem]

    @abstractmethod
    async def fetch_metadata(self, name: str, version: str) -> PackageMetadata:
        """Return metadata for an exact version."""

    @abstractmethod
    async def download_artifact(
        self, artifact: ArtifactInfo, destination_dir: Path
    ) -> DownloadedArtifact:
        """Download an artifact, keeping the file only if its published hashes match."""
