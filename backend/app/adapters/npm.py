"""Adapter for the official npm registry (https://registry.npmjs.org)."""

import base64
import binascii
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, cast, get_args
from urllib.parse import quote, urlsplit

import httpx
from pydantic import JsonValue

from app.adapters.base import (
    ArtifactHash,
    ArtifactInfo,
    Dependency,
    DependencyKind,
    DownloadedArtifact,
    HashAlgorithm,
    PackageAdapter,
    PackageMetadata,
    SourceRepository,
)
from app.adapters.errors import (
    InvalidPackageRequestError,
    InvalidRegistryResponseError,
    PackageNotFoundError,
    RegistryNotFoundError,
    VersionNotFoundError,
)
from app.adapters.http import RegistryLimits, download_verified, fetch_json
from app.schemas.scans import NPM_NAME, SEMVER, Ecosystem

REGISTRY_HOST = "registry.npmjs.org"
REGISTRY_URL = f"https://{REGISTRY_HOST}"

_SHASUM = re.compile(r"[0-9a-fA-F]{40}")
_SCP_REPOSITORY = re.compile(r"(?:[\w.-]+@)([\w.-]+):(?!/)(.+)")
_GITHUB_SHORTHAND = re.compile(r"[\w.-]+/[\w.-]+")
_HOST_SHORTHANDS = {
    "github": "github.com",
    "gitlab": "gitlab.com",
    "bitbucket": "bitbucket.org",
}
_REPOSITORY_SCHEMES = {"git", "git+https", "git+http", "git+ssh", "https", "http", "ssh"}
_DECLARED_DEPENDENCIES = {
    "dependencies": DependencyKind.RUNTIME,
    "devDependencies": DependencyKind.DEVELOPMENT,
    "peerDependencies": DependencyKind.PEER,
    "optionalDependencies": DependencyKind.OPTIONAL,
}
_ENTRY_POINT_FIELDS = ("main", "module", "browser", "exports", "bin", "types", "typings")
_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _normalize_repository_url(declared: str) -> str | None:
    """Convert npm's repository spellings to https, or None if the value is not recognized.

    The result will later be used to fetch source, so only plain https is ever returned.
    """
    value = declared.strip()
    if not value or any(ord(char) < 0x21 for char in value):
        return None

    host_prefix, separator, rest = value.partition(":")
    if separator and host_prefix in _HOST_SHORTHANDS and not rest.startswith("/"):
        value = f"https://{_HOST_SHORTHANDS[host_prefix]}/{rest}"
    elif _GITHUB_SHORTHAND.fullmatch(value):
        value = f"https://github.com/{value}"
    elif scp := _SCP_REPOSITORY.fullmatch(value):
        value = f"https://{scp.group(1)}/{scp.group(2)}"

    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme not in _REPOSITORY_SCHEMES or not host or "." not in host:
        return None

    path = parts.path.rstrip("/").removesuffix(".git")
    if not path or ".." in path.split("/"):
        return None
    return f"https://{host}{path}"


def _parse_repository(value: object) -> SourceRepository | None:
    directory = None
    if isinstance(value, dict):
        directory = _text(value.get("directory"))
        value = value.get("url")
    declared = _text(value)
    if declared is None:
        return None
    return SourceRepository(
        declared=declared, url=_normalize_repository_url(declared), directory=directory
    )


def _parse_license(manifest: dict[str, Any]) -> str | None:
    value = manifest.get("license")
    if isinstance(value, dict):
        value = value.get("type")
    return _text(value)


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _parse_dependencies(manifest: dict[str, Any]) -> tuple[Dependency, ...]:
    dependencies: list[Dependency] = []
    for field, kind in _DECLARED_DEPENDENCIES.items():
        declared = manifest.get(field)
        if isinstance(declared, dict):
            dependencies += [
                Dependency(name=name, specifier=specifier, kind=kind)
                for name, specifier in declared.items()
                if isinstance(specifier, str)
            ]

    # npm accepts both spellings. The value `true` means "everything", which only the
    # tarball can answer, so that form is left to the manifest.
    for field in ("bundleDependencies", "bundledDependencies"):
        declared = manifest.get(field)
        if isinstance(declared, list):
            dependencies += [
                Dependency(name=name, specifier=None, kind=DependencyKind.BUNDLED)
                for name in declared
                if isinstance(name, str)
            ]
    return tuple(dependencies)


def _parse_scripts(manifest: dict[str, Any]) -> dict[str, str]:
    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict):
        return {}
    return {name: body for name, body in scripts.items() if isinstance(body, str)}


def _parse_integrity(value: str) -> list[ArtifactHash]:
    """Parse a Subresource Integrity string, ignoring algorithms this adapter cannot verify."""
    hashes: list[ArtifactHash] = []
    for token in value.split():
        algorithm, _, encoded = token.partition("-")
        if algorithm not in get_args(HashAlgorithm):
            continue
        try:
            digest = base64.b64decode(encoded.partition("?")[0], validate=True)
        except binascii.Error as exc:
            raise InvalidRegistryResponseError("Malformed integrity value") from exc
        if len(digest) != hashlib.new(algorithm).digest_size:
            raise InvalidRegistryResponseError("Malformed integrity value")
        hashes.append(
            ArtifactHash(algorithm=cast(HashAlgorithm, algorithm), hex_digest=digest.hex())
        )
    return hashes


def _parse_hashes(dist: dict[str, Any]) -> tuple[ArtifactHash, ...]:
    hashes: list[ArtifactHash] = []
    integrity = dist.get("integrity")
    if isinstance(integrity, str):
        hashes += _parse_integrity(integrity)

    shasum = dist.get("shasum")
    if shasum is not None:
        if not isinstance(shasum, str) or not _SHASUM.fullmatch(shasum):
            raise InvalidRegistryResponseError("Malformed shasum value")
        hashes.append(ArtifactHash(algorithm="sha1", hex_digest=shasum.lower()))
    return tuple(dict.fromkeys(hashes))


def _require_registry_url(url: str) -> None:
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise InvalidRegistryResponseError("Malformed tarball URL") from exc
    # Comparing netloc also rejects embedded credentials and non-default ports.
    if (
        parts.scheme != "https"
        or parts.netloc != REGISTRY_HOST
        or parts.query
        or parts.fragment
        or not parts.path.endswith(".tgz")
    ):
        raise InvalidRegistryResponseError(f"Tarball is not hosted by {REGISTRY_HOST}: {url!r}")


def _require_tarball_of_package(url: str, name: str) -> None:
    _require_registry_url(url)
    filename = urlsplit(url).path.removeprefix(f"/{name}/-/")
    if filename == urlsplit(url).path or "/" in filename or "%" in filename or ".." in filename:
        raise InvalidRegistryResponseError(f"Tarball URL does not belong to {name}: {url!r}")


def _artifact_filename(name: str, version: str) -> str:
    return f"{name.removeprefix('@').replace('/', '-')}-{version}.tgz"


class NpmAdapter(PackageAdapter):
    ecosystem: ClassVar[Ecosystem] = Ecosystem.NPM

    def __init__(self, client: httpx.AsyncClient, limits: RegistryLimits | None = None) -> None:
        self._client = client
        self._limits = limits or RegistryLimits()

    async def fetch_metadata(self, name: str, version: str) -> PackageMetadata:
        if not isinstance(name, str) or len(name) > 214 or not NPM_NAME.fullmatch(name):
            raise InvalidPackageRequestError("Not a valid npm package name")
        if not isinstance(version, str) or len(version) > 256 or not SEMVER.fullmatch(version):
            raise InvalidPackageRequestError("Not an exact semantic version")

        # Only the full package document includes publication times. A scoped name is sent
        # as one encoded path segment, the form the registry documents.
        url = f"{REGISTRY_URL}/{quote(name, safe='@')}"
        try:
            document = await fetch_json(self._client, url, self._limits)
        except RegistryNotFoundError as exc:
            raise PackageNotFoundError(f"npm package {name} does not exist") from exc

        return self._parse_version(document, name, version)

    async def download_artifact(
        self, artifact: ArtifactInfo, destination_dir: Path
    ) -> DownloadedArtifact:
        _require_registry_url(artifact.url)
        return await download_verified(self._client, artifact, destination_dir, self._limits)

    def _parse_version(self, document: dict[str, Any], name: str, version: str) -> PackageMetadata:
        versions = document.get("versions")
        times = document.get("time")
        times = times if isinstance(times, dict) else {}

        # A fully unpublished package has a `time.unpublished` entry and no versions.
        if versions is None and "unpublished" in times:
            raise VersionNotFoundError(f"npm package {name} has been unpublished")
        if not isinstance(versions, dict):
            raise InvalidRegistryResponseError(f"No version list returned for {name}")
        if version not in versions:
            raise VersionNotFoundError(f"npm package {name} has no version {version}")

        manifest = versions[version]
        if not isinstance(manifest, dict):
            raise InvalidRegistryResponseError(f"Malformed document for {name}@{version}")
        if manifest.get("name") != name or manifest.get("version") != version:
            raise InvalidRegistryResponseError(
                f"Registry returned a different package for {name}@{version}"
            )

        dist = manifest.get("dist")
        if not isinstance(dist, dict) or not isinstance(dist.get("tarball"), str):
            raise InvalidRegistryResponseError(f"No tarball listed for {name}@{version}")
        _require_tarball_of_package(dist["tarball"], name)

        scripts = _parse_scripts(manifest)
        try:
            return PackageMetadata(
                ecosystem=Ecosystem.NPM,
                name=name,
                version=version,
                description=_text(manifest.get("description")),
                license=_parse_license(manifest),
                homepage=_text(manifest.get("homepage")),
                repository=_parse_repository(manifest.get("repository")),
                source_commit=_text(manifest.get("gitHead")),
                published_at=_parse_time(times.get(version)),
                dependencies=_parse_dependencies(manifest),
                scripts=scripts,
                has_install_script=manifest.get("hasInstallScript") is True
                or any(script in scripts for script in _INSTALL_SCRIPTS),
                entry_points={
                    field: cast(JsonValue, manifest[field])
                    for field in _ENTRY_POINT_FIELDS
                    if field in manifest
                },
                artifacts=(
                    ArtifactInfo(
                        url=dist["tarball"],
                        filename=_artifact_filename(name, version),
                        hashes=_parse_hashes(dist),
                        declared_integrity=_text(dist.get("integrity")),
                    ),
                ),
                manifest=manifest,
            )
        except (ValueError, RecursionError) as exc:
            # pydantic's ValidationError is a ValueError. Publisher fields can be any JSON.
            raise InvalidRegistryResponseError(
                f"Could not parse the document for {name}@{version}"
            ) from exc
