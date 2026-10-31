"""Bounded, verified HTTP retrieval shared by registry adapters."""

import asyncio
import hashlib
import json
import os
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from app.adapters.base import ArtifactHash, ArtifactInfo, DownloadedArtifact, HashAlgorithm
from app.adapters.errors import (
    ArtifactStorageError,
    IntegrityVerificationError,
    InvalidRegistryResponseError,
    RegistryNotFoundError,
    RegistryTimeoutError,
    RegistryUnavailableError,
    ResponseTooLargeError,
)

CHUNK_SIZE = 64 * 1024
USER_AGENT = "veritor/0.1.0"
NOT_FOUND_STATUSES = frozenset({404})


@dataclass(frozen=True)
class RegistryLimits:
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 30.0
    # Read timeouts only cover the gap between chunks, so a slow stream also needs a deadline.
    metadata_deadline_seconds: float = 60.0
    download_deadline_seconds: float = 300.0
    # The largest package document seen in testing (next) decoded to about 31 MiB.
    max_metadata_bytes: int = 128 * 1024 * 1024
    max_artifact_bytes: int = 256 * 1024 * 1024
    # Source archives contain a whole repository, which can be far larger than a package.
    max_source_archive_bytes: int = 1024 * 1024 * 1024


def create_registry_client(limits: RegistryLimits) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=limits.connect_timeout_seconds,
            read=limits.read_timeout_seconds,
            write=limits.read_timeout_seconds,
            pool=limits.connect_timeout_seconds,
        ),
        follow_redirects=False,
        # Keeps .netrc credentials and proxy variables out of requests.
        trust_env=False,
        headers={"User-Agent": USER_AGENT},
    )


def _check_status(response: httpx.Response, not_found_statuses: frozenset[int]) -> None:
    status = response.status_code
    if status == 200:
        return
    if status in not_found_statuses:
        raise RegistryNotFoundError(f"Registry returned {status} for {response.url}")
    # GitHub reports an exhausted rate limit as 403 as well as 429.
    if status in (403, 429) or status >= 500:
        raise RegistryUnavailableError(f"Registry returned {status} for {response.url}")
    raise InvalidRegistryResponseError(f"Unexpected status {status} for {response.url}")


def _check_declared_size(response: httpx.Response, limit: int) -> None:
    declared = response.headers.get("Content-Length")
    if declared is not None and declared.isdecimal() and int(declared) > limit:
        raise ResponseTooLargeError(f"Response from {response.url} exceeds {limit} bytes")


@asynccontextmanager
async def _registry_stream(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str],
    deadline_seconds: float,
    not_found_statuses: frozenset[int] = NOT_FOUND_STATUSES,
) -> AsyncIterator[httpx.Response]:
    try:
        async with asyncio.timeout(deadline_seconds):
            # Redirects are refused so a response cannot move a request to another host.
            async with client.stream(
                "GET", url, headers=headers, follow_redirects=False
            ) as response:
                _check_status(response, not_found_statuses)
                yield response
    except (TimeoutError, httpx.TimeoutException) as exc:
        raise RegistryTimeoutError(f"Timed out retrieving {url}") from exc
    except httpx.DecodingError as exc:
        raise InvalidRegistryResponseError(f"Could not decode response from {url}") from exc
    except httpx.HTTPError as exc:
        raise RegistryUnavailableError(f"Could not retrieve {url}") from exc


async def fetch_bytes(
    client: httpx.AsyncClient,
    url: str,
    limits: RegistryLimits,
    headers: dict[str, str],
    not_found_statuses: frozenset[int] = NOT_FOUND_STATUSES,
) -> bytes:
    body = bytearray()
    async with _registry_stream(
        client, url, headers, limits.metadata_deadline_seconds, not_found_statuses
    ) as response:
        _check_declared_size(response, limits.max_metadata_bytes)
        async for chunk in response.aiter_bytes(CHUNK_SIZE):
            body += chunk
            if len(body) > limits.max_metadata_bytes:
                raise ResponseTooLargeError(
                    f"Response from {url} exceeds {limits.max_metadata_bytes} bytes"
                )
    return bytes(body)


async def fetch_json(
    client: httpx.AsyncClient,
    url: str,
    limits: RegistryLimits,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    body = await fetch_bytes(client, url, limits, headers or {"Accept": "application/json"})
    try:
        document = json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise InvalidRegistryResponseError(f"Response from {url} is not valid JSON") from exc
    if not isinstance(document, dict):
        raise InvalidRegistryResponseError(f"Response from {url} is not a JSON object")
    return document


async def download_verified(
    client: httpx.AsyncClient,
    artifact: ArtifactInfo,
    destination_dir: Path,
    limits: RegistryLimits,
) -> DownloadedArtifact:
    """Stream an artifact to disk, and keep it only if every published hash matches.

    The file is written and hashed as opaque bytes. It is never unpacked or executed.
    """
    if not artifact.hashes:
        raise IntegrityVerificationError(f"{artifact.filename} has no published hash to verify")
    return await _download_to_file(
        client,
        artifact.url,
        artifact.filename,
        destination_dir,
        limits.download_deadline_seconds,
        limits.max_artifact_bytes,
        artifact.hashes,
    )


async def download_unhashed(
    client: httpx.AsyncClient,
    url: str,
    filename: str,
    destination_dir: Path,
    limits: RegistryLimits,
) -> DownloadedArtifact:
    """Stream a file with no published hash to disk as opaque bytes, recording its sha256.

    ``verified_algorithms`` is empty on the result, because nothing was verified.
    """
    return await _download_to_file(
        client,
        url,
        filename,
        destination_dir,
        limits.download_deadline_seconds,
        limits.max_source_archive_bytes,
        (),
    )


async def _download_to_file(
    client: httpx.AsyncClient,
    url: str,
    filename: str,
    destination_dir: Path,
    deadline_seconds: float,
    max_bytes: int,
    expected_hashes: tuple[ArtifactHash, ...],
) -> DownloadedArtifact:
    algorithms: set[HashAlgorithm] = {item.algorithm for item in expected_hashes} | {"sha256"}
    hashers = {algorithm: hashlib.new(algorithm) for algorithm in algorithms}
    temp_path: Path | None = None
    size = 0
    try:
        destination_dir.mkdir(parents=True, exist_ok=True)
        # NamedTemporaryFile creates the file with mode 0600, so it is never executable.
        with tempfile.NamedTemporaryFile(
            dir=destination_dir, prefix=".download-", delete=False
        ) as temp_file:
            temp_path = Path(temp_file.name)
            # Identity encoding and raw bytes mean the hash covers exactly what was published.
            async with _registry_stream(
                client, url, {"Accept-Encoding": "identity"}, deadline_seconds
            ) as response:
                _check_declared_size(response, max_bytes)
                async for chunk in response.aiter_raw(CHUNK_SIZE):
                    size += len(chunk)
                    if size > max_bytes:
                        raise ResponseTooLargeError(f"{filename} exceeds {max_bytes} bytes")
                    temp_file.write(chunk)
                    for hasher in hashers.values():
                        hasher.update(chunk)

        # Every hash must match, so a weak sha1 cannot outvote a failed sha512.
        for expected in expected_hashes:
            if hashers[expected.algorithm].hexdigest() != expected.hex_digest:
                raise IntegrityVerificationError(
                    f"{filename} does not match its published {expected.algorithm} hash"
                )

        final_path = destination_dir / filename
        os.replace(temp_path, final_path)
        temp_path = None
    except OSError as exc:
        raise ArtifactStorageError(f"Could not store {filename}") from exc
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

    return DownloadedArtifact(
        path=final_path,
        size_bytes=size,
        sha256=hashers["sha256"].hexdigest(),
        verified_algorithms=tuple(
            sorted({item.algorithm for item in expected_hashes}, key=_strength_order)
        ),
    )


def _strength_order(algorithm: HashAlgorithm) -> int:
    return ("sha512", "sha384", "sha256", "sha1").index(algorithm)
