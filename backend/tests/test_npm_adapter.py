import asyncio
import base64
import gzip
import hashlib
import json
import os
import stat
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.adapters.base import DependencyKind, PackageAdapter, PackageMetadata
from app.adapters.errors import (
    ArtifactStorageError,
    IntegrityVerificationError,
    InvalidPackageRequestError,
    InvalidRegistryResponseError,
    PackageNotFoundError,
    RegistryNotFoundError,
    RegistryTimeoutError,
    RegistryUnavailableError,
    ResponseTooLargeError,
    VersionNotFoundError,
)
from app.adapters.http import RegistryLimits, create_registry_client
from app.adapters.npm import NpmAdapter, _normalize_repository_url
from app.config import Settings
from app.schemas.scans import Ecosystem

pytestmark = pytest.mark.anyio

NAME = "demo-pkg"
VERSION = "1.2.3"
TARBALL = b"opaque tarball bytes: postinstall would touch a sentinel file"
TARBALL_URL = f"https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz"
Handler = Callable[[httpx.Request], httpx.Response]


def sri(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def dist(**overrides: Any) -> dict[str, Any]:
    return {
        "tarball": TARBALL_URL,
        "integrity": sri(TARBALL),
        "shasum": hashlib.sha1(TARBALL, usedforsecurity=False).hexdigest(),
        **overrides,
    }


def manifest(**overrides: Any) -> dict[str, Any]:
    return {"name": NAME, "version": VERSION, "dist": dist(), **overrides}


def packument(**overrides: Any) -> dict[str, Any]:
    return {
        "name": NAME,
        "time": {VERSION: "2026-01-02T03:04:05.678Z"},
        "versions": {VERSION: manifest(**overrides)},
    }


def json_handler(document: Any) -> Handler:
    return lambda _: httpx.Response(200, json=document)


def adapter_for(handler: Handler, limits: RegistryLimits | None = None) -> NpmAdapter:
    return NpmAdapter(httpx.AsyncClient(transport=httpx.MockTransport(handler)), limits)


async def fetch(handler: Handler, limits: RegistryLimits | None = None) -> PackageMetadata:
    return await adapter_for(handler, limits).fetch_metadata(NAME, VERSION)


async def metadata(**overrides: Any) -> PackageMetadata:
    return await fetch(json_handler(packument(**overrides)))


async def test_adapter_implements_interface() -> None:
    adapter = adapter_for(json_handler({}))

    assert isinstance(adapter, PackageAdapter)
    assert adapter.ecosystem is Ecosystem.NPM


async def test_collects_requested_metadata() -> None:
    result = await metadata(
        description="A demo",
        license="MIT",
        homepage="https://example.test",
        gitHead="abc123",
        repository={
            "type": "git",
            "url": "git+https://github.com/acme/demo.git",
            "directory": "packages/demo",
        },
        dependencies={"a": "^1.0.0"},
        devDependencies={"b": "^2.0.0"},
        peerDependencies={"c": "^3.0.0"},
        optionalDependencies={"d": "^4.0.0"},
        bundleDependencies=["a"],
        scripts={"postinstall": "node evil.js", "test": "jest"},
        main="index.js",
        module="index.mjs",
        browser={"./a.js": "./b.js"},
        exports={".": {"import": "./index.mjs"}},
        bin={"demo": "./cli.js"},
        types="index.d.ts",
        custom_field={"kept": True},
    )

    assert result.ecosystem is Ecosystem.NPM
    assert (result.name, result.version) == (NAME, VERSION)
    assert (result.description, result.license) == ("A demo", "MIT")
    assert result.homepage == "https://example.test"
    assert result.source_commit == "abc123"
    assert result.published_at == datetime(2026, 1, 2, 3, 4, 5, 678000, tzinfo=UTC)
    assert result.repository is not None
    assert result.repository.url == "https://github.com/acme/demo"
    assert result.repository.declared == "git+https://github.com/acme/demo.git"
    assert result.repository.directory == "packages/demo"
    assert {(d.name, d.specifier, d.kind) for d in result.dependencies} == {
        ("a", "^1.0.0", DependencyKind.RUNTIME),
        ("b", "^2.0.0", DependencyKind.DEVELOPMENT),
        ("c", "^3.0.0", DependencyKind.PEER),
        ("d", "^4.0.0", DependencyKind.OPTIONAL),
        ("a", None, DependencyKind.BUNDLED),
    }
    assert result.scripts == {"postinstall": "node evil.js", "test": "jest"}
    assert result.has_install_script is True
    assert result.entry_points == {
        "main": "index.js",
        "module": "index.mjs",
        "browser": {"./a.js": "./b.js"},
        "exports": {".": {"import": "./index.mjs"}},
        "bin": {"demo": "./cli.js"},
        "types": "index.d.ts",
    }
    assert result.manifest["custom_field"] == {"kept": True}

    only = result.artifacts[0]
    assert only.url == TARBALL_URL
    assert only.filename == f"{NAME}-{VERSION}.tgz"
    assert only.declared_integrity == sri(TARBALL)
    assert {h.algorithm: h.hex_digest for h in only.hashes} == {
        "sha512": hashlib.sha512(TARBALL).hexdigest(),
        "sha1": hashlib.sha1(TARBALL, usedforsecurity=False).hexdigest(),
    }


async def test_minimal_manifest_has_empty_optional_fields() -> None:
    result = await metadata()

    assert result.repository is None
    assert result.source_commit is None
    assert result.dependencies == ()
    assert result.scripts == {}
    assert result.entry_points == {}
    assert result.has_install_script is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"repository": 42},
        {"license": ["MIT"]},
        {"description": {"not": "text"}},
        {"homepage": 7},
        {"dependencies": "nope"},
        {"dependencies": {"a": 1}},
        {"scripts": ["x"]},
        {"scripts": {"test": 1}},
        {"bundleDependencies": True},
        {"bundledDependencies": [1, 2]},
    ],
)
async def test_malformed_publisher_fields_do_not_fail_retrieval(
    overrides: dict[str, Any],
) -> None:
    result = await metadata(**overrides)

    assert result.dependencies == ()
    assert result.scripts == {}
    assert result.repository is None


async def test_registry_install_flag_sets_has_install_script() -> None:
    assert (await metadata(hasInstallScript=True)).has_install_script is True


@pytest.mark.parametrize("value", [None, "not a time", "2026-01-02T03:04:05", 5])
async def test_unusable_publication_time_is_none(value: Any) -> None:
    document = packument()
    document["time"][VERSION] = value

    assert (await fetch(json_handler(document))).published_at is None


@pytest.mark.parametrize(
    ("declared", "expected"),
    [
        ("git+https://github.com/a/b.git", "https://github.com/a/b"),
        ("git+ssh://git@github.com/a/b.git", "https://github.com/a/b"),
        ("git://github.com/a/b.git", "https://github.com/a/b"),
        ("ssh://git@github.com/a/b.git", "https://github.com/a/b"),
        ("git@github.com:a/b.git", "https://github.com/a/b"),
        ("http://github.com/a/b/", "https://github.com/a/b"),
        ("https://user:pass@github.com/a/b.git#main", "https://github.com/a/b"),
        ("https://gitlab.example.org/group/sub/b", "https://gitlab.example.org/group/sub/b"),
        ("a/b", "https://github.com/a/b"),
        ("github:a/b", "https://github.com/a/b"),
        ("gitlab:a/b", "https://gitlab.com/a/b"),
        ("bitbucket:a/b", "https://bitbucket.org/a/b"),
        ("file:///etc/passwd", None),
        ("javascript:alert(1)", None),
        ("https://localhost/a/b", None),
        ("https://github.com", None),
        ("https://github.com/a/../../b", None),
        ("https://[bad/a", None),
        ("https://github.com/a b", None),
        ("", None),
        ("just words", None),
    ],
)
def test_normalize_repository_url(declared: str, expected: str | None) -> None:
    assert _normalize_repository_url(declared) == expected


async def test_scoped_name_is_one_encoded_path_segment() -> None:
    seen: list[httpx.URL] = []
    name = "@acme/demo"

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url)
        return httpx.Response(
            200,
            json={
                "versions": {
                    VERSION: {
                        "name": name,
                        "version": VERSION,
                        "dist": dist(
                            tarball=f"https://registry.npmjs.org/{name}/-/demo-{VERSION}.tgz"
                        ),
                    }
                }
            },
        )

    result = await adapter_for(handler).fetch_metadata(name, VERSION)

    assert seen[0].host == "registry.npmjs.org"
    assert seen[0].raw_path == b"/@acme%2Fdemo"
    assert result.artifacts[0].filename == f"acme-demo-{VERSION}.tgz"


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("../secret", VERSION),
        ("a/b", VERSION),
        ("", VERSION),
        ("a" * 215, VERSION),
        ("name\n", VERSION),
        ("a?x=1", VERSION),
        (NAME, "latest"),
        (NAME, "^1.0.0"),
        (NAME, "1.0"),
        (NAME, "1.0.0/../x"),
        (NAME, ""),
        (None, VERSION),
        (NAME, None),
    ],
)
async def test_invalid_input_never_reaches_the_network(name: Any, version: Any) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("request must not be sent")

    with pytest.raises(InvalidPackageRequestError):
        await adapter_for(handler).fetch_metadata(name, version)


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (404, PackageNotFoundError),
        (429, RegistryUnavailableError),
        (500, RegistryUnavailableError),
        (503, RegistryUnavailableError),
        (401, InvalidRegistryResponseError),
        (302, InvalidRegistryResponseError),
    ],
)
async def test_error_status_maps_to_adapter_error(status: int, error: type[Exception]) -> None:
    with pytest.raises(error):
        await fetch(lambda _: httpx.Response(status, headers={"Location": "https://evil.test/"}))


async def test_redirect_is_not_followed() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(302, headers={"Location": "https://evil.test/"})

    with pytest.raises(InvalidRegistryResponseError):
        await fetch(handler)
    assert calls == 1


async def test_missing_version_is_reported() -> None:
    with pytest.raises(VersionNotFoundError):
        await fetch(json_handler({"versions": {"9.9.9": manifest()}}))


async def test_unpublished_package_is_reported() -> None:
    with pytest.raises(VersionNotFoundError):
        await fetch(json_handler({"name": NAME, "time": {"unpublished": {"time": "2020"}}}))


@pytest.mark.parametrize(
    "document",
    [
        [],
        "text",
        {"versions": []},
        {"versions": {VERSION: "text"}},
        {"name": NAME},
        {"versions": {VERSION: manifest(name="other-pkg")}},
        {"versions": {VERSION: manifest(version="9.9.9")}},
        {"versions": {VERSION: manifest(dist=None)}},
        {"versions": {VERSION: manifest(dist={"integrity": sri(TARBALL)})}},
        {"versions": {VERSION: manifest(dist=dist(integrity="sha512-@@@@"))}},
        {"versions": {VERSION: manifest(dist=dist(integrity="sha512-AAAA"))}},
        {"versions": {VERSION: manifest(dist=dist(shasum="xyz"))}},
        {"versions": {VERSION: manifest(dist=dist(shasum=5))}},
    ],
)
async def test_malformed_document_is_rejected(document: Any) -> None:
    with pytest.raises(InvalidRegistryResponseError):
        await fetch(json_handler(document))


@pytest.mark.parametrize(
    "url",
    [
        f"http://registry.npmjs.org/{NAME}/-/x.tgz",
        f"https://evil.test/{NAME}/-/x.tgz",
        f"https://registry.npmjs.org.evil.test/{NAME}/-/x.tgz",
        f"https://user:pw@registry.npmjs.org/{NAME}/-/x.tgz",
        f"https://registry.npmjs.org:8443/{NAME}/-/x.tgz",
        f"https://registry.npmjs.org/{NAME}/-/x.tgz?redirect=evil",
        f"https://registry.npmjs.org/{NAME}/-/x.zip",
        "https://registry.npmjs.org/other-pkg/-/x.tgz",
        f"https://registry.npmjs.org/{NAME}/-/../../other/-/x.tgz",
        f"https://registry.npmjs.org/{NAME}/-/%2e%2e%2fx.tgz",
        "https://[bad/x.tgz",
        "file:///etc/passwd.tgz",
    ],
)
async def test_untrusted_tarball_location_is_rejected(url: str) -> None:
    with pytest.raises(InvalidRegistryResponseError):
        await metadata(dist=dist(tarball=url))


async def test_rejects_non_json_body() -> None:
    with pytest.raises(InvalidRegistryResponseError):
        await fetch(lambda _: httpx.Response(200, content=b"<html>"))


async def test_rejects_extremely_nested_json() -> None:
    nested = b"[" * 200_000 + b"]" * 200_000

    with pytest.raises(InvalidRegistryResponseError):
        await fetch(lambda _: httpx.Response(200, content=nested))


@pytest.mark.parametrize("depth", [500, 5_000, 50_000])
async def test_deep_manifest_never_escapes_as_an_unexpected_error(depth: int) -> None:
    body = (
        json.dumps(packument())
        .replace(
            '"name": "demo-pkg", "version"',
            '"exports": ' + '{"x":' * depth + "1" + "}" * depth + ', "name": "demo-pkg", "version"',
        )
        .encode()
    )

    try:
        result = await fetch(lambda _: httpx.Response(200, content=body))
    except InvalidRegistryResponseError:
        return
    assert "exports" in result.entry_points


async def test_reads_gzip_encoded_metadata() -> None:
    body = gzip.compress(json.dumps(packument()).encode())

    result = await fetch(
        lambda _: httpx.Response(200, content=body, headers={"Content-Encoding": "gzip"})
    )

    assert result.name == NAME


async def test_rejects_corrupt_gzip_metadata() -> None:
    with pytest.raises(InvalidRegistryResponseError):
        await fetch(
            lambda _: httpx.Response(200, content=b"junk", headers={"Content-Encoding": "gzip"})
        )


async def test_metadata_size_limit_applies_to_streamed_body() -> None:
    with pytest.raises(ResponseTooLargeError):
        await fetch(
            lambda _: httpx.Response(200, stream=httpx.ByteStream(b" " * 11)),
            RegistryLimits(max_metadata_bytes=10),
        )


async def test_metadata_size_limit_applies_to_declared_length() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=httpx.ByteStream(b"{}"), headers={"Content-Length": "99"})

    with pytest.raises(ResponseTooLargeError):
        await fetch(handler, RegistryLimits(max_metadata_bytes=10))


async def test_metadata_size_limit_applies_after_decompression() -> None:
    # The compressed body is under the limit, so only the decoded size can trigger it.
    body = gzip.compress(b" " * 1_000_000)
    limit = len(body) + 1

    with pytest.raises(ResponseTooLargeError):
        await fetch(
            lambda _: httpx.Response(
                200, stream=httpx.ByteStream(body), headers={"Content-Encoding": "gzip"}
            ),
            RegistryLimits(max_metadata_bytes=limit),
        )


@pytest.mark.parametrize(
    ("exception", "error"),
    [
        (httpx.ConnectTimeout("slow"), RegistryTimeoutError),
        (httpx.ReadTimeout("slow"), RegistryTimeoutError),
        (httpx.ConnectError("down"), RegistryUnavailableError),
    ],
)
async def test_transport_failure_maps_to_adapter_error(
    exception: Exception, error: type[Exception]
) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise exception

    with pytest.raises(error):
        await fetch(handler)


class StalledStream(httpx.AsyncByteStream):
    async def __aiter__(self) -> Any:
        yield b"x"
        await asyncio.sleep(30)


async def test_metadata_deadline_stops_a_stalled_response() -> None:
    with pytest.raises(RegistryTimeoutError):
        await fetch(
            lambda _: httpx.Response(200, stream=StalledStream()),
            RegistryLimits(metadata_deadline_seconds=0.01),
        )


def tarball_handler(body: bytes = TARBALL) -> Handler:
    # A stream, like a real download: no Content-Length is set and the body is unread.
    return lambda _: httpx.Response(200, stream=httpx.ByteStream(body))


async def test_download_verifies_and_stores_exact_bytes(tmp_path: Path) -> None:
    item = (await metadata()).artifacts[0]
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return tarball_handler()(request)

    result = await adapter_for(handler).download_artifact(item, tmp_path / "new" / "dir")

    assert result.path == tmp_path / "new" / "dir" / item.filename
    assert result.path.read_bytes() == TARBALL
    assert result.size_bytes == len(TARBALL)
    assert result.sha256 == hashlib.sha256(TARBALL).hexdigest()
    assert result.verified_algorithms == ("sha512", "sha1")
    assert requests[0].headers["Accept-Encoding"] == "identity"
    assert [path.name for path in result.path.parent.iterdir()] == [item.filename]


async def test_downloaded_file_is_private_and_not_executable(tmp_path: Path) -> None:
    item = (await metadata()).artifacts[0]

    result = await adapter_for(tarball_handler()).download_artifact(item, tmp_path)

    assert stat.S_IMODE(result.path.stat().st_mode) == 0o600


async def test_nothing_is_executed_or_unpacked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail on any attempt to start a process while a package with install scripts is handled."""

    def forbidden(*_: Any, **__: Any) -> None:
        raise AssertionError("a process was started")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(os, "posix_spawn", forbidden)
    monkeypatch.setattr(os, "fork", forbidden)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
    monkeypatch.setattr(asyncio, "create_subprocess_shell", forbidden)
    sentinel = tmp_path / "ran"
    scripts = {name: f"touch {sentinel}" for name in ("preinstall", "install", "postinstall")}

    result = await metadata(scripts=scripts)
    download = await adapter_for(tarball_handler()).download_artifact(
        result.artifacts[0], tmp_path / "out"
    )

    assert result.scripts == scripts
    assert not sentinel.exists()
    assert [path.name for path in tmp_path.iterdir()] == ["out"]
    assert [path.name for path in download.path.parent.iterdir()] == [download.path.name]


@pytest.mark.parametrize(
    "bad_dist",
    [
        {"integrity": sri(b"something else")},
        {"shasum": hashlib.sha1(b"something else", usedforsecurity=False).hexdigest()},
    ],
)
async def test_any_hash_mismatch_rejects_and_removes_the_file(
    tmp_path: Path, bad_dist: dict[str, str]
) -> None:
    item = (await metadata(dist=dist(**bad_dist))).artifacts[0]

    with pytest.raises(IntegrityVerificationError):
        await adapter_for(tarball_handler()).download_artifact(item, tmp_path)

    assert list(tmp_path.iterdir()) == []


async def test_failed_verification_keeps_an_existing_good_file(tmp_path: Path) -> None:
    good = (await metadata()).artifacts[0]
    await adapter_for(tarball_handler()).download_artifact(good, tmp_path)

    with pytest.raises(IntegrityVerificationError):
        await adapter_for(tarball_handler(b"tampered")).download_artifact(good, tmp_path)

    assert (tmp_path / good.filename).read_bytes() == TARBALL


async def test_legacy_shasum_only_is_reported_as_sha1(tmp_path: Path) -> None:
    legacy = dist()
    del legacy["integrity"]
    item = (await metadata(dist=legacy)).artifacts[0]

    result = await adapter_for(tarball_handler()).download_artifact(item, tmp_path)

    assert result.verified_algorithms == ("sha1",)


async def test_download_without_any_hash_fails_closed(tmp_path: Path) -> None:
    item = (await metadata(dist={"tarball": TARBALL_URL})).artifacts[0]

    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("request must not be sent")

    with pytest.raises(IntegrityVerificationError):
        await adapter_for(handler).download_artifact(item, tmp_path)


async def test_unsupported_integrity_algorithm_is_not_treated_as_verified(tmp_path: Path) -> None:
    item = (await metadata(dist={"tarball": TARBALL_URL, "integrity": "md5-AAAA"})).artifacts[0]

    with pytest.raises(IntegrityVerificationError):
        await adapter_for(tarball_handler()).download_artifact(item, tmp_path)


async def test_download_rechecks_host_of_caller_supplied_artifact(tmp_path: Path) -> None:
    item = (await metadata()).artifacts[0].model_copy(update={"url": "https://evil.test/x.tgz"})

    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("request must not be sent")

    with pytest.raises(InvalidRegistryResponseError):
        await adapter_for(handler).download_artifact(item, tmp_path)


@pytest.mark.parametrize(
    "handler",
    [
        tarball_handler(b"x" * 11),
        lambda _: httpx.Response(
            200, stream=httpx.ByteStream(b"x"), headers={"Content-Length": "99"}
        ),
    ],
    ids=["streamed-body", "declared-length"],
)
async def test_download_size_limit_removes_partial_file(tmp_path: Path, handler: Handler) -> None:
    item = (await metadata()).artifacts[0]
    adapter = adapter_for(handler, RegistryLimits(max_artifact_bytes=10))

    with pytest.raises(ResponseTooLargeError):
        await adapter.download_artifact(item, tmp_path)

    assert list(tmp_path.iterdir()) == []


async def test_download_deadline_removes_partial_file(tmp_path: Path) -> None:
    item = (await metadata()).artifacts[0]
    adapter = adapter_for(
        lambda _: httpx.Response(200, stream=StalledStream()),
        RegistryLimits(download_deadline_seconds=0.01),
    )

    with pytest.raises(RegistryTimeoutError):
        await adapter.download_artifact(item, tmp_path)

    assert list(tmp_path.iterdir()) == []


async def test_download_not_found_removes_partial_file(tmp_path: Path) -> None:
    item = (await metadata()).artifacts[0]

    with pytest.raises(RegistryNotFoundError):
        await adapter_for(lambda _: httpx.Response(404)).download_artifact(item, tmp_path)

    assert list(tmp_path.iterdir()) == []


async def test_unwritable_destination_is_a_storage_error(tmp_path: Path) -> None:
    item = (await metadata()).artifacts[0]
    blocker = tmp_path / "file"
    blocker.write_text("not a directory")

    with pytest.raises(ArtifactStorageError):
        await adapter_for(tarball_handler()).download_artifact(item, blocker / "child")


async def test_client_factory_applies_safe_defaults() -> None:
    limits = RegistryLimits(connect_timeout_seconds=1, read_timeout_seconds=2)

    async with create_registry_client(limits) as client:
        assert client.timeout.connect == 1
        assert client.timeout.read == 2
        assert client.follow_redirects is False
        assert client.trust_env is False


def test_settings_build_registry_limits() -> None:
    limits = Settings(
        registry_read_timeout_seconds=7, registry_max_artifact_bytes=9
    ).registry_limits()

    assert limits.read_timeout_seconds == 7
    assert limits.max_artifact_bytes == 9
