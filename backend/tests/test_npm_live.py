"""Checks against the real npm registry. Run with: pytest -m live"""

import stat
from pathlib import Path

import pytest

from app.adapters.errors import PackageNotFoundError, VersionNotFoundError
from app.adapters.http import RegistryLimits, create_registry_client
from app.adapters.npm import NpmAdapter

pytestmark = [pytest.mark.live, pytest.mark.anyio]


@pytest.mark.parametrize(
    ("name", "version"),
    [("left-pad", "1.3.0"), ("@babel/core", "7.26.0"), ("JSONStream", "1.3.5")],
)
async def test_retrieves_and_verifies_real_package(name: str, version: str, tmp_path: Path) -> None:
    limits = RegistryLimits()
    async with create_registry_client(limits) as client:
        adapter = NpmAdapter(client, limits)
        metadata = await adapter.fetch_metadata(name, version)
        result = await adapter.download_artifact(metadata.artifacts[0], tmp_path)

    assert metadata.published_at is not None
    assert metadata.repository is not None
    assert metadata.repository.url is not None
    assert metadata.repository.url.startswith("https://github.com/")
    assert "sha1" in result.verified_algorithms
    assert result.size_bytes > 0
    assert stat.S_IMODE(result.path.stat().st_mode) == 0o600


async def test_real_missing_package_and_version() -> None:
    async with create_registry_client(RegistryLimits()) as client:
        adapter = NpmAdapter(client)
        with pytest.raises(PackageNotFoundError):
            await adapter.fetch_metadata("veritor-package-that-does-not-exist", "1.0.0")
        with pytest.raises(VersionNotFoundError):
            await adapter.fetch_metadata("left-pad", "99.0.0")
