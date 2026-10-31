"""Extraction of real archives from npm and GitHub. Run with: pytest -m live"""

import hashlib
import stat
from pathlib import Path

import pytest

from app.adapters.http import RegistryLimits, create_registry_client
from app.adapters.npm import NpmAdapter
from app.archives.extract import extract_archive
from app.archives.models import EntryKind
from app.source.github import GitHubSourceResolver
from app.source.models import MatchStatus

pytestmark = [pytest.mark.live, pytest.mark.anyio]


async def test_real_npm_and_github_archives(tmp_path: Path) -> None:
    limits = RegistryLimits()
    async with create_registry_client(limits) as client:
        adapter = NpmAdapter(client, limits)
        metadata = await adapter.fetch_metadata("left-pad", "1.3.0")
        tarball = await adapter.download_artifact(metadata.artifacts[0], tmp_path / "dl")
        resolver = GitHubSourceResolver(client, limits)
        match = await resolver.resolve(metadata)
        assert match.status is MatchStatus.MATCHED
        source = await resolver.download_source(match, tmp_path / "dl")

    package = extract_archive(tarball.path, tmp_path / "package")
    repository = extract_archive(source.path, tmp_path / "source")

    assert package.archive_root == "package"
    assert package.archive_sha256 == tarball.sha256
    assert "index.js" in {entry.path for entry in package.entries}
    assert match.commit_sha is not None and match.commit_sha in (repository.archive_root or "")
    assert "index.js" in {entry.path for entry in repository.entries}

    for inventory in (package, repository):
        for entry in inventory.entries:
            if entry.kind is EntryKind.REGULAR:
                written = inventory.root / entry.path
                assert stat.S_IMODE(written.stat().st_mode) == 0o600
                assert hashlib.sha256(written.read_bytes()).hexdigest() == entry.sha256
