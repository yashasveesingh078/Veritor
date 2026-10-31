"""Checks against the real npm registry and GitHub. Run with: pytest -m live"""

from pathlib import Path

import pytest

from app.adapters.base import PackageMetadata
from app.adapters.http import RegistryLimits, create_registry_client
from app.adapters.npm import NpmAdapter
from app.source.github import GitHubSourceResolver
from app.source.models import Confidence, MatchMethod, MatchStatus, SourceMatch, UncertainReason

pytestmark = [pytest.mark.live, pytest.mark.anyio]


async def resolve_real(name: str, version: str) -> tuple[PackageMetadata, SourceMatch]:
    limits = RegistryLimits()
    async with create_registry_client(limits) as client:
        metadata = await NpmAdapter(client, limits).fetch_metadata(name, version)
        return metadata, await GitHubSourceResolver(client, limits).resolve(metadata)


async def test_recorded_commit_agreeing_with_tag(tmp_path: Path) -> None:
    limits = RegistryLimits()
    metadata, match = await resolve_real("left-pad", "1.3.0")

    assert match.status is MatchStatus.MATCHED
    assert match.method is MatchMethod.RECORDED_COMMIT_AND_TAG
    assert match.confidence is Confidence.HIGH
    assert match.commit_sha == metadata.source_commit

    async with create_registry_client(limits) as client:
        archive = await GitHubSourceResolver(client, limits).download_source(match, tmp_path)
    assert archive.size_bytes > 0
    assert archive.path.read_bytes()[:2] == b"\x1f\x8b"


async def test_scoped_monorepo_package_tag() -> None:
    _, match = await resolve_real("@babel/core", "7.26.0")

    assert match.status is MatchStatus.MATCHED
    assert match.tag == "v7.26.0"
    assert match.repository is not None
    assert match.repository.url == "https://github.com/babel/babel"


async def test_real_conflict_is_uncertain() -> None:
    _, match = await resolve_real("lodash", "4.18.1")

    assert match.status is MatchStatus.UNCERTAIN
    assert match.reason is UncertainReason.RECORDED_COMMIT_CONFLICTS_WITH_TAG
    assert match.commit_sha is None


async def test_monorepo_without_package_tags_is_uncertain() -> None:
    _, match = await resolve_real("@types/node", "26.6.6")

    assert match.status is MatchStatus.UNCERTAIN
    assert match.commit_sha is None
