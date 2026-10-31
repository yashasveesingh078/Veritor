"""Match a published package version to an exact commit in its GitHub repository.

A match must come from evidence about that version. If there is none, the result is
UNCERTAIN: a default branch is never used as a substitute for a release.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx
from pydantic import SecretStr, ValidationError

from app.adapters.base import PackageMetadata
from app.adapters.errors import (
    AdapterError,
    InvalidRegistryResponseError,
    RegistryNotFoundError,
)
from app.adapters.http import RegistryLimits, download_unhashed, fetch_bytes, fetch_json
from app.source.models import (
    Confidence,
    GitHubRepository,
    MatchMethod,
    MatchStatus,
    SourceArchive,
    SourceMatch,
    UncertainReason,
)

GITHUB_HOSTS = {"github.com", "www.github.com"}
ARCHIVE_HOST = "https://codeload.github.com"
API_HOST = "https://api.github.com"

_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
_SERVICE_HEADER = b"# service=git-upload-pack\n"
_DEFAULT_BRANCH = re.compile(rb"(?:^| )symref=HEAD:refs/heads/(\S+)")
_PEELED_SUFFIX = "^{}"
# GitHub answers 401 rather than 404 for a repository that does not exist.
_REFS_NOT_FOUND_STATUSES = frozenset({401, 404})
_REACHABLE_COMPARE_STATUSES = {"identical", "behind"}


class SourceNotMatchedError(AdapterError):
    """Source was requested for a result that did not establish an exact commit."""


class TagKind(IntEnum):
    """Candidate tag formats, most specific first."""

    PACKAGE = 0
    VERSION = 1
    RELEASE_PREFIX = 2


_TAG_METHODS = {
    TagKind.PACKAGE: MatchMethod.PACKAGE_TAG,
    TagKind.VERSION: MatchMethod.VERSION_TAG,
    TagKind.RELEASE_PREFIX: MatchMethod.RELEASE_PREFIX_TAG,
}


@dataclass(frozen=True)
class RepositoryRefs:
    tags: dict[str, str]
    branch_tips: frozenset[str]
    default_branch: str | None


def parse_github_repository(url: str) -> GitHubRepository | None:
    """Return the owner and repository from an https GitHub URL, ignoring any longer path."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme != "https" or parts.hostname not in GITHUB_HOSTS:
        return None
    segments = [segment for segment in parts.path.split("/") if segment]
    if len(segments) < 2:
        return None
    try:
        return GitHubRepository(owner=segments[0], name=segments[1].removesuffix(".git"))
    except ValidationError:
        return None


def candidate_tags(name: str, version: str, directory: str | None = None) -> dict[str, TagKind]:
    """Return the tag names to look for, in order of preference."""
    short = name.rpartition("/")[2]
    package_tags = [
        f"{name}@{version}",
        f"{name}@v{version}",
        f"{name}/v{version}",
        f"{name}/{version}",
        f"{name}-v{version}",
        f"{name}-{version}",
        f"{short}@{version}",
        f"{short}@v{version}",
        f"{short}/v{version}",
        f"{short}/{version}",
        f"{short}-v{version}",
        f"{short}-{version}",
        f"{short}_v{version}",
        f"{short}_{version}",
    ]
    if directory:
        path = directory.strip("/").removeprefix("./")
        package_tags += [f"{path}/v{version}", f"{path}/{version}"]

    candidates = dict.fromkeys(package_tags, TagKind.PACKAGE)
    for tag in (f"v{version}", version, f"V{version}"):
        candidates.setdefault(tag, TagKind.VERSION)
    for prefix in ("release", "version"):
        for separator in ("-", "/"):
            for tag in (f"{prefix}{separator}{version}", f"{prefix}{separator}v{version}"):
                candidates.setdefault(tag, TagKind.RELEASE_PREFIX)
    return candidates


def parse_refs_advertisement(body: bytes) -> RepositoryRefs:
    """Parse git's smart HTTP reference list. See git's http-protocol documentation."""
    tags: dict[str, str] = {}
    branch_tips: set[str] = set()
    default_branch: str | None = None
    packets = _iter_packets(body)
    if next(packets, None) != _SERVICE_HEADER:
        raise InvalidRegistryResponseError("Not a git reference advertisement")

    for packet in packets:
        line, _, capabilities = packet.rstrip(b"\n").partition(b"\0")
        if capabilities and (symref := _DEFAULT_BRANCH.search(capabilities)):
            default_branch = symref.group(1).decode(errors="replace")
        sha_bytes, _, ref_bytes = line.partition(b" ")
        sha = sha_bytes.decode(errors="replace")
        ref = ref_bytes.decode(errors="replace")
        if not _COMMIT_SHA.fullmatch(sha) or not ref:
            raise InvalidRegistryResponseError("Malformed git reference")

        if ref.startswith("refs/heads/"):
            branch_tips.add(sha)
        elif ref.startswith("refs/tags/"):
            # A peeled entry follows its annotated tag and names the commit it points to.
            tags[ref.removeprefix("refs/tags/").removesuffix(_PEELED_SUFFIX)] = sha
    return RepositoryRefs(tags, frozenset(branch_tips), default_branch)


def _iter_packets(body: bytes) -> Iterator[bytes]:
    """Yield git pkt-line payloads, skipping flush packets."""
    position = 0
    while position < len(body):
        try:
            length = int(body[position : position + 4], 16)
        except ValueError as exc:
            raise InvalidRegistryResponseError("Malformed git packet") from exc
        if length == 0:
            position += 4
            continue
        end = position + length
        if length < 4 or end > len(body):
            raise InvalidRegistryResponseError("Malformed git packet")
        yield body[position + 4 : end]
        position = end


class GitHubSourceResolver:
    def __init__(
        self,
        client: httpx.AsyncClient,
        limits: RegistryLimits | None = None,
        token: SecretStr | None = None,
    ) -> None:
        self._client = client
        self._limits = limits or RegistryLimits()
        self._token = token

    async def resolve(self, metadata: PackageMetadata) -> SourceMatch:
        """Find the commit for a package version. Lookup failures are returned as UNCERTAIN."""
        declared = metadata.repository
        if declared is None:
            return _uncertain(
                UncertainReason.NO_REPOSITORY, "The package does not declare a repository."
            )
        directory = declared.directory
        repository = parse_github_repository(declared.url) if declared.url else None
        if repository is None:
            return _uncertain(
                UncertainReason.UNSUPPORTED_HOST,
                "The declared repository is not a recognized GitHub repository.",
                directory=directory,
            )

        candidates = candidate_tags(metadata.name, metadata.version, directory)
        recorded = (metadata.source_commit or "").lower()
        recorded_commit = recorded if _COMMIT_SHA.fullmatch(recorded) else None
        shared: dict[str, object] = {
            "repository": repository,
            "directory": directory,
            "recorded_commit": recorded_commit,
            "tags_checked": tuple(candidates),
        }

        try:
            refs = await self._fetch_refs(repository)
        except RegistryNotFoundError:
            return _uncertain(
                UncertainReason.REPOSITORY_NOT_FOUND,
                "The declared repository does not exist or is private.",
                **shared,
            )
        except AdapterError as exc:
            return _uncertain(
                UncertainReason.LOOKUP_FAILED, f"Could not read repository tags: {exc}", **shared
            )

        found = {tag: refs.tags[tag] for tag in candidates if tag in refs.tags}
        shared["tags_found"] = found

        if recorded_commit is not None:
            return await self._match_recorded_commit(
                repository, recorded_commit, refs, found, shared
            )
        return _match_tags_only(found, candidates, directory, shared)

    async def download_source(self, match: SourceMatch, destination_dir: Path) -> SourceArchive:
        """Download the archive for the exact matched commit.

        The URL is built only from the validated repository and full commit SHA, so a
        branch or tag name can never select the code. The file is not unpacked.
        """
        if (
            match.status is not MatchStatus.MATCHED
            or match.repository is None
            or match.commit_sha is None
        ):
            raise SourceNotMatchedError(f"No source commit was established: {match.explanation}")

        repository, commit = match.repository, match.commit_sha
        download = await download_unhashed(
            self._client,
            f"{ARCHIVE_HOST}/{repository.owner}/{repository.name}/tar.gz/{commit}",
            f"{repository.owner}-{repository.name}-{commit}.tar.gz",
            destination_dir,
            self._limits,
        )
        return SourceArchive(
            repository=repository,
            commit_sha=commit,
            path=download.path,
            size_bytes=download.size_bytes,
            sha256=download.sha256,
        )

    async def _fetch_refs(self, repository: GitHubRepository) -> RepositoryRefs:
        # The git endpoint returns every tag in one request, and does not use the API's
        # hourly quota, which allows only 60 requests without a token.
        body = await fetch_bytes(
            self._client,
            f"{repository.url}.git/info/refs?service=git-upload-pack",
            self._limits,
            {},
            _REFS_NOT_FOUND_STATUSES,
        )
        return parse_refs_advertisement(body)

    async def _match_recorded_commit(
        self,
        repository: GitHubRepository,
        recorded_commit: str,
        refs: RepositoryRefs,
        found: dict[str, str],
        shared: dict[str, object],
    ) -> SourceMatch:
        agreeing_tag = next((tag for tag, sha in found.items() if sha == recorded_commit), None)
        if agreeing_tag is not None:
            return _matched(
                MatchMethod.RECORDED_COMMIT_AND_TAG,
                Confidence.HIGH,
                f"The commit recorded by the package is the commit of tag {agreeing_tag}.",
                commit_sha=recorded_commit,
                tag=agreeing_tag,
                **shared,
            )

        if found:
            return _uncertain(
                UncertainReason.RECORDED_COMMIT_CONFLICTS_WITH_TAG,
                "The package recorded a different commit from the matching release tag.",
                **shared,
            )

        try:
            reachable = await self._is_reachable(repository, recorded_commit, refs)
        except AdapterError as exc:
            return _uncertain(
                UncertainReason.LOOKUP_FAILED, f"Could not check the commit: {exc}", **shared
            )
        if not reachable:
            return _uncertain(
                UncertainReason.RECORDED_COMMIT_UNVERIFIED,
                "No release tag exists, and the recorded commit is not on the default branch "
                "or at the tip of any branch.",
                **shared,
            )
        return _matched(
            MatchMethod.RECORDED_COMMIT,
            Confidence.MEDIUM,
            "No release tag exists. The commit recorded by the package is part of the "
            "repository's history.",
            commit_sha=recorded_commit,
            **shared,
        )

    async def _is_reachable(
        self, repository: GitHubRepository, commit: str, refs: RepositoryRefs
    ) -> bool:
        """Check that a commit belongs to this repository.

        GitHub also serves commits that exist only in a fork through the parent's URLs, so
        a successful commit lookup alone would let a fork's code pass as the project's.
        """
        if commit in refs.branch_tips:
            return True
        if refs.default_branch is None:
            return False

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        # The token is added only here, so it cannot reach any other host.
        if self._token is not None and self._token.get_secret_value():
            headers["Authorization"] = f"Bearer {self._token.get_secret_value()}"
        branch = quote(refs.default_branch, safe="")
        url = (
            f"{API_HOST}/repos/{repository.owner}/{repository.name}"
            f"/compare/{branch}...{commit}?per_page=1"
        )
        try:
            comparison = await fetch_json(self._client, url, self._limits, headers)
        except (RegistryNotFoundError, InvalidRegistryResponseError):
            return False
        # "behind" means the default branch already contains the commit.
        return comparison.get("status") in _REACHABLE_COMPARE_STATUSES


def _match_tags_only(
    found: dict[str, str],
    candidates: dict[str, TagKind],
    directory: str | None,
    shared: dict[str, object],
) -> SourceMatch:
    if not found:
        return _uncertain(
            UncertainReason.NO_MATCHING_TAG,
            "The package recorded no commit, and no tag matches this version.",
            **shared,
        )
    if len(set(found.values())) > 1:
        return _uncertain(
            UncertainReason.AMBIGUOUS_TAGS,
            "Tags matching this version point to different commits.",
            **shared,
        )

    # `found` follows the candidate order, so the first tag is the most specific.
    tag = next(iter(found))
    kind = candidates[tag]
    confidence = Confidence.MEDIUM
    explanation = f"Tag {tag} matches this version. The package recorded no commit to confirm it."
    if kind is TagKind.RELEASE_PREFIX:
        confidence = Confidence.LOW
    elif kind is TagKind.VERSION and directory:
        confidence = Confidence.LOW
        explanation += " The tag is not specific to this package within a monorepo."
    return _matched(
        _TAG_METHODS[kind],
        confidence,
        explanation,
        commit_sha=found[tag],
        tag=tag,
        **shared,
    )


def _matched(
    method: MatchMethod, confidence: Confidence, explanation: str, **fields: object
) -> SourceMatch:
    return SourceMatch.model_validate(
        {
            "status": MatchStatus.MATCHED,
            "method": method,
            "confidence": confidence,
            "explanation": explanation,
            **fields,
        }
    )


def _uncertain(reason: UncertainReason, explanation: str, **fields: object) -> SourceMatch:
    return SourceMatch.model_validate(
        {
            "status": MatchStatus.UNCERTAIN,
            "reason": reason,
            "explanation": explanation,
            **fields,
        }
    )
