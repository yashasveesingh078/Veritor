import hashlib
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from app.adapters.base import PackageMetadata, SourceRepository
from app.adapters.errors import (
    InvalidRegistryResponseError,
    RegistryNotFoundError,
    RegistryTimeoutError,
    RegistryUnavailableError,
    ResponseTooLargeError,
)
from app.adapters.http import RegistryLimits
from app.config import Settings
from app.schemas.scans import Ecosystem
from app.source.github import (
    GitHubSourceResolver,
    SourceNotMatchedError,
    TagKind,
    candidate_tags,
    parse_github_repository,
    parse_refs_advertisement,
)
from app.source.models import (
    Confidence,
    GitHubRepository,
    MatchMethod,
    MatchStatus,
    SourceMatch,
    UncertainReason,
)

pytestmark = pytest.mark.anyio

COMMIT_A = "a" * 40
COMMIT_B = "b" * 40
COMMIT_C = "c" * 40
ANNOTATED = "d" * 40
TIP = "e" * 40
VERSION = "1.2.3"
REPO_URL = "https://github.com/acme/demo"
REFS_PATH = "/acme/demo.git/info/refs"
Handler = Callable[[httpx.Request], httpx.Response]


def packet(text: bytes) -> bytes:
    return f"{len(text) + 4:04x}".encode() + text


def advertisement(
    tags: dict[str, str] | None = None,
    branches: dict[str, str] | None = None,
    default_branch: str | None = "main",
) -> bytes:
    symref = f" symref=HEAD:refs/heads/{default_branch}" if default_branch else ""
    capabilities = f"multi_ack{symref} agent=git/github".encode()
    lines = [packet(f"{TIP} HEAD".encode() + b"\0" + capabilities + b"\n")]
    for branch, sha in (branches if branches is not None else {"main": TIP}).items():
        lines.append(packet(f"{sha} refs/heads/{branch}\n".encode()))
    for tag, sha in (tags or {}).items():
        lines.append(packet(f"{sha} refs/tags/{tag}\n".encode()))
    return packet(b"# service=git-upload-pack\n") + b"0000" + b"".join(lines) + b"0000"


def make_metadata(
    name: str = "demo",
    version: str = VERSION,
    url: str | None = REPO_URL,
    source_commit: str | None = None,
    directory: str | None = None,
    no_repository: bool = False,
) -> PackageMetadata:
    repository = (
        None
        if no_repository
        else SourceRepository(declared=url or "unparseable", url=url, directory=directory)
    )
    return PackageMetadata(
        ecosystem=Ecosystem.NPM,
        name=name,
        version=version,
        description=None,
        license=None,
        homepage=None,
        repository=repository,
        source_commit=source_commit,
        published_at=None,
        dependencies=(),
        scripts={},
        has_install_script=False,
        entry_points={},
        artifacts=(),
        manifest={},
    )


def refs_handler(body: bytes, requests: list[httpx.Request] | None = None) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        if requests is not None:
            requests.append(request)
        assert request.url.host == "github.com"
        assert request.url.path == REFS_PATH
        return httpx.Response(200, content=body)

    return handler


def resolver_for(
    handler: Handler, token: SecretStr | None = None, limits: RegistryLimits | None = None
) -> GitHubSourceResolver:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return GitHubSourceResolver(client, limits, token)


async def resolve(tags: dict[str, str], **metadata_fields: Any) -> SourceMatch:
    handler = refs_handler(advertisement(tags))
    return await resolver_for(handler).resolve(make_metadata(**metadata_fields))


def api_handler(compare: httpx.Response, seen: list[httpx.Request] | None = None) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if request.url.host == "github.com":
            return httpx.Response(200, content=advertisement())
        assert request.url.host == "api.github.com"
        return compare

    return handler


def assert_uncertain(match: SourceMatch, reason: UncertainReason) -> None:
    assert match.status is MatchStatus.UNCERTAIN
    assert match.reason is reason
    assert match.confidence is Confidence.NONE
    assert match.method is MatchMethod.NONE
    assert match.commit_sha is None
    assert match.tag is None
    assert match.explanation


# Repository metadata


@pytest.mark.parametrize(
    ("url", "owner", "name"),
    [
        ("https://github.com/acme/demo", "acme", "demo"),
        ("https://www.github.com/acme/demo", "acme", "demo"),
        ("https://github.com/acme/demo.git", "acme", "demo"),
        ("https://github.com/acme/next.js", "acme", "next.js"),
        ("https://github.com/acme/demo/tree/main/packages/x", "acme", "demo"),
    ],
)
def test_parses_github_repository(url: str, owner: str, name: str) -> None:
    assert parse_github_repository(url) == GitHubRepository(owner=owner, name=name)


@pytest.mark.parametrize(
    "url",
    [
        "https://gitlab.com/acme/demo",
        "https://github.com.evil.test/acme/demo",
        "https://evil.test/github.com/acme/demo",
        "http://github.com/acme/demo",
        "https://github.com/acme",
        "https://github.com/",
        "https://github.com/../demo",
        "https://github.com/acme/..",
        "https://github.com/acme/.git",
        "https://github.com/ac me/demo",
        "https://github.com/acme/de%2fmo",
        "https://[bad/a/b",
    ],
)
def test_rejects_other_repository_urls(url: str) -> None:
    assert parse_github_repository(url) is None


async def test_no_repository_is_uncertain_without_any_request() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("no request expected")

    match = await resolver_for(handler).resolve(make_metadata(no_repository=True))

    assert_uncertain(match, UncertainReason.NO_REPOSITORY)


@pytest.mark.parametrize("url", ["https://gitlab.com/acme/demo", None])
async def test_unsupported_repository_is_uncertain_without_any_request(url: str | None) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("no request expected")

    match = await resolver_for(handler).resolve(make_metadata(url=url))

    assert_uncertain(match, UncertainReason.UNSUPPORTED_HOST)


# Tag formats


@pytest.mark.parametrize(
    ("tag", "method"),
    [
        (f"v{VERSION}", MatchMethod.VERSION_TAG),
        (VERSION, MatchMethod.VERSION_TAG),
        (f"V{VERSION}", MatchMethod.VERSION_TAG),
        (f"@acme/demo@{VERSION}", MatchMethod.PACKAGE_TAG),
        (f"@acme/demo@v{VERSION}", MatchMethod.PACKAGE_TAG),
        (f"demo@{VERSION}", MatchMethod.PACKAGE_TAG),
        (f"demo@v{VERSION}", MatchMethod.PACKAGE_TAG),
        (f"demo-{VERSION}", MatchMethod.PACKAGE_TAG),
        (f"demo-v{VERSION}", MatchMethod.PACKAGE_TAG),
        (f"demo/{VERSION}", MatchMethod.PACKAGE_TAG),
        (f"demo/v{VERSION}", MatchMethod.PACKAGE_TAG),
        (f"demo_{VERSION}", MatchMethod.PACKAGE_TAG),
        (f"release-{VERSION}", MatchMethod.RELEASE_PREFIX_TAG),
        (f"release/v{VERSION}", MatchMethod.RELEASE_PREFIX_TAG),
        (f"version-{VERSION}", MatchMethod.RELEASE_PREFIX_TAG),
    ],
)
async def test_common_tag_formats_are_matched(tag: str, method: MatchMethod) -> None:
    match = await resolve({tag: COMMIT_A}, name="@acme/demo")

    assert match.status is MatchStatus.MATCHED
    assert match.commit_sha == COMMIT_A
    assert match.tag == tag
    assert match.method is method


async def test_prerelease_version_tag_is_matched() -> None:
    match = await resolve({"v1.2.3-rc.1": COMMIT_A}, version="1.2.3-rc.1")

    assert match.tag == "v1.2.3-rc.1"


async def test_directory_tag_is_matched() -> None:
    match = await resolve({f"packages/demo/v{VERSION}": COMMIT_A}, directory="packages/demo")

    assert match.method is MatchMethod.PACKAGE_TAG


@pytest.mark.parametrize(
    "tag",
    [
        "v1.2.30",
        "v1.2",
        "1.2.3.1",
        f"other@{VERSION}",
        f"xdemo-{VERSION}",
        f"v{VERSION}-rc.1",
        f"demo-{VERSION}-beta",
        "main",
        "latest",
    ],
)
async def test_tag_for_something_else_never_matches(tag: str) -> None:
    match = await resolve({tag: COMMIT_A})

    assert_uncertain(match, UncertainReason.NO_MATCHING_TAG)


def test_candidates_are_unique_and_prefer_package_tags() -> None:
    candidates = candidate_tags("demo", VERSION)
    kinds = list(candidates.values())

    assert kinds == sorted(kinds)
    assert candidates[f"demo@{VERSION}"] is TagKind.PACKAGE
    assert candidates[f"v{VERSION}"] is TagKind.VERSION


# Matching method and confidence


async def test_recorded_commit_agreeing_with_tag_is_high_confidence() -> None:
    match = await resolve({f"v{VERSION}": COMMIT_A}, source_commit=COMMIT_A)

    assert match.status is MatchStatus.MATCHED
    assert match.method is MatchMethod.RECORDED_COMMIT_AND_TAG
    assert match.confidence is Confidence.HIGH
    assert match.commit_sha == COMMIT_A
    assert match.tag == f"v{VERSION}"
    assert match.recorded_commit == COMMIT_A
    assert match.tags_found == {f"v{VERSION}": COMMIT_A}
    assert f"v{VERSION}" in match.tags_checked
    assert match.repository == GitHubRepository(owner="acme", name="demo")


async def test_uppercase_recorded_commit_is_normalized() -> None:
    match = await resolve({f"v{VERSION}": COMMIT_A}, source_commit=COMMIT_A.upper())

    assert match.confidence is Confidence.HIGH


async def test_annotated_tag_resolves_to_its_commit() -> None:
    body = advertisement({f"v{VERSION}": ANNOTATED, f"v{VERSION}^{{}}": COMMIT_A})

    match = await resolver_for(refs_handler(body)).resolve(make_metadata(source_commit=COMMIT_A))

    assert match.commit_sha == COMMIT_A
    assert match.confidence is Confidence.HIGH


@pytest.mark.parametrize(
    ("tag", "fields", "method", "confidence"),
    [
        (f"demo@{VERSION}", {}, MatchMethod.PACKAGE_TAG, Confidence.MEDIUM),
        (f"v{VERSION}", {}, MatchMethod.VERSION_TAG, Confidence.MEDIUM),
        (
            f"v{VERSION}",
            {"directory": "packages/demo"},
            MatchMethod.VERSION_TAG,
            Confidence.LOW,
        ),
        (
            f"demo@{VERSION}",
            {"directory": "packages/demo"},
            MatchMethod.PACKAGE_TAG,
            Confidence.MEDIUM,
        ),
        (f"release-{VERSION}", {}, MatchMethod.RELEASE_PREFIX_TAG, Confidence.LOW),
    ],
)
async def test_tag_only_confidence(
    tag: str, fields: dict[str, str], method: MatchMethod, confidence: Confidence
) -> None:
    match = await resolve({tag: COMMIT_A}, **fields)

    assert (match.method, match.confidence) == (method, confidence)
    assert match.recorded_commit is None


async def test_several_tags_on_one_commit_prefer_the_most_specific() -> None:
    match = await resolve({f"v{VERSION}": COMMIT_A, f"demo@{VERSION}": COMMIT_A})

    assert match.tag == f"demo@{VERSION}"
    assert match.status is MatchStatus.MATCHED


@pytest.mark.parametrize("value", ["abc123", "not hex", "a" * 39, "g" * 40])
async def test_invalid_recorded_commit_is_treated_as_absent(value: str) -> None:
    match = await resolve({f"v{VERSION}": COMMIT_A}, source_commit=value)

    assert match.method is MatchMethod.VERSION_TAG
    assert match.confidence is Confidence.MEDIUM
    assert match.recorded_commit is None


# Never fall back: every failure below is UNCERTAIN, with no commit.


async def test_conflicting_recorded_commit_and_tag_is_uncertain() -> None:
    match = await resolve({f"v{VERSION}": COMMIT_A}, source_commit=COMMIT_B)

    assert_uncertain(match, UncertainReason.RECORDED_COMMIT_CONFLICTS_WITH_TAG)
    assert match.recorded_commit == COMMIT_B
    assert match.tags_found == {f"v{VERSION}": COMMIT_A}


async def test_tags_pointing_to_different_commits_are_uncertain() -> None:
    match = await resolve({f"v{VERSION}": COMMIT_A, f"demo@{VERSION}": COMMIT_B})

    assert_uncertain(match, UncertainReason.AMBIGUOUS_TAGS)
    assert match.tags_found == {f"demo@{VERSION}": COMMIT_B, f"v{VERSION}": COMMIT_A}


async def test_no_tag_and_no_commit_never_uses_the_default_branch() -> None:
    requests: list[httpx.Request] = []
    body = advertisement(
        {"v9.9.9": COMMIT_A}, branches={"main": TIP, "master": COMMIT_B, "develop": COMMIT_C}
    )

    match = await resolver_for(refs_handler(body, requests)).resolve(make_metadata())

    assert_uncertain(match, UncertainReason.NO_MATCHING_TAG)
    assert len(requests) == 1


@pytest.mark.parametrize("branch", ["main", "master"])
async def test_branch_named_like_a_version_is_not_a_tag(branch: str) -> None:
    body = advertisement(branches={branch: TIP, VERSION: COMMIT_A, f"v{VERSION}": COMMIT_A})

    match = await resolver_for(refs_handler(body)).resolve(make_metadata())

    assert_uncertain(match, UncertainReason.NO_MATCHING_TAG)


@pytest.mark.parametrize("status", [401, 404])
async def test_missing_repository_is_uncertain(status: int) -> None:
    match = await resolver_for(lambda _: httpx.Response(status)).resolve(make_metadata())

    assert_uncertain(match, UncertainReason.REPOSITORY_NOT_FOUND)


@pytest.mark.parametrize(
    "handler",
    [
        lambda _: httpx.Response(500),
        lambda _: httpx.Response(429),
        lambda _: httpx.Response(403),
        lambda _: httpx.Response(302, headers={"Location": "https://evil.test/"}),
        lambda _: httpx.Response(200, content=b"<html>not git</html>"),
        lambda _: httpx.Response(200, content=b""),
    ],
)
async def test_unreadable_refs_are_uncertain(handler: Handler) -> None:
    match = await resolver_for(handler).resolve(make_metadata())

    assert_uncertain(match, UncertainReason.LOOKUP_FAILED)


@pytest.mark.parametrize("error", [httpx.ConnectError("down"), httpx.ReadTimeout("slow")])
async def test_network_failure_is_uncertain(error: Exception) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise error

    match = await resolver_for(handler).resolve(make_metadata())

    assert_uncertain(match, UncertainReason.LOOKUP_FAILED)


async def test_oversized_refs_are_uncertain() -> None:
    match = await resolver_for(
        lambda _: httpx.Response(200, stream=httpx.ByteStream(b"x" * 11)),
        limits=RegistryLimits(max_metadata_bytes=10),
    ).resolve(make_metadata())

    assert_uncertain(match, UncertainReason.LOOKUP_FAILED)


def test_uncertain_result_cannot_carry_a_commit() -> None:
    with pytest.raises(ValidationError):
        SourceMatch(
            status=MatchStatus.UNCERTAIN,
            reason=UncertainReason.NO_MATCHING_TAG,
            explanation="x",
            commit_sha=COMMIT_A,
        )


def test_matched_result_needs_an_exact_commit() -> None:
    repository = GitHubRepository(owner="acme", name="demo")
    base = {
        "status": MatchStatus.MATCHED,
        "method": MatchMethod.VERSION_TAG,
        "confidence": Confidence.LOW,
        "explanation": "x",
        "repository": repository,
    }

    with pytest.raises(ValidationError):
        SourceMatch.model_validate(base)
    with pytest.raises(ValidationError):
        SourceMatch.model_validate({**base, "commit_sha": "main"})


# Recorded commit with no tag


async def test_recorded_commit_at_a_branch_tip_needs_no_api_call() -> None:
    requests: list[httpx.Request] = []
    body = advertisement(branches={"release/1.x": COMMIT_A})

    match = await resolver_for(refs_handler(body, requests)).resolve(
        make_metadata(source_commit=COMMIT_A)
    )

    assert match.method is MatchMethod.RECORDED_COMMIT
    assert match.confidence is Confidence.MEDIUM
    assert match.commit_sha == COMMIT_A
    assert match.tag is None
    assert len(requests) == 1


@pytest.mark.parametrize("compare_status", ["behind", "identical"])
async def test_recorded_commit_on_default_branch_is_matched(compare_status: str) -> None:
    seen: list[httpx.Request] = []
    handler = api_handler(httpx.Response(200, json={"status": compare_status}), seen)

    match = await resolver_for(handler).resolve(make_metadata(source_commit=COMMIT_A))

    assert match.method is MatchMethod.RECORDED_COMMIT
    assert match.confidence is Confidence.MEDIUM
    assert match.commit_sha == COMMIT_A
    assert seen[1].url.path == f"/repos/acme/demo/compare/main...{COMMIT_A}"


@pytest.mark.parametrize(
    "response",
    [
        # A commit that exists only in a fork is ahead of or diverged from the default branch.
        httpx.Response(200, json={"status": "diverged"}),
        httpx.Response(200, json={"status": "ahead"}),
        httpx.Response(200, json={}),
        httpx.Response(404),
        httpx.Response(422),
    ],
)
async def test_commit_outside_repository_history_is_uncertain(response: httpx.Response) -> None:
    match = await resolver_for(api_handler(response)).resolve(make_metadata(source_commit=COMMIT_A))

    assert_uncertain(match, UncertainReason.RECORDED_COMMIT_UNVERIFIED)
    assert match.recorded_commit == COMMIT_A


@pytest.mark.parametrize("status", [403, 429, 500])
async def test_rate_limited_commit_check_is_uncertain_and_retryable(status: int) -> None:
    handler = api_handler(httpx.Response(status))

    match = await resolver_for(handler).resolve(make_metadata(source_commit=COMMIT_A))

    assert_uncertain(match, UncertainReason.LOOKUP_FAILED)


async def test_commit_cannot_be_checked_without_a_default_branch() -> None:
    body = advertisement(default_branch=None)

    match = await resolver_for(refs_handler(body)).resolve(make_metadata(source_commit=COMMIT_A))

    assert_uncertain(match, UncertainReason.RECORDED_COMMIT_UNVERIFIED)


async def test_default_branch_with_slash_is_one_encoded_path_segment() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "github.com":
            return httpx.Response(200, content=advertisement(default_branch="dev/next"))
        return httpx.Response(200, json={"status": "behind"})

    await resolver_for(handler).resolve(make_metadata(source_commit=COMMIT_A))

    assert b"/compare/dev%2Fnext..." in seen[1].url.raw_path


async def test_token_is_sent_only_to_the_api() -> None:
    seen: list[httpx.Request] = []
    token = SecretStr("secret-token")
    resolver = resolver_for(
        api_handler(httpx.Response(200, json={"status": "behind"}), seen), token
    )

    await resolver.resolve(make_metadata(source_commit=COMMIT_A))

    assert "Authorization" not in seen[0].headers
    assert seen[1].url.host == "api.github.com"
    assert seen[1].headers["Authorization"] == "Bearer secret-token"


def test_settings_hide_the_token() -> None:
    settings = Settings(github_token=SecretStr("secret-token"))

    assert "secret-token" not in repr(settings)


# Reference parsing


def test_parses_refs() -> None:
    refs = parse_refs_advertisement(
        advertisement(
            {"v1": COMMIT_A, "v2": ANNOTATED, "v2^{}": COMMIT_B},
            branches={"main": COMMIT_C},
            default_branch="main",
        )
    )

    assert refs.tags == {"v1": COMMIT_A, "v2": COMMIT_B}
    assert refs.branch_tips == {COMMIT_C}
    assert refs.default_branch == "main"


def test_ignores_refs_that_are_not_tags_or_branches() -> None:
    body = (
        packet(b"# service=git-upload-pack\n")
        + b"0000"
        + packet(f"{COMMIT_A} refs/pull/1/head\n".encode())
        + b"0000"
    )

    refs = parse_refs_advertisement(body)

    assert refs.tags == {}
    assert refs.branch_tips == frozenset()


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"garbage!",
        packet(b"other service\n"),
        packet(b"# service=git-upload-pack\n") + b"zzzz",
        packet(b"# service=git-upload-pack\n") + b"0001",
        packet(b"# service=git-upload-pack\n") + b"ffff" + b"short",
        packet(b"# service=git-upload-pack\n") + packet(b"nosha refs/tags/v1\n"),
    ],
)
def test_rejects_malformed_refs(body: bytes) -> None:
    with pytest.raises(InvalidRegistryResponseError):
        parse_refs_advertisement(body)


# Archive download


ARCHIVE = b"opaque source archive bytes"


async def matched(tag: str = f"v{VERSION}") -> SourceMatch:
    return await resolve({tag: COMMIT_A})


def archive_handler(requests: list[httpx.Request] | None = None) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        if requests is not None:
            requests.append(request)
        return httpx.Response(200, stream=httpx.ByteStream(ARCHIVE))

    return handler


async def test_downloads_archive_for_the_exact_commit(tmp_path: Path) -> None:
    requests: list[httpx.Request] = []
    match = await matched()

    archive = await resolver_for(archive_handler(requests)).download_source(match, tmp_path)

    assert str(requests[0].url) == f"https://codeload.github.com/acme/demo/tar.gz/{COMMIT_A}"
    assert archive.commit_sha == COMMIT_A
    assert archive.path == tmp_path / f"acme-demo-{COMMIT_A}.tar.gz"
    assert archive.path.read_bytes() == ARCHIVE
    assert archive.size_bytes == len(ARCHIVE)
    assert archive.sha256 == hashlib.sha256(ARCHIVE).hexdigest()
    assert stat.S_IMODE(archive.path.stat().st_mode) == 0o600
    assert [path.name for path in tmp_path.iterdir()] == [archive.path.name]


async def test_uncertain_match_cannot_download_anything(tmp_path: Path) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("no request expected")

    match = await resolve({})

    with pytest.raises(SourceNotMatchedError):
        await resolver_for(handler).download_source(match, tmp_path)
    assert list(tmp_path.iterdir()) == []


async def test_archive_token_is_never_sent(tmp_path: Path) -> None:
    requests: list[httpx.Request] = []
    resolver = resolver_for(archive_handler(requests), SecretStr("secret-token"))

    await resolver.download_source(await matched(), tmp_path)

    assert "Authorization" not in requests[0].headers


@pytest.mark.parametrize(
    ("handler", "error"),
    [
        (lambda _: httpx.Response(404), RegistryNotFoundError),
        (lambda _: httpx.Response(503), RegistryUnavailableError),
        (
            lambda _: httpx.Response(302, headers={"Location": "https://evil.test/"}),
            InvalidRegistryResponseError,
        ),
    ],
)
async def test_failed_archive_download_leaves_nothing(
    tmp_path: Path, handler: Handler, error: type[Exception]
) -> None:
    match = await matched()

    with pytest.raises(error):
        await resolver_for(handler).download_source(match, tmp_path)

    assert list(tmp_path.iterdir()) == []


async def test_archive_timeout_leaves_nothing(tmp_path: Path) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    match = await matched()

    with pytest.raises(RegistryTimeoutError):
        await resolver_for(handler).download_source(match, tmp_path)
    assert list(tmp_path.iterdir()) == []


async def test_archive_size_limit_is_separate_from_package_limit(tmp_path: Path) -> None:
    match = await matched()
    within = RegistryLimits(max_artifact_bytes=1, max_source_archive_bytes=len(ARCHIVE))
    below = RegistryLimits(max_artifact_bytes=1000, max_source_archive_bytes=len(ARCHIVE) - 1)

    await resolver_for(archive_handler(), limits=within).download_source(match, tmp_path / "a")
    with pytest.raises(ResponseTooLargeError):
        await resolver_for(archive_handler(), limits=below).download_source(match, tmp_path / "b")

    assert list((tmp_path / "b").iterdir()) == []
