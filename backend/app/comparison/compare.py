"""Compare a package with its source using inventories, SHA-256 hashes and difflib.

Nothing here executes or interprets package code. Content is only hashed, decoded and
diffed. This function blocks. Async callers should run it with ``asyncio.to_thread``.
"""

import difflib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass

from app.adapters.base import PackageMetadata
from app.archives.models import EntryKind, FileInventory, InventoryEntry
from app.comparison.build_evidence import BuildProfile, collect_build_profile
from app.comparison.generated import (
    TEXT_CONTENT_TYPES,
    AssessmentContext,
    assess_generated,
    install_script_text,
)
from app.comparison.models import (
    BuildSummary,
    ComparisonLimits,
    ComparisonReport,
    ComparisonSummary,
    DiffStatus,
    FileComparison,
    FileSide,
    FileStatus,
    GeneratedAssessment,
    GeneratedClassification,
    ScopeMethod,
    SourceScope,
    TextDiff,
)
from app.comparison.trees import FileTree, is_within, normalize_relative
from app.source.github import SourceNotMatchedError
from app.source.models import MatchStatus, SourceMatch

# Short files such as an empty stub are too common for an equal hash to prove a rename.
MIN_RENAME_BYTES = 32
_NO_DIFF = TextDiff(status=DiffStatus.NOT_APPLICABLE)


@dataclass
class _Pair:
    path: str
    status: FileStatus
    package_path: str | None
    source_path: str | None
    package: InventoryEntry | None
    source: InventoryEntry | None
    notes: tuple[str, ...] = ()
    generated: GeneratedAssessment | None = None
    diff: TextDiff = _NO_DIFF


def compare_inventories(
    metadata: PackageMetadata,
    match: SourceMatch,
    package_inventory: FileInventory,
    source_inventory: FileInventory,
    limits: ComparisonLimits | None = None,
) -> ComparisonReport:
    """Compare a package with the source at a matched commit."""
    if match.status is not MatchStatus.MATCHED:
        raise SourceNotMatchedError(f"No source commit was established: {match.explanation}")
    limits = limits or ComparisonLimits()

    repository = FileTree(source_inventory)
    package = FileTree(package_inventory)
    warnings: list[str] = []
    directory, method = _resolve_scope(metadata, match, repository, limits, warnings)
    source = FileTree(source_inventory, directory)

    profile = collect_build_profile(source, repository, limits)
    scope = SourceScope(
        directory=directory,
        method=method,
        manifest_name_matches=(
            profile.manifest_name == metadata.name if profile.manifest_name else None
        ),
        manifest_version_matches=(
            profile.manifest_version == metadata.version if profile.manifest_version else None
        ),
    )
    if scope.manifest_name_matches is False:
        warnings.append(
            f"The repository's package.json names {profile.manifest_name!r}, not the package."
        )
    if scope.manifest_version_matches is False:
        warnings.append(
            f"The repository's package.json has version {profile.manifest_version!r} at this "
            "commit, not the published version."
        )

    pairs = _pair_files(package, source)
    context = AssessmentContext(
        profile=profile,
        source=source,
        package=package,
        limits=limits,
        install_script_text=install_script_text(
            metadata.scripts, package.read("package.json", limits.max_config_bytes)
        ),
    )
    for pair in pairs:
        if pair.package is not None and pair.status is not FileStatus.IDENTICAL:
            pair.generated = assess_generated(pair.package_path or pair.path, pair.package, context)

    _add_diffs(pairs, package, source, limits)
    files = tuple(_to_file_comparison(pair) for pair in sorted(pairs, key=lambda p: p.path))
    return ComparisonReport(
        ecosystem=metadata.ecosystem,
        package_name=metadata.name,
        package_version=metadata.version,
        source_match=match,
        scope=scope,
        build=_build_summary(profile),
        summary=_summarize(files),
        files=files,
        warnings=tuple(warnings),
    )


def _resolve_scope(
    metadata: PackageMetadata,
    match: SourceMatch,
    repository: FileTree,
    limits: ComparisonLimits,
    warnings: list[str],
) -> tuple[str, ScopeMethod]:
    """Find the part of a repository that a package is built from."""
    if match.directory:
        directory = normalize_relative(match.directory)
        if directory and any(is_within(path, directory) for path in repository.entries):
            return directory, ScopeMethod.DECLARED_DIRECTORY
        warnings.append(f"The declared directory {match.directory!r} is not in the repository.")

    if _manifest_name(repository, "package.json", limits) == metadata.name:
        return "", ScopeMethod.REPOSITORY_ROOT

    manifests = [
        path
        for path in repository.entries
        if path.endswith("/package.json") and "node_modules/" not in path
    ][: limits.max_manifest_search_files]
    located = [
        path for path in manifests if _manifest_name(repository, path, limits) == metadata.name
    ]
    if len(located) == 1:
        directory = located[0].removesuffix("/package.json")
        warnings.append(f"Located the package at {directory!r} by the name in its package.json.")
        return directory, ScopeMethod.MANIFEST_SEARCH

    warnings.append("Could not tell which part of the repository holds this package.")
    return "", ScopeMethod.UNRESOLVED


def _manifest_name(tree: FileTree, path: str, limits: ComparisonLimits) -> str | None:
    data = tree.read(path, limits.max_config_bytes)
    if data is None:
        return None
    try:
        manifest = json.loads(data)
    except (ValueError, RecursionError):
        return None
    name = manifest.get("name") if isinstance(manifest, dict) else None
    return name if isinstance(name, str) else None


def _pair_files(package: FileTree, source: FileTree) -> list[_Pair]:
    pairs: list[_Pair] = []
    added: dict[str, InventoryEntry] = {}
    removed = {path: entry for path, entry in source.entries.items() if path not in package.entries}

    for path, entry in package.entries.items():
        counterpart = source.entries.get(path)
        if counterpart is None:
            added[path] = entry
        else:
            pairs.append(_paired(path, entry, counterpart))

    renamed = _find_renames(added, removed)
    for package_path, source_path in renamed.items():
        pairs.append(
            _Pair(
                path=package_path,
                status=FileStatus.RENAMED,
                package_path=package_path,
                source_path=source_path,
                package=added.pop(package_path),
                source=removed.pop(source_path),
            )
        )

    added_hashes = Counter(_rename_key(entry) for entry in added.values())
    removed_hashes = Counter(_rename_key(entry) for entry in removed.values())
    for path, entry in added.items():
        key = _rename_key(entry)
        notes = (
            ("An identical file exists at other source paths, so no rename could be proven.",)
            if key is not None and removed_hashes[key]
            else ()
        )
        pairs.append(_Pair(path, FileStatus.ADDED, path, None, entry, None, notes))
    for path, entry in removed.items():
        key = _rename_key(entry)
        notes = (
            ("An identical file exists at other package paths, so no rename could be proven.",)
            if key is not None and added_hashes[key]
            else ()
        )
        pairs.append(_Pair(path, FileStatus.REMOVED, None, path, None, entry, notes))
    return pairs


def _paired(path: str, package: InventoryEntry, source: InventoryEntry) -> _Pair:
    same_kind = package.kind is source.kind
    # A special file has no hash, and so can never be shown to be identical.
    if same_kind and package.sha256 is not None and package.sha256 == source.sha256:
        status = FileStatus.IDENTICAL
    elif (
        same_kind
        and package.kind is EntryKind.REGULAR
        and not (
            package.content_type in TEXT_CONTENT_TYPES and source.content_type in TEXT_CONTENT_TYPES
        )
    ):
        status = FileStatus.BINARY_DIFFERENT
    else:
        status = FileStatus.MODIFIED
    notes = (
        (f"The entry changed from {source.kind.value} to {package.kind.value}.",)
        if not same_kind
        else ()
    )
    return _Pair(path, status, path, path, package, source, notes)


def _rename_key(entry: InventoryEntry) -> str | None:
    if entry.kind is not EntryKind.REGULAR or entry.size_bytes < MIN_RENAME_BYTES:
        return None
    return entry.sha256


def _find_renames(
    added: dict[str, InventoryEntry], removed: dict[str, InventoryEntry]
) -> dict[str, str]:
    """Pair files only when one exact hash appears once on each side."""
    added_by_hash: dict[str, list[str]] = defaultdict(list)
    removed_by_hash: dict[str, list[str]] = defaultdict(list)
    for path, entry in added.items():
        if (key := _rename_key(entry)) is not None:
            added_by_hash[key].append(path)
    for path, entry in removed.items():
        if (key := _rename_key(entry)) is not None:
            removed_by_hash[key].append(path)
    return {
        paths[0]: removed_by_hash[key][0]
        for key, paths in added_by_hash.items()
        if len(paths) == 1 and len(removed_by_hash.get(key, ())) == 1
    }


def _add_diffs(
    pairs: list[_Pair], package: FileTree, source: FileTree, limits: ComparisonLimits
) -> None:
    """Add text diffs, spending the shared budget on unexplained files first."""
    budget = limits.max_total_diff_bytes

    def priority(pair: _Pair) -> tuple[bool, str]:
        generated = pair.generated is not None and (
            pair.generated.classification is GeneratedClassification.LIKELY_GENERATED
        )
        return generated, pair.path

    for pair in sorted(pairs, key=priority):
        if pair.status not in (
            FileStatus.ADDED,
            FileStatus.MODIFIED,
            FileStatus.BINARY_DIFFERENT,
        ):
            continue
        if pair.status is FileStatus.BINARY_DIFFERENT:
            pair.diff = TextDiff(status=DiffStatus.NOT_TEXT)
            continue
        if budget <= 0:
            pair.diff = TextDiff(status=DiffStatus.BUDGET_EXHAUSTED)
            continue
        _diff_pair(pair, package, source, limits)
        if pair.diff.unified is not None:
            budget -= len(pair.diff.unified.encode(errors="replace"))


def _diff_pair(pair: _Pair, package: FileTree, source: FileTree, limits: ComparisonLimits) -> None:
    package_entry, source_entry = pair.package, pair.source
    if package_entry is None or (
        package_entry.kind is not EntryKind.REGULAR
        or (source_entry is not None and source_entry.kind is not EntryKind.REGULAR)
    ):
        return
    if package_entry.content_type not in TEXT_CONTENT_TYPES:
        pair.diff = TextDiff(status=DiffStatus.NOT_TEXT)
        return

    package_data = package.read(pair.path, limits.max_diff_file_bytes)
    source_data = (
        source.read(pair.path, limits.max_diff_file_bytes) if source_entry is not None else b""
    )
    if package_data is None or source_data is None:
        pair.diff = TextDiff(status=DiffStatus.TOO_LARGE)
        return

    package_text = _decode_text(package_data)
    source_text = _decode_text(source_data)
    # The inventory only samples each file's start, so binary content can appear later.
    if package_text is None or source_text is None:
        pair.diff = TextDiff(status=DiffStatus.NOT_TEXT)
        if source_entry is not None:
            pair.status = FileStatus.BINARY_DIFFERENT
        return

    pair.diff = _unified_diff(pair.path, source_text, package_text, source_entry is None, limits)


def _decode_text(data: bytes) -> str | None:
    if b"\0" in data:
        return None
    try:
        return data.decode()
    except UnicodeDecodeError:
        return None


def _unified_diff(
    path: str, source_text: str, package_text: str, is_new: bool, limits: ComparisonLimits
) -> TextDiff:
    # Splitting only on newlines keeps the diff faithful to what the file contains.
    source_lines = source_text.split("\n") if source_text else []
    package_lines = package_text.split("\n") if package_text else []
    if max(len(source_lines), len(package_lines)) > limits.max_diff_lines:
        return TextDiff(status=DiffStatus.TOO_LARGE)

    only_line_endings = not is_new and source_text.replace("\r\n", "\n") == package_text.replace(
        "\r\n", "\n"
    )
    output: list[str] = []
    size = 0
    added = removed = 0
    truncated = False
    for line in difflib.unified_diff(
        source_lines,
        package_lines,
        fromfile="/dev/null" if is_new else f"a/{path}",
        tofile=f"b/{path}",
        lineterm="",
    ):
        size += len(line.encode(errors="replace")) + 1
        if size > limits.max_diff_output_bytes:
            truncated = True
            break
        output.append(line)
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return TextDiff(
        status=DiffStatus.TRUNCATED if truncated else DiffStatus.INCLUDED,
        unified="\n".join(output),
        # Counts from part of a diff would look like totals.
        added_lines=None if truncated else added,
        removed_lines=None if truncated else removed,
        only_line_endings_differ=only_line_endings,
    )


def _side(entry: InventoryEntry | None) -> FileSide | None:
    if entry is None:
        return None
    return FileSide(
        size_bytes=entry.size_bytes,
        sha256=entry.sha256,
        kind=entry.kind,
        content_type=entry.content_type,
        mode=entry.mode,
        is_executable=entry.is_executable,
        link_target=entry.link_target,
    )


def _to_file_comparison(pair: _Pair) -> FileComparison:
    return FileComparison(
        path=pair.path,
        status=pair.status,
        package_path=pair.package_path,
        source_path=pair.source_path,
        package=_side(pair.package),
        source=_side(pair.source),
        executable_bit_changed=(
            pair.package is not None
            and pair.source is not None
            and pair.package.is_executable != pair.source.is_executable
        ),
        diff=pair.diff,
        generated=pair.generated,
        notes=pair.notes,
    )


def _build_summary(profile: BuildProfile) -> BuildSummary:
    return BuildSummary(
        tools=tuple(sorted(profile.tools)),
        output_directories=tuple(sorted({output.directory for output in profile.outputs})),
        output_files=tuple(sorted(profile.output_files)),
        unrecognized_build_commands=tuple(profile.unrecognized_commands),
    )


def _summarize(files: tuple[FileComparison, ...]) -> ComparisonSummary:
    statuses = Counter(file.status for file in files)
    classifications = Counter(
        file.generated.classification for file in files if file.generated is not None
    )
    return ComparisonSummary(
        identical=statuses[FileStatus.IDENTICAL],
        added=statuses[FileStatus.ADDED],
        removed=statuses[FileStatus.REMOVED],
        modified=statuses[FileStatus.MODIFIED],
        binary_different=statuses[FileStatus.BINARY_DIFFERENT],
        renamed=statuses[FileStatus.RENAMED],
        likely_generated=classifications[GeneratedClassification.LIKELY_GENERATED],
        uncertain=classifications[GeneratedClassification.UNCERTAIN],
    )
