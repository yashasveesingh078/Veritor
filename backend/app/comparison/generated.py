"""Decide whether a differing package file is likely to be build output.

LIKELY_GENERATED requires both of these, and no blocker:

1. Pipeline: the source repository declares a build that outputs to this location.
2. Relationship: this particular file is connected to the repository's source.

A directory name is never evidence. `dist/evil.js` stays UNCERTAIN in a project that
really does build to `dist/`, unless something ties that file to the source.
"""

import base64
import binascii
import hashlib
import json
import posixpath
import re
from dataclasses import dataclass
from typing import Any

from app.archives.models import ContentType, EntryKind, InventoryEntry
from app.comparison.build_evidence import BUNDLERS, COMPILERS, BuildOutput, BuildProfile
from app.comparison.models import (
    ComparisonLimits,
    Evidence,
    EvidenceKind,
    GeneratedAssessment,
    GeneratedClassification,
)
from app.comparison.trees import FileTree, is_within, normalize_relative

TEXT_CONTENT_TYPES = {ContentType.TEXT, ContentType.SCRIPT, ContentType.EMPTY}
_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
_OUTPUT_SUFFIXES = (
    ".d.ts.map",
    ".d.mts.map",
    ".d.cts.map",
    ".js.map",
    ".mjs.map",
    ".cjs.map",
    ".css.map",
    ".d.ts",
    ".d.mts",
    ".d.cts",
    ".js",
    ".mjs",
    ".cjs",
    ".css",
)
_COMPILER_SUFFIXES = tuple(suffix for suffix in _OUTPUT_SUFFIXES if ".css" not in suffix)
_TYPESCRIPT_SOURCES = (".ts", ".tsx", ".mts", ".cts")
_COMPILER_SOURCES = {
    "tsc": (*_TYPESCRIPT_SOURCES, ".js", ".jsx", ".mjs", ".cjs"),
    "babel": (*_TYPESCRIPT_SOURCES, ".js", ".jsx", ".mjs", ".cjs"),
    "swc": (*_TYPESCRIPT_SOURCES, ".js", ".jsx", ".mjs", ".cjs"),
}
_SOURCE_MAPPING_URL = re.compile(rb"(?://|/\*)[#@]\s*sourceMappingURL=([^\s*]+)")
_EXTERNAL_SOURCE = re.compile(
    r"(?:^|/)node_modules/|^\(webpack\)|^webpack/|^\x00|^virtual:|^vite/|^rollup"
)
_BUNDLER_URL_PREFIX = re.compile(r"^(?:webpack|rollup|vite)://[^/]*/")


@dataclass(frozen=True)
class AssessmentContext:
    profile: BuildProfile
    source: FileTree
    package: FileTree
    limits: ComparisonLimits
    install_script_text: str


def assess_generated(
    path: str, entry: InventoryEntry, context: AssessmentContext
) -> GeneratedAssessment:
    """Assess one package file that differs from, or is absent from, the source."""
    profile = context.profile
    blockers = _blockers(path, entry, context)
    evidence: list[Evidence] = []
    missing: list[str] = []

    outputs = [output for output in profile.outputs if is_within(path, output.directory)]
    for output in outputs:
        evidence.append(
            Evidence(
                kind=EvidenceKind.OUTPUT_DIRECTORY,
                detail=f"{output.tool} outputs to {output.directory}/",
                source_file=output.origin,
            )
        )
    declared_file = profile.output_files.get(path)
    if declared_file is not None:
        evidence.append(
            Evidence(
                kind=EvidenceKind.OUTPUT_FILE,
                detail=f"{declared_file.tool} declares this exact output file",
                source_file=declared_file.origin,
            )
        )
    if not outputs and declared_file is None:
        counterpart = _beside_source_counterpart(path, profile, context.source)
        if counterpart is not None:
            evidence.append(
                Evidence(
                    kind=EvidenceKind.OUTPUT_DIRECTORY,
                    detail="tsc has no outDir, so it writes output beside each source file",
                    source_file=profile.tsc_emits_beside_source,
                )
            )
            evidence.append(
                Evidence(
                    kind=EvidenceKind.SOURCE_COUNTERPART,
                    detail=f"Compiled from {counterpart}",
                    source_file=counterpart,
                )
            )
        else:
            missing.append("The repository declares no build output containing this file")

    is_text = entry.kind is EntryKind.REGULAR and entry.content_type in TEXT_CONTENT_TYPES
    if outputs and is_text:
        evidence += _output_relationships(path, outputs, profile, context.source)

    if is_text and path.endswith(_OUTPUT_SUFFIXES):
        map_evidence, map_blocker, map_missing = _check_source_map(path, context)
        evidence += map_evidence
        blockers += map_blocker
        missing += map_missing

    if path in profile.gitignored_directories or any(
        is_within(path, directory) for directory in profile.gitignored_directories
    ):
        evidence.append(
            Evidence(
                kind=EvidenceKind.GITIGNORE,
                detail="The repository's .gitignore excludes this path",
                source_file=".gitignore",
            )
        )
    if _in_files_field(path, profile.files_field):
        evidence.append(
            Evidence(
                kind=EvidenceKind.FILES_FIELD,
                detail="The repository's package.json publishes this path",
                source_file="package.json",
            )
        )

    kinds = {item.kind for item in evidence}
    has_pipeline = bool(kinds & {EvidenceKind.OUTPUT_DIRECTORY, EvidenceKind.OUTPUT_FILE})
    has_relationship = bool(
        kinds
        & {
            EvidenceKind.SOURCE_COUNTERPART,
            EvidenceKind.SOURCE_ENTRY_POINT,
            EvidenceKind.SOURCE_MAP,
            EvidenceKind.OUTPUT_FILE,
        }
    )
    if has_pipeline and not has_relationship:
        missing.append("Nothing connects this particular file to the repository's source")

    likely = has_pipeline and has_relationship and not blockers
    return GeneratedAssessment(
        classification=(
            GeneratedClassification.LIKELY_GENERATED
            if likely
            else GeneratedClassification.UNCERTAIN
        ),
        evidence=tuple(evidence),
        blockers=tuple(blockers),
        missing=tuple(missing),
    )


def _blockers(path: str, entry: InventoryEntry, context: AssessmentContext) -> list[str]:
    blockers: list[str] = []
    if entry.kind is not EntryKind.REGULAR:
        blockers.append(f"A {entry.kind.value} entry cannot be confirmed as build output")
    elif entry.content_type not in TEXT_CONTENT_TYPES:
        label = entry.content_type.value if entry.content_type else "unknown"
        blockers.append(f"Binary content ({label}) cannot be confirmed as build output")
    if entry.kind is EntryKind.REGULAR and not path.endswith(_OUTPUT_SUFFIXES):
        blockers.append("This file type is not an expected output of a JavaScript build")
    if named_in_text(path, context.install_script_text):
        blockers.append("An install script runs this file, so it executes at install time")
    if entry.kind is EntryKind.REGULAR and entry.content_type in TEXT_CONTENT_TYPES:
        blockers += _whole_file_text_blocker(path, context)
    return blockers


def _whole_file_text_blocker(path: str, context: AssessmentContext) -> list[str]:
    """Check all of the file, because the inventory's content type only samples its start."""
    data = context.package.read(path, context.limits.max_source_map_bytes)
    if data is None:
        return ["This file is too large to confirm that all of it is text"]
    binary = ["Binary content appears after the start of this text file"]
    if b"\0" in data:
        return binary
    try:
        data.decode()
    except UnicodeDecodeError:
        return binary
    return []


def named_in_text(path: str, text: str) -> bool:
    return (
        bool(text)
        and re.search(rf"(?:^|[\s\"'/=]){re.escape(path)}(?:$|[\s\"';&|])", text) is not None
    )


def _output_relationships(
    path: str, outputs: list[BuildOutput], profile: BuildProfile, source: FileTree
) -> list[Evidence]:
    found: list[Evidence] = []
    for output in outputs:
        if output.tool in COMPILERS:
            counterpart = _compiler_counterpart(path, output, profile, source)
            if counterpart is not None:
                found.append(
                    Evidence(
                        kind=EvidenceKind.SOURCE_COUNTERPART,
                        detail=f"{output.tool} compiles {counterpart} to this path",
                        source_file=counterpart,
                    )
                )
        elif output.tool in BUNDLERS and path in profile.entry_points:
            found.append(
                Evidence(
                    kind=EvidenceKind.SOURCE_ENTRY_POINT,
                    detail=(
                        f"The repository's package.json {profile.entry_points[path]} "
                        f"names this {output.tool} output"
                    ),
                    source_file="package.json",
                )
            )
    return found


def _compiler_counterpart(
    path: str, output: BuildOutput, profile: BuildProfile, source: FileTree
) -> str | None:
    stem = _output_stem(path, _COMPILER_SUFFIXES)
    if stem is None:
        return None
    relative = stem.removeprefix(f"{output.directory}/")
    roots = [
        root.root
        for root in profile.compiler_roots
        if root.tool == output.tool and root.output_directory == output.directory
    ]
    for root in roots:
        for suffix in _COMPILER_SOURCES.get(output.tool, ()):
            candidate = posixpath.join(root, f"{relative}{suffix}")
            if candidate != path and candidate in source.entries:
                return candidate
    return None


def _beside_source_counterpart(path: str, profile: BuildProfile, source: FileTree) -> str | None:
    if profile.tsc_emits_beside_source is None:
        return None
    stem = _output_stem(path, _COMPILER_SUFFIXES)
    if stem is None:
        return None
    # Only TypeScript sources: a .js file beside a .js file would not be build output.
    for suffix in _TYPESCRIPT_SOURCES:
        candidate = f"{stem}{suffix}"
        if candidate in source.entries:
            return candidate
    return None


def _output_stem(path: str, suffixes: tuple[str, ...]) -> str | None:
    for suffix in suffixes:
        if path.endswith(suffix):
            return path[: -len(suffix)]
    return None


def _in_files_field(path: str, files: list[str]) -> bool:
    for pattern in files:
        normalized = normalize_relative(pattern.rstrip("/"))
        if (
            normalized
            and "*" not in normalized
            and (path == normalized or is_within(path, normalized))
        ):
            return True
    return False


def _check_source_map(
    path: str, context: AssessmentContext
) -> tuple[list[Evidence], list[str], list[str]]:
    """Check that this file's source map, or this map itself, points into the repository."""
    limits = context.limits
    if path.endswith(".map"):
        document = _load_map(context.package.read(path, limits.max_source_map_bytes))
        map_path = path
    else:
        document, map_path = _find_linked_map(path, context)
    if document is None:
        return [], [], []

    sources = document.get("sources")
    if not isinstance(sources, list) or not sources:
        return [], [], ["The source map lists no sources"]

    source_root = document.get("sourceRoot")
    contents = document.get("sourcesContent")
    contents = contents if isinstance(contents, list) else []
    resolved_count = 0
    blockers: list[str] = []
    for index, source in enumerate(sources):
        if not isinstance(source, str):
            return [], [], ["The source map has an invalid source entry"]
        if _EXTERNAL_SOURCE.search(source):
            continue
        resolved = _resolve_map_source(source, source_root, map_path)
        if resolved is None or resolved not in context.source.entries:
            return [], [], [f"The source map names a file not in the repository: {source[:200]!r}"]
        resolved_count += 1
        content = contents[index] if index < len(contents) else None
        if isinstance(content, str):
            expected = context.source.entries[resolved].sha256
            if hashlib.sha256(content.encode()).hexdigest() != expected:
                blockers.append(
                    f"The source map embeds different content for {resolved} than the repository"
                )
    if resolved_count == 0:
        return [], [], ["The source map names no files from the repository"]
    if blockers:
        return [], blockers, []
    return (
        [
            Evidence(
                kind=EvidenceKind.SOURCE_MAP,
                detail=f"The source map resolves to {resolved_count} repository file(s)",
                source_file=map_path,
            )
        ],
        [],
        [],
    )


def _find_linked_map(path: str, context: AssessmentContext) -> tuple[dict[str, Any] | None, str]:
    limits = context.limits
    data = context.package.read(path, limits.max_source_map_bytes)
    if data is None:
        return None, path
    matches = _SOURCE_MAPPING_URL.findall(data)
    if not matches:
        return None, path
    # The last comment is the one that browsers and Node use.
    url = matches[-1].decode(errors="replace")
    if url.startswith("data:"):
        _, separator, encoded = url.partition(";base64,")
        if not separator:
            return None, path
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            return None, path
        return _load_map(decoded), path
    map_path = normalize_relative(posixpath.join(posixpath.dirname(path), url))
    if not map_path:
        return None, path
    return _load_map(context.package.read(map_path, limits.max_source_map_bytes)), map_path


def _load_map(data: bytes | None) -> dict[str, Any] | None:
    if data is None:
        return None
    try:
        document = json.loads(data)
    except (ValueError, RecursionError):
        return None
    return document if isinstance(document, dict) else None


def _resolve_map_source(source: str, source_root: object, map_path: str) -> str | None:
    cleaned = _BUNDLER_URL_PREFIX.sub("", source)
    if "://" in cleaned or cleaned.startswith("/"):
        return None
    if cleaned != source:
        # A bundler URL such as webpack://name/./src/a.ts is relative to the project.
        return normalize_relative(cleaned)
    root = source_root if isinstance(source_root, str) else ""
    if "://" in root or root.startswith("/"):
        return None
    return normalize_relative(posixpath.join(posixpath.dirname(map_path), root, cleaned))


def install_script_text(scripts: dict[str, str], package_manifest: bytes | None) -> str:
    """Join install scripts from the registry and the tarball, which can disagree."""
    parts = [scripts[name] for name in _INSTALL_SCRIPTS if name in scripts]
    if package_manifest is not None:
        try:
            manifest = json.loads(package_manifest)
        except (ValueError, RecursionError):
            manifest = None
        declared = manifest.get("scripts") if isinstance(manifest, dict) else None
        if isinstance(declared, dict):
            parts += [
                declared[name] for name in _INSTALL_SCRIPTS if isinstance(declared.get(name), str)
            ]
    return "\n".join(parts)
