from dataclasses import dataclass
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.adapters.base import PackageMetadata
from app.archives.models import ContentType, EntryKind
from app.schemas.scans import Ecosystem
from app.source.models import SourceMatch


@dataclass(frozen=True)
class ComparisonLimits:
    max_diff_file_bytes: int = 1024 * 1024
    max_diff_lines: int = 20_000
    max_diff_output_bytes: int = 256 * 1024
    max_total_diff_bytes: int = 64 * 1024 * 1024
    max_config_bytes: int = 1024 * 1024
    max_source_map_bytes: int = 16 * 1024 * 1024
    max_manifest_search_files: int = 5_000
    max_script_depth: int = 8


class FileStatus(StrEnum):
    IDENTICAL = "IDENTICAL"
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    MODIFIED = "MODIFIED"
    BINARY_DIFFERENT = "BINARY_DIFFERENT"
    RENAMED = "RENAMED"


class GeneratedClassification(StrEnum):
    LIKELY_GENERATED = "LIKELY_GENERATED"
    UNCERTAIN = "UNCERTAIN"


class EvidenceKind(StrEnum):
    """Build evidence, all read from the source repository except for the source map."""

    # Pipeline evidence: the repository declares a build that outputs to this location.
    OUTPUT_DIRECTORY = "output_directory"
    OUTPUT_FILE = "output_file"
    # Relationship evidence: this particular file is connected to the repository's source.
    SOURCE_COUNTERPART = "source_counterpart"
    SOURCE_ENTRY_POINT = "source_entry_point"
    SOURCE_MAP = "source_map"
    # Supporting evidence: never sufficient by itself.
    GITIGNORE = "gitignore"
    FILES_FIELD = "files_field"


PIPELINE_EVIDENCE = frozenset({EvidenceKind.OUTPUT_DIRECTORY, EvidenceKind.OUTPUT_FILE})
RELATIONSHIP_EVIDENCE = frozenset(
    {
        EvidenceKind.SOURCE_COUNTERPART,
        EvidenceKind.SOURCE_ENTRY_POINT,
        EvidenceKind.SOURCE_MAP,
        EvidenceKind.OUTPUT_FILE,
    }
)


class DiffStatus(StrEnum):
    INCLUDED = "included"
    TRUNCATED = "truncated"
    NOT_APPLICABLE = "not_applicable"
    NOT_TEXT = "not_text"
    TOO_LARGE = "too_large"
    BUDGET_EXHAUSTED = "budget_exhausted"


class ScopeMethod(StrEnum):
    DECLARED_DIRECTORY = "declared_directory"
    REPOSITORY_ROOT = "repository_root"
    MANIFEST_SEARCH = "manifest_search"
    UNRESOLVED = "unresolved"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class Evidence(_FrozenModel):
    kind: EvidenceKind
    detail: str
    source_file: str | None = Field(default=None, description="The file that supplied this.")


class GeneratedAssessment(_FrozenModel):
    """Whether a differing file looks like build output.

    LIKELY_GENERATED describes where a file came from, not whether its content is safe:
    a file could be real build output with code injected into it.
    """

    classification: GeneratedClassification
    evidence: tuple[Evidence, ...] = ()
    blockers: tuple[str, ...] = Field(
        default=(), description="Facts that rule out LIKELY_GENERATED, whatever else is true."
    )
    missing: tuple[str, ...] = Field(default=(), description="Evidence that was looked for.")

    @model_validator(mode="after")
    def check_likely_generated_has_support(self) -> Self:
        if self.classification is GeneratedClassification.LIKELY_GENERATED:
            kinds = {item.kind for item in self.evidence}
            if self.blockers or not kinds & PIPELINE_EVIDENCE or not kinds & RELATIONSHIP_EVIDENCE:
                raise ValueError(
                    "LIKELY_GENERATED needs build and relationship evidence, and no blockers"
                )
        return self


class FileSide(_FrozenModel):
    size_bytes: int
    sha256: str | None
    kind: EntryKind
    content_type: ContentType | None
    mode: str | None
    is_executable: bool
    link_target: str | None = None


class TextDiff(_FrozenModel):
    status: DiffStatus
    unified: str | None = Field(
        default=None, description="Unified diff from source to package. This is untrusted data."
    )
    added_lines: int | None = None
    removed_lines: int | None = None
    only_line_endings_differ: bool = False


class FileComparison(_FrozenModel):
    path: str = Field(description="The path in the package, or in the source if it was removed.")
    status: FileStatus
    package_path: str | None
    source_path: str | None
    package: FileSide | None
    source: FileSide | None
    executable_bit_changed: bool = False
    diff: TextDiff
    generated: GeneratedAssessment | None = Field(
        default=None, description="Present for every package file that is not identical."
    )
    notes: tuple[str, ...] = ()


class SourceScope(_FrozenModel):
    directory: str = Field(description="The compared part of the repository. Empty for the root.")
    method: ScopeMethod
    manifest_name_matches: bool | None = None
    manifest_version_matches: bool | None = None


class BuildSummary(_FrozenModel):
    """What the source repository declares about its build, read without running anything."""

    tools: tuple[str, ...] = ()
    output_directories: tuple[str, ...] = ()
    output_files: tuple[str, ...] = ()
    unrecognized_build_commands: tuple[str, ...] = ()


class ComparisonSummary(_FrozenModel):
    identical: int = 0
    added: int = 0
    removed: int = 0
    modified: int = 0
    binary_different: int = 0
    renamed: int = 0
    likely_generated: int = 0
    uncertain: int = 0


class ComparisonReport(_FrozenModel):
    ecosystem: Ecosystem
    package_name: str
    package_version: str
    source_match: SourceMatch
    scope: SourceScope
    build: BuildSummary
    summary: ComparisonSummary
    files: tuple[FileComparison, ...]
    warnings: tuple[str, ...] = ()


class ReleaseComparison(_FrozenModel):
    """A retrieved release. ``report`` is None when no source commit could be established."""

    metadata: PackageMetadata
    source_match: SourceMatch
    report: ComparisonReport | None = None
