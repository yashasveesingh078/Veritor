"""Generated Artifact Intelligence for Veritor.

Analyzes package files against source repository configurations and code to classify
differing or added files as LIKELY_GENERATED, SUSPICIOUS, or UNCERTAIN based strictly
on deterministic evidence.

Identifies artifact types:
- COMPILED: single source-to-target compilation (e.g. TypeScript -> JavaScript)
- BUNDLED: multi-source bundling (e.g. Rollup, Webpack, Vite, Esbuild, Tsup)
- MINIFIED: whitespace-compressed, identifier-mangled code
- SOURCE_MAP: source map document (.map) or inline source mapping
- DECLARATION: TypeScript type definitions (.d.ts, .d.mts, .d.cts)
- GENERATED: generic build outputs with verified pipeline evidence

Guiding Principles:
- Never blindly whitelist output directories (dist/, build/, lib/).
- Do not mark every extra file malicious: unlinked files without suspicious evidence are UNCERTAIN.
- Classify as SUSPICIOUS only when supported by positive evidence (e.g. untracked install script
  execution, deceptive source map traversal, or obfuscation in unlinked artifacts).
"""

from __future__ import annotations

import difflib
import logging
import re

from app.archives.models import ContentType, EntryKind, InventoryEntry
from app.comparison.build_evidence import BUNDLERS, COMPILERS, BuildOutput, BuildProfile
from app.comparison.generated import (
    _OUTPUT_SUFFIXES,
    _SOURCE_MAPPING_URL,
    AssessmentContext,
    _beside_source_counterpart,
    _blockers,
    _check_source_map,
    _in_files_field,
    _output_relationships,
    named_in_text,
)
from app.comparison.models import (
    ArtifactType,
    Evidence,
    EvidenceKind,
    FileStatus,
    GeneratedAssessment,
    GeneratedClassification,
)
from app.comparison.trees import FileTree, is_within

logger = logging.getLogger(__name__)

__all__ = ["ArtifactClassifier", "ArtifactType", "classify_artifact"]

TEXT_CONTENT_TYPES = frozenset({ContentType.TEXT, ContentType.SCRIPT, ContentType.EMPTY})
_DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")
_SOURCE_MAP_SUFFIXES = (".map", ".d.ts.map", ".js.map", ".mjs.map", ".cjs.map", ".css.map")
_MINIFIED_SUFFIXES = (".min.js", ".min.mjs", ".min.cjs", ".min.css")

_OBFUSCATION_PATTERNS = (
    re.compile(r"eval\s*\(\s*(?:unescape|atob|Buffer\.from)\b"),
    re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,"),
    re.compile(r"\b_0x[a-f0-9]{4,6}\b"),
    re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}"),
)
_DANGEROUS_MAP_TARGETS = re.compile(
    r"""(?:\.\./){3,}|^(?:https?|ftp|file|javascript):|^data:(?!application/json)"""
)


class ArtifactClassifier:
    """Classifies differing package files by inspecting build profiles, source relationships,

    source maps, minification, and content similarity.
    """

    def __init__(self, context: AssessmentContext) -> None:
        self.context = context
        self.profile: BuildProfile = context.profile
        self.source: FileTree = context.source
        self.package: FileTree = context.package
        self.limits = context.limits
        self.install_script_text = context.install_script_text

    def classify(
        self,
        path: str,
        entry: InventoryEntry,
        status: FileStatus = FileStatus.ADDED,
        source_path: str | None = None,
    ) -> GeneratedAssessment:
        """Classify a single package file that differs from or is absent from source."""
        # 1. Gather baseline blockers and evidence
        blockers = _blockers(path, entry, self.context)
        evidence: list[Evidence] = []
        missing: list[str] = []

        # 2. Check build pipeline declarations
        outputs = [output for output in self.profile.outputs if is_within(path, output.directory)]
        for output in outputs:
            evidence.append(
                Evidence(
                    kind=EvidenceKind.OUTPUT_DIRECTORY,
                    detail=f"{output.tool} outputs to {output.directory}/",
                    source_file=output.origin,
                )
            )

        declared_file = self.profile.output_files.get(path)
        if declared_file is not None:
            evidence.append(
                Evidence(
                    kind=EvidenceKind.OUTPUT_FILE,
                    detail=f"{declared_file.tool} declares this exact output file",
                    source_file=declared_file.origin,
                )
            )

        counterpart: str | None = None
        if not outputs and declared_file is None:
            counterpart = _beside_source_counterpart(path, self.profile, self.source)
            if counterpart is not None:
                evidence.append(
                    Evidence(
                        kind=EvidenceKind.OUTPUT_DIRECTORY,
                        detail="tsc has no outDir, so it writes output beside each source file",
                        source_file=self.profile.tsc_emits_beside_source,
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
            rel_evidence = _output_relationships(path, outputs, self.profile, self.source)
            evidence += rel_evidence
            if counterpart is None:
                for ev in rel_evidence:
                    if ev.kind is EvidenceKind.SOURCE_COUNTERPART and ev.source_file:
                        counterpart = ev.source_file
                        break

        # If counterpart wasn't found by beside/output rules, check same relative path
        if counterpart is None and source_path and source_path in self.source.entries:
            counterpart = source_path
        elif counterpart is None and path in self.source.entries:
            counterpart = path

        # 3. Source map analysis
        has_valid_source_map = False
        if is_text and path.endswith(_OUTPUT_SUFFIXES):
            map_evidence, map_blockers, map_missing = _check_source_map(path, self.context)
            evidence += map_evidence
            blockers += map_blockers
            missing += map_missing
            if map_evidence:
                has_valid_source_map = True

        # 4. Gitignore and package.json files field evidence
        if path in self.profile.gitignored_directories or any(
            is_within(path, directory) for directory in self.profile.gitignored_directories
        ):
            evidence.append(
                Evidence(
                    kind=EvidenceKind.GITIGNORE,
                    detail="The repository's .gitignore excludes this path",
                    source_file=".gitignore",
                )
            )

        if _in_files_field(path, self.profile.files_field):
            evidence.append(
                Evidence(
                    kind=EvidenceKind.FILES_FIELD,
                    detail="The repository's package.json publishes this path",
                    source_file="package.json",
                )
            )

        # 5. Content similarity and minification detection
        file_bytes = self.package.read(path, self.limits.max_diff_file_bytes) if is_text else None
        similarity: float | None = None
        if is_text and counterpart is not None:
            similarity = self._compute_similarity(path, counterpart, file_bytes)
            if similarity is not None and similarity >= 0.85:
                evidence.append(
                    Evidence(
                        kind=EvidenceKind.CONTENT_SIMILARITY,
                        detail=f"Content similarity of {similarity:.1%} with source {counterpart}",
                        source_file=counterpart,
                    )
                )

        is_minified = self._detect_minification(path, file_bytes)

        # 6. Identify Artifact Type
        artifact_type = self._identify_artifact_type(
            path=path,
            entry=entry,
            outputs=outputs,
            counterpart=counterpart,
            is_minified=is_minified,
            has_source_map=has_valid_source_map,
        )

        # 7. Check for affirmative SUSPICIOUS indicators
        suspicious_reasons = self._check_suspicious_indicators(
            path=path,
            entry=entry,
            counterpart=counterpart,
            outputs=outputs,
            file_bytes=file_bytes,
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
                EvidenceKind.CONTENT_SIMILARITY,
            }
        )
        if has_pipeline and not has_relationship:
            missing.append("Nothing connects this particular file to the repository's source")

        # 8. Classification determination
        classification: GeneratedClassification
        confidence: float
        explanation: str

        if suspicious_reasons:
            classification = GeneratedClassification.SUSPICIOUS
            for reason in suspicious_reasons:
                evidence.append(
                    Evidence(
                        kind=EvidenceKind.SUSPICIOUS_INDICATOR,
                        detail=reason,
                        source_file=path,
                    )
                )
            confidence = 0.90 if len(suspicious_reasons) > 1 else 0.85
            explanation = f"Suspicious artifact: {'; '.join(suspicious_reasons)}"
        elif has_pipeline and has_relationship and not blockers:
            classification = GeneratedClassification.LIKELY_GENERATED
            confidence = self._compute_likely_confidence(
                counterpart=counterpart,
                declared_file=declared_file,
                has_source_map=has_valid_source_map,
                similarity=similarity,
            )
            explanation = self._build_likely_explanation(
                path=path,
                artifact_type=artifact_type,
                outputs=outputs,
                counterpart=counterpart,
                declared_file=declared_file,
                has_source_map=has_valid_source_map,
            )
        else:
            classification = GeneratedClassification.UNCERTAIN
            confidence = 0.65 if has_pipeline else 0.45
            explanation = self._build_uncertain_explanation(
                path=path,
                has_pipeline=has_pipeline,
                outputs=outputs,
                blockers=blockers,
                missing=missing,
            )

        return GeneratedAssessment(
            classification=classification,
            explanation=explanation,
            evidence=tuple(evidence),
            confidence=confidence,
            artifact_type=artifact_type,
            content_similarity=similarity,
            blockers=tuple(blockers),
            missing=tuple(missing),
        )

    def _identify_artifact_type(
        self,
        path: str,
        entry: InventoryEntry,
        outputs: list[BuildOutput],
        counterpart: str | None,
        is_minified: bool,
        has_source_map: bool,
    ) -> ArtifactType:
        """Categorize the artifact into COMPILED, BUNDLED, MINIFIED, etc."""
        if path.endswith(_SOURCE_MAP_SUFFIXES):
            return ArtifactType.SOURCE_MAP
        if path.endswith(_DECLARATION_SUFFIXES):
            return ArtifactType.DECLARATION

        # Bundler tools in profile or outputs
        bundler_tools = {out.tool for out in outputs if out.tool in BUNDLERS}
        bundler_tools.update(self.profile.tools & BUNDLERS)
        is_entry_point = path in self.profile.entry_points

        if is_minified:
            return ArtifactType.MINIFIED

        if bundler_tools or is_entry_point:
            return ArtifactType.BUNDLED

        if counterpart is not None or any(out.tool in COMPILERS for out in outputs):
            return ArtifactType.COMPILED

        if outputs or path.endswith(_OUTPUT_SUFFIXES):
            return ArtifactType.GENERATED

        return ArtifactType.UNKNOWN

    def _detect_minification(self, path: str, file_bytes: bytes | None) -> bool:
        """Heuristic check for minified content."""
        if path.endswith(_MINIFIED_SUFFIXES):
            return True
        if file_bytes is None or len(file_bytes) < 150:
            return False

        try:
            text = file_bytes[:16384].decode("utf-8", errors="replace")
        except Exception:
            return False

        lines = text.splitlines()
        if not lines:
            return False

        # Extremely long lines or high character-to-line ratio indicates minification
        avg_line_length = len(text) / len(lines)
        max_line_length = max(len(line) for line in lines)
        if (len(lines) <= 3 and len(text) > 300) or avg_line_length > 140 or max_line_length > 600:
            return True

        return False

    def _compute_similarity(
        self, path: str, counterpart: str, pkg_bytes: bytes | None
    ) -> float | None:
        """Calculate content and identifier similarity with source counterpart."""
        if pkg_bytes is None or len(pkg_bytes) > self.limits.max_diff_file_bytes:
            return None
        src_bytes = self.source.read(counterpart, self.limits.max_diff_file_bytes)
        if src_bytes is None or len(src_bytes) > self.limits.max_diff_file_bytes:
            return None

        try:
            pkg_text = pkg_bytes.decode("utf-8", errors="replace")
            src_text = src_bytes.decode("utf-8", errors="replace")
        except Exception:
            return None

        # Quick ratio on text sequence
        matcher = difflib.SequenceMatcher(None, src_text, pkg_text)
        seq_ratio = matcher.quick_ratio()

        # Token set overlap for JavaScript/TypeScript identifiers
        id_pattern = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]{2,}\b")
        src_tokens = set(id_pattern.findall(src_text))
        pkg_tokens = set(id_pattern.findall(pkg_text))

        if not src_tokens:
            return round(seq_ratio, 3)

        jaccard = len(src_tokens & pkg_tokens) / len(src_tokens | pkg_tokens)
        combined = 0.5 * seq_ratio + 0.5 * jaccard
        return round(combined, 3)

    def _check_suspicious_indicators(
        self,
        path: str,
        entry: InventoryEntry,
        counterpart: str | None,
        outputs: list[BuildOutput],
        file_bytes: bytes | None,
    ) -> list[str]:
        """Check for affirmative indicators of malicious, deceptive, or untracked behavior."""
        reasons: list[str] = []

        # 1. Install script executes an untracked added file with no source counterpart
        is_named_in_install = named_in_text(path, self.install_script_text)
        has_counterpart = counterpart is not None and counterpart in self.source.entries
        is_exact_declared_file = path in self.profile.output_files

        if is_named_in_install and not has_counterpart and not is_exact_declared_file:
            reasons.append(
                "File is executed at install time by an install script but has no source "
                f"counterpart and is not declared in build configuration: {path}"
            )

        # 2. Deceptive or dangerous source map targets
        if file_bytes is not None:
            matches = _SOURCE_MAPPING_URL.findall(file_bytes)
            for raw_url in matches:
                url = raw_url.decode(errors="replace")
                if _DANGEROUS_MAP_TARGETS.search(url):
                    reasons.append(
                        "Source mapping URL points to dangerous or path-traversing location: "
                        f"{url[:100]}"
                    )

        # 3. Obfuscated packing in unlinked artifact (has no counterpart in source)
        if not has_counterpart and file_bytes is not None and len(file_bytes) >= 10:
            sample = file_bytes[:16384].decode("utf-8", errors="replace")
            for pattern in _OBFUSCATION_PATTERNS:
                if pattern.search(sample):
                    reasons.append(
                        "Obfuscated code structure detected in unlinked package artifact: "
                        f"{pattern.pattern}"
                    )
                    break

        # 4. Unexpected executable permission on library build artifact without counterpart
        if (
            entry.is_executable
            and not has_counterpart
            and path.endswith((".js", ".mjs", ".cjs", ".json", ".map", ".css"))
            and not is_within(path, "bin")
        ):
            reasons.append(
                f"Unexpected executable bit set on library JavaScript/data artifact: {path}"
            )

        return reasons

    def _compute_likely_confidence(
        self,
        counterpart: str | None,
        declared_file: BuildOutput | None,
        has_source_map: bool,
        similarity: float | None,
    ) -> float:
        """Compute confidence score for LIKELY_GENERATED files."""
        conf = 0.88
        if counterpart:
            conf += 0.05
        if declared_file:
            conf += 0.04
        if has_source_map:
            conf += 0.03
        if similarity and similarity > 0.8:
            conf += 0.02
        return min(round(conf, 2), 0.98)

    def _build_likely_explanation(
        self,
        path: str,
        artifact_type: ArtifactType,
        outputs: list[BuildOutput],
        counterpart: str | None,
        declared_file: BuildOutput | None,
        has_source_map: bool,
    ) -> str:
        """Compose human-readable explanation for LIKELY_GENERATED classification."""
        tools = (
            ", ".join(sorted({out.tool for out in outputs})) if outputs else "build configuration"
        )
        if counterpart:
            return (
                f"Likely generated {artifact_type.value.lower()} artifact compiled from "
                f"'{counterpart}' using {tools}."
            )
        if declared_file:
            return (
                f"Likely generated {artifact_type.value.lower()} artifact '{path}' explicitly "
                f"declared by {declared_file.tool} in '{declared_file.origin}'."
            )
        if has_source_map:
            return (
                f"Likely generated {artifact_type.value.lower()} artifact linked to repository "
                "sources via verified source map."
            )
        return (
            f"Likely generated {artifact_type.value.lower()} artifact matching repository "
            f"build output directory ({tools})."
        )

    def _build_uncertain_explanation(
        self,
        path: str,
        has_pipeline: bool,
        outputs: list[BuildOutput],
        blockers: list[str],
        missing: list[str],
    ) -> str:
        """Compose human-readable explanation for UNCERTAIN classification."""
        if blockers:
            return f"Uncertain: build classification blocked ({'; '.join(blockers)})."
        if has_pipeline:
            tools = ", ".join(sorted({out.tool for out in outputs}))
            return (
                f"Uncertain: file resides in build output directory declared by {tools}, "
                "but no source counterpart, entry point, or source map connects it to repository."
            )
        return (
            "Uncertain: repository declares no build output or configuration producing this file."
        )


def classify_artifact(
    path: str,
    entry: InventoryEntry,
    context: AssessmentContext,
    status: FileStatus = FileStatus.ADDED,
    source_path: str | None = None,
) -> GeneratedAssessment:
    """Classify a differing package file using ArtifactClassifier."""
    classifier = ArtifactClassifier(context)
    return classifier.classify(path, entry, status, source_path)
