import base64
import gzip
import hashlib
import io
import json
import tarfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.adapters.base import PackageMetadata, SourceRepository
from app.adapters.npm import NpmAdapter
from app.archives.extract import extract_archive
from app.archives.models import EntryKind, FileInventory
from app.comparison.build_evidence import parse_json_with_comments
from app.comparison.compare import MIN_RENAME_BYTES, compare_inventories
from app.comparison.models import (
    ComparisonLimits,
    ComparisonReport,
    DiffStatus,
    EvidenceKind,
    FileComparison,
    FileStatus,
    GeneratedAssessment,
    GeneratedClassification,
    ScopeMethod,
)
from app.comparison.service import compare_release
from app.comparison.trees import ComparisonIntegrityError, FileTree, normalize_relative
from app.config import Settings
from app.schemas.scans import Ecosystem
from app.source.github import GitHubSourceResolver, SourceNotMatchedError
from app.source.models import (
    Confidence,
    GitHubRepository,
    MatchMethod,
    MatchStatus,
    SourceMatch,
    UncertainReason,
)

COMMIT = "a" * 40
LIKELY = GeneratedClassification.LIKELY_GENERATED
UNCERTAIN = GeneratedClassification.UNCERTAIN
Files = Mapping[str, bytes | str]
LONG_TEXT = "shared content long enough to count as a rename\n"


def matched(directory: str | None = None) -> SourceMatch:
    return SourceMatch(
        status=MatchStatus.MATCHED,
        method=MatchMethod.RECORDED_COMMIT_AND_TAG,
        confidence=Confidence.HIGH,
        explanation="test",
        repository=GitHubRepository(owner="acme", name="demo"),
        directory=directory,
        commit_sha=COMMIT,
        tag="v1.0.0",
    )


def make_metadata(name: str = "demo", scripts: dict[str, str] | None = None) -> PackageMetadata:
    return PackageMetadata(
        ecosystem=Ecosystem.NPM,
        name=name,
        version="1.0.0",
        description=None,
        license=None,
        homepage=None,
        repository=SourceRepository(declared="x", url="https://github.com/acme/demo"),
        source_commit=COMMIT,
        published_at=None,
        dependencies=(),
        scripts=scripts or {},
        has_install_script=False,
        entry_points={},
        artifacts=(),
        manifest={},
    )


def inventory(
    tmp_path: Path,
    label: str,
    files: Files,
    links: Mapping[str, str] | None = None,
    modes: Mapping[str, int] | None = None,
) -> FileInventory:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, content in files.items():
            data = content.encode() if isinstance(content, str) else content
            info = tarfile.TarInfo(f"root/{name}")
            info.size = len(data)
            info.mode = (modes or {}).get(name, 0o644)
            tar.addfile(info, io.BytesIO(data))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(f"root/{name}")
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)
    archive = tmp_path / f"{label}.tgz"
    archive.write_bytes(gzip.compress(buffer.getvalue()))
    return extract_archive(archive, tmp_path / label)


def manifest(**fields: Any) -> str:
    return json.dumps({"name": "demo", "version": "1.0.0", **fields})


def compare(
    tmp_path: Path,
    package: Files,
    source: Files,
    limits: ComparisonLimits | None = None,
    metadata: PackageMetadata | None = None,
    match: SourceMatch | None = None,
    **kwargs: Any,
) -> ComparisonReport:
    return compare_inventories(
        metadata or make_metadata(),
        match or matched(),
        inventory(
            tmp_path, "package", package, kwargs.get("package_links"), kwargs.get("package_modes")
        ),
        inventory(
            tmp_path, "source", source, kwargs.get("source_links"), kwargs.get("source_modes")
        ),
        limits,
    )


def file_named(report: ComparisonReport, path: str) -> FileComparison:
    return next(item for item in report.files if item.path == path)


def assessment(report: ComparisonReport, path: str) -> GeneratedAssessment:
    generated = file_named(report, path).generated
    assert generated is not None
    return generated


def kinds(generated: GeneratedAssessment) -> set[EvidenceKind]:
    return {item.kind for item in generated.evidence}


TSC_SOURCE: dict[str, str] = {
    "package.json": manifest(scripts={"build": "tsc"}, main="dist/index.js"),
    "tsconfig.json": json.dumps({"compilerOptions": {"outDir": "dist", "rootDir": "src"}}),
    "src/index.ts": "export const a: number = 1;\n",
    "src/lib/util.ts": "export const b: number = 2;\n",
}
TSC_PUBLISHED_MANIFEST = TSC_SOURCE["package.json"]


# Detecting file differences


def test_identical_file(tmp_path: Path) -> None:
    report = compare(tmp_path, {"a.js": "same\n"}, {"a.js": "same\n"})

    item = file_named(report, "a.js")
    assert item.status is FileStatus.IDENTICAL
    assert item.generated is None
    assert item.diff.status is DiffStatus.NOT_APPLICABLE
    assert item.package is not None and item.source is not None
    assert item.package.sha256 == hashlib.sha256(b"same\n").hexdigest()
    assert item.package.sha256 == item.source.sha256
    assert report.summary.identical == 1


def test_added_text_file_has_a_diff_and_stays_uncertain(tmp_path: Path) -> None:
    report = compare(tmp_path, {"evil.js": "steal()\n"}, {"other.txt": "x"})

    item = file_named(report, "evil.js")
    assert item.status is FileStatus.ADDED
    assert item.source is None and item.source_path is None
    assert item.diff.status is DiffStatus.INCLUDED
    assert item.diff.unified is not None
    assert item.diff.unified.startswith("--- /dev/null\n+++ b/evil.js")
    assert "+steal()" in item.diff.unified
    assert item.diff.added_lines == 2
    assert assessment(report, "evil.js").classification is UNCERTAIN


def test_removed_file(tmp_path: Path) -> None:
    report = compare(tmp_path, {"a.js": "a"}, {"a.js": "a", "test/a.test.js": "t"})

    item = file_named(report, "test/a.test.js")
    assert item.status is FileStatus.REMOVED
    assert item.package is None and item.package_path is None
    assert item.generated is None
    assert item.diff.status is DiffStatus.NOT_APPLICABLE
    assert report.summary.removed == 1


def test_modified_text_file_has_hashes_and_a_diff(tmp_path: Path) -> None:
    report = compare(
        tmp_path,
        {"a.js": "one\ntwo\nfetch('https://evil.test')\n"},
        {"a.js": "one\ntwo\nthree\n"},
    )

    item = file_named(report, "a.js")
    assert item.status is FileStatus.MODIFIED
    assert item.package is not None and item.source is not None
    assert item.package.sha256 != item.source.sha256
    assert item.diff.unified is not None
    assert "--- a/a.js\n+++ b/a.js" in item.diff.unified
    assert "-three" in item.diff.unified
    assert "+fetch('https://evil.test')" in item.diff.unified
    assert (item.diff.added_lines, item.diff.removed_lines) == (1, 1)
    assert assessment(report, "a.js").classification is UNCERTAIN


def test_binary_different_has_no_text_diff(tmp_path: Path) -> None:
    report = compare(tmp_path, {"a.bin": b"\x00\x01new"}, {"a.bin": b"\x00\x01old"})

    item = file_named(report, "a.bin")
    assert item.status is FileStatus.BINARY_DIFFERENT
    assert item.diff.status is DiffStatus.NOT_TEXT
    assert item.diff.unified is None
    assert report.summary.binary_different == 1


def test_text_replaced_by_binary_is_binary_different(tmp_path: Path) -> None:
    report = compare(tmp_path, {"a.js": b"\x7fELF\x02\x01"}, {"a.js": "text\n"})

    assert file_named(report, "a.js").status is FileStatus.BINARY_DIFFERENT


def test_binary_content_past_the_sniffed_sample_is_binary_different(tmp_path: Path) -> None:
    package = b"a" * 10_000 + b"\x00binary"

    report = compare(tmp_path, {"a.js": package}, {"a.js": "a" * 20_000})

    item = file_named(report, "a.js")
    assert item.status is FileStatus.BINARY_DIFFERENT
    assert item.diff.status is DiffStatus.NOT_TEXT


def test_added_binary_is_uncertain_with_no_text_diff(tmp_path: Path) -> None:
    report = compare(tmp_path, {"native.node": b"\x7fELF\x02\x01"}, {"a": "a"})

    item = file_named(report, "native.node")
    assert item.status is FileStatus.ADDED
    assert item.diff.status is DiffStatus.NOT_TEXT
    assert assessment(report, "native.node").classification is UNCERTAIN


def test_line_ending_only_change_is_reported_but_still_modified(tmp_path: Path) -> None:
    report = compare(tmp_path, {"a.js": "x\r\ny\r\n"}, {"a.js": "x\ny\n"})

    item = file_named(report, "a.js")
    assert item.status is FileStatus.MODIFIED
    assert item.diff.only_line_endings_differ is True


def test_executable_bit_change_on_identical_content_is_evidence(tmp_path: Path) -> None:
    report = compare(
        tmp_path,
        {"a.js": "x"},
        {"a.js": "x"},
        package_modes={"a.js": 0o755},
        source_modes={"a.js": 0o644},
    )

    item = file_named(report, "a.js")
    assert item.status is FileStatus.IDENTICAL
    assert item.executable_bit_changed is True


def test_ordinary_mode_difference_is_not_a_change(tmp_path: Path) -> None:
    report = compare(
        tmp_path,
        {"a.js": "x"},
        {"a.js": "x"},
        package_modes={"a.js": 0o644},
        source_modes={"a.js": 0o664},
    )

    assert file_named(report, "a.js").executable_bit_changed is False


def test_link_replacing_a_file_is_modified_and_uncertain(tmp_path: Path) -> None:
    report = compare(
        tmp_path, {"other": "o"}, {"other": "o", "a.js": "x"}, package_links={"a.js": "/etc/passwd"}
    )

    item = file_named(report, "a.js")
    assert item.status is FileStatus.MODIFIED
    assert item.package is not None
    assert item.package.kind is EntryKind.SYMLINK
    assert item.package.link_target == "/etc/passwd"
    assert "changed from regular to symlink" in item.notes[0]
    assert assessment(report, "a.js").classification is UNCERTAIN


def test_link_is_not_identical_to_a_file_containing_its_target(tmp_path: Path) -> None:
    """A link's hash covers its target text, which a regular file could also contain."""
    report = compare(
        tmp_path,
        {"other": "o"},
        {"other": "o", "a.js": "target.js"},
        package_links={"a.js": "target.js"},
    )

    assert file_named(report, "a.js").status is FileStatus.MODIFIED


def test_files_are_sorted_and_counted(tmp_path: Path) -> None:
    report = compare(tmp_path, {"c": "c", "a": "1"}, {"a": "2", "b": "b"})

    assert [item.path for item in report.files] == ["a", "b", "c"]
    assert (report.summary.modified, report.summary.removed, report.summary.added) == (1, 1, 1)


# Renames


def test_exact_unique_hash_is_a_rename(tmp_path: Path) -> None:
    report = compare(tmp_path, {"new/name.js": LONG_TEXT}, {"old/name.js": LONG_TEXT})

    item = file_named(report, "new/name.js")
    assert item.status is FileStatus.RENAMED
    assert (item.package_path, item.source_path) == ("new/name.js", "old/name.js")
    assert report.summary.renamed == 1
    assert len(report.files) == 1


def test_similar_but_not_identical_file_is_not_a_rename(tmp_path: Path) -> None:
    report = compare(tmp_path, {"new.js": LONG_TEXT + "x"}, {"old.js": LONG_TEXT})

    assert file_named(report, "new.js").status is FileStatus.ADDED
    assert file_named(report, "old.js").status is FileStatus.REMOVED


@pytest.mark.parametrize(
    ("package", "source"),
    [
        ({"n1.js": LONG_TEXT}, {"o1.js": LONG_TEXT, "o2.js": LONG_TEXT}),
        ({"n1.js": LONG_TEXT, "n2.js": LONG_TEXT}, {"o1.js": LONG_TEXT}),
        ({"n1.js": LONG_TEXT, "n2.js": LONG_TEXT}, {"o1.js": LONG_TEXT, "o2.js": LONG_TEXT}),
    ],
)
def test_ambiguous_hash_is_not_a_rename(
    tmp_path: Path, package: dict[str, str], source: dict[str, str]
) -> None:
    report = compare(tmp_path, package, source)

    assert report.summary.renamed == 0
    assert report.summary.added == len(package)
    assert report.summary.removed == len(source)
    assert "no rename could be proven" in file_named(report, "n1.js").notes[0]


def test_short_file_is_not_a_rename(tmp_path: Path) -> None:
    text = "x" * (MIN_RENAME_BYTES - 1)

    report = compare(tmp_path, {"new.js": text}, {"old.js": text})

    assert report.summary.renamed == 0


def test_empty_files_are_not_renames(tmp_path: Path) -> None:
    report = compare(tmp_path, {"new.js": ""}, {"old.js": ""})

    assert report.summary.renamed == 0


# Legitimate build output


def test_tsc_output_with_a_source_counterpart_is_likely_generated(tmp_path: Path) -> None:
    report = compare(
        tmp_path,
        {
            "package.json": TSC_PUBLISHED_MANIFEST,
            "dist/index.js": "exports.a = 1;\n",
            "dist/index.d.ts": "export declare const a: number;\n",
            "dist/lib/util.js": "exports.b = 2;\n",
        },
        TSC_SOURCE,
    )

    for path in ("dist/index.js", "dist/index.d.ts", "dist/lib/util.js"):
        generated = assessment(report, path)
        assert generated.classification is LIKELY, path
        assert kinds(generated) >= {EvidenceKind.OUTPUT_DIRECTORY, EvidenceKind.SOURCE_COUNTERPART}
    assert "tsc" in report.build.tools
    assert report.build.output_directories == ("dist",)
    counterpart = next(
        item
        for item in assessment(report, "dist/lib/util.js").evidence
        if item.kind is EvidenceKind.SOURCE_COUNTERPART
    )
    assert counterpart.source_file == "src/lib/util.ts"


def test_tsc_outdir_from_flag(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"build": "tsc --outDir out --rootDir src"}),
        "src/a.ts": "x",
    }

    report = compare(tmp_path, {"out/a.js": "x"}, source)

    assert assessment(report, "out/a.js").classification is LIKELY


def test_tsconfig_comments_extends_and_project_flag(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"compile": "tsc -p tsconfig.build.json"}),
        "tsconfig.base.json": (
            '{ "compilerOptions": { "outDir": "built", /* c */ "rootDir": "src", } }'
        ),
        "tsconfig.build.json": '// comment\n{ "extends": "./tsconfig.base.json", }',
        "src/a.ts": "x",
    }

    report = compare(tmp_path, {"built/a.js": "x"}, source)

    assert assessment(report, "built/a.js").classification is LIKELY


def test_tsc_with_no_outdir_writes_beside_each_source(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"build": "tsc"}),
        "tsconfig.json": "{}",
        "lib/a.ts": "x",
    }

    report = compare(tmp_path, {"lib/a.js": "x", "lib/evil.js": "y"}, source)

    assert assessment(report, "lib/a.js").classification is LIKELY
    assert assessment(report, "lib/evil.js").classification is UNCERTAIN


def test_babel_output_with_a_source_counterpart(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"build": "babel src --out-dir lib"}),
        "src/a.js": "const a = 1;\n",
    }

    report = compare(tmp_path, {"lib/a.js": "var a = 1;\n"}, source)

    assert assessment(report, "lib/a.js").classification is LIKELY


def test_build_script_followed_through_npm_run(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(
            scripts={
                "prepublishOnly": "npm run clean && npm run build:js",
                "clean": "rm -rf dist",
                "build:js": "cross-env NODE_ENV=production npx tsc --outDir dist",
            }
        ),
        "src/a.ts": "x",
    }

    report = compare(tmp_path, {"dist/a.js": "x"}, source)

    assert assessment(report, "dist/a.js").classification is LIKELY


def test_bundler_output_named_as_the_source_entry_point(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"build": "tsup"}, main="./dist/index.js"),
        "src/index.ts": "x",
    }

    report = compare(tmp_path, {"dist/index.js": "bundle", "dist/other.js": "y"}, source)

    generated = assessment(report, "dist/index.js")
    assert generated.classification is LIKELY
    assert EvidenceKind.SOURCE_ENTRY_POINT in kinds(generated)
    assert assessment(report, "dist/other.js").classification is UNCERTAIN


def test_bundler_entry_point_from_conditional_exports(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(
            scripts={"build": "vite build"},
            exports={".": {"import": "./dist/a.mjs", "require": "./dist/a.cjs"}},
        ),
    }

    report = compare(tmp_path, {"dist/a.mjs": "x", "dist/a.cjs": "y"}, source)

    assert assessment(report, "dist/a.mjs").classification is LIKELY
    assert assessment(report, "dist/a.cjs").classification is LIKELY


def test_rollup_config_declares_the_exact_output_file(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"build": "rollup -c"}),
        "rollup.config.mjs": "export default { output: { file: 'out/bundle.js', format: 'cjs' } };",
    }

    report = compare(tmp_path, {"out/bundle.js": "bundle", "out/extra.js": "x"}, source)

    assert assessment(report, "out/bundle.js").classification is LIKELY
    assert assessment(report, "out/extra.js").classification is UNCERTAIN


def test_webpack_config_output_path_and_filename(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"build": "webpack --mode production"}),
        "webpack.config.js": (
            "module.exports = { output: "
            "{ path: path.resolve(__dirname, 'public'), filename: 'app.js' } };"
        ),
    }

    report = compare(tmp_path, {"public/app.js": "x", "public/evil.js": "y"}, source)

    assert report.build.output_directories == ("public",)
    assert assessment(report, "public/app.js").classification is LIKELY
    assert assessment(report, "public/evil.js").classification is UNCERTAIN


def test_esbuild_outfile_flag(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"build": "esbuild src/a.ts --bundle --outfile=out/a.js"}),
        "src/a.ts": "x",
    }

    report = compare(tmp_path, {"out/a.js": "x"}, source)

    assert assessment(report, "out/a.js").classification is LIKELY


def _map(sources: list[str], **fields: Any) -> str:
    return json.dumps({"version": 3, "sources": sources, "mappings": "AAAA", **fields})


def test_source_map_ties_a_chunk_to_repository_files(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"build": "vite build"}),
        "src/a.ts": "const a = 1;\n",
    }
    package = {
        "dist/chunk-abc.js": "x\n//# sourceMappingURL=chunk-abc.js.map\n",
        "dist/chunk-abc.js.map": _map(
            ["../src/a.ts", "../node_modules/dep/index.js"],
            sourcesContent=["const a = 1;\n", "dep"],
        ),
    }

    report = compare(tmp_path, package, source)

    for path in package:
        generated = assessment(report, path)
        assert generated.classification is LIKELY, path
        assert EvidenceKind.SOURCE_MAP in kinds(generated)


def test_bundler_url_source_map_and_source_root(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"build": "webpack"}),
        "src/a.ts": "x",
        "src/b.ts": "y",
    }
    package = {
        "dist/a.js": "x\n//# sourceMappingURL=a.js.map",
        "dist/a.js.map": _map(["webpack://demo/./src/a.ts", "webpack/bootstrap"]),
        "dist/b.js": "y\n//# sourceMappingURL=b.js.map",
        "dist/b.js.map": _map(["b.ts"], sourceRoot="../src"),
    }

    report = compare(tmp_path, package, source)

    assert assessment(report, "dist/a.js").classification is LIKELY
    assert assessment(report, "dist/b.js").classification is LIKELY


def test_inline_source_map(tmp_path: Path) -> None:
    source = {"package.json": manifest(scripts={"build": "vite build"}), "src/a.ts": "x"}
    encoded = base64.b64encode(_map(["../src/a.ts"]).encode()).decode()

    report = compare(
        tmp_path,
        {"dist/a.js": f"x\n//# sourceMappingURL=data:application/json;base64,{encoded}"},
        source,
    )

    assert assessment(report, "dist/a.js").classification is LIKELY


def test_generated_file_that_differs_from_a_committed_copy_is_still_assessed(
    tmp_path: Path,
) -> None:
    source = {**TSC_SOURCE, "dist/index.js": "old build\n"}

    report = compare(tmp_path, {"dist/index.js": "new build\n"}, source)

    item = file_named(report, "dist/index.js")
    assert item.status is FileStatus.MODIFIED
    assert assessment(report, "dist/index.js").classification is LIKELY


def test_gitignore_and_files_field_are_recorded_as_support(tmp_path: Path) -> None:
    source = {
        **TSC_SOURCE,
        "package.json": manifest(scripts={"build": "tsc"}, files=["dist"]),
        ".gitignore": "node_modules\n/dist/\n",
    }

    report = compare(tmp_path, {"dist/index.js": "x"}, source)

    assert kinds(assessment(report, "dist/index.js")) >= {
        EvidenceKind.GITIGNORE,
        EvidenceKind.FILES_FIELD,
    }


# Unexpected additions must not pass as build output


@pytest.mark.parametrize("directory", ["dist", "build", "lib", "out", "bundle"])
def test_output_named_directory_alone_is_never_evidence(tmp_path: Path, directory: str) -> None:
    source = {"package.json": manifest(scripts={"test": "jest"}), "src/a.ts": "x"}

    report = compare(tmp_path, {f"{directory}/a.js": "steal()"}, source)

    generated = assessment(report, f"{directory}/a.js")
    assert generated.classification is UNCERTAIN
    assert generated.evidence == ()
    assert "no build output" in generated.missing[0]


def test_extra_file_in_a_real_output_directory_stays_uncertain(tmp_path: Path) -> None:
    report = compare(tmp_path, {"dist/index.js": "ok", "dist/evil.js": "steal()"}, TSC_SOURCE)

    assert assessment(report, "dist/index.js").classification is LIKELY
    generated = assessment(report, "dist/evil.js")
    assert generated.classification is UNCERTAIN
    assert EvidenceKind.OUTPUT_DIRECTORY in kinds(generated)
    assert "Nothing connects" in generated.missing[-1]


def test_build_config_in_the_package_cannot_vouch_for_itself(tmp_path: Path) -> None:
    """A publisher controls the package, so only the repository's config counts."""
    package = {
        "package.json": manifest(scripts={"build": "tsc"}),
        "tsconfig.json": json.dumps({"compilerOptions": {"outDir": "dist", "rootDir": "src"}}),
        "src/evil.ts": "steal()",
        "dist/evil.js": "steal()",
    }
    source = {"package.json": manifest(scripts={"test": "jest"})}

    report = compare(tmp_path, package, source)

    assert assessment(report, "dist/evil.js").classification is UNCERTAIN
    assert report.build.tools == ()


def test_published_entry_point_cannot_vouch_for_itself(tmp_path: Path) -> None:
    source = {"package.json": manifest(scripts={"build": "tsup"}, main="dist/index.js")}
    package = {"package.json": manifest(main="dist/evil.js"), "dist/evil.js": "steal()"}

    report = compare(tmp_path, package, source)

    assert assessment(report, "dist/evil.js").classification is UNCERTAIN


def test_valid_source_map_without_a_declared_build_stays_uncertain(tmp_path: Path) -> None:
    """A publisher can write a source map, so it cannot stand in for a declared build."""
    source = {"package.json": manifest(scripts={"test": "jest"}), "src/a.ts": "x"}
    package = {
        "dist/a.js": "steal()\n//# sourceMappingURL=a.js.map\n",
        "dist/a.js.map": _map(["../src/a.ts"]),
    }

    generated = assessment(compare(tmp_path, package, source), "dist/a.js")

    assert generated.classification is UNCERTAIN
    assert EvidenceKind.SOURCE_MAP in kinds(generated)


def test_source_root_of_another_tool_does_not_count(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(
            scripts={"build": "babel src --out-dir lib && tsc --outDir dist --rootDir types"}
        ),
        "src/a.ts": "x",
    }

    report = compare(tmp_path, {"dist/a.js": "steal()", "lib/a.js": "x"}, source)

    assert assessment(report, "lib/a.js").classification is LIKELY
    assert assessment(report, "dist/a.js").classification is UNCERTAIN


def test_source_file_alone_without_a_build_is_not_evidence(tmp_path: Path) -> None:
    source = {"package.json": manifest(), "src/a.ts": "x"}

    report = compare(tmp_path, {"dist/a.js": "x"}, source)

    assert assessment(report, "dist/a.js").classification is UNCERTAIN


def test_type_check_only_tsc_produces_no_evidence(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"build": "tsc --noEmit"}),
        "tsconfig.json": json.dumps({"compilerOptions": {"outDir": "dist", "rootDir": "src"}}),
        "src/a.ts": "x",
    }

    report = compare(tmp_path, {"dist/a.js": "x"}, source)

    assert assessment(report, "dist/a.js").classification is UNCERTAIN
    assert report.build.tools == ()


def test_noemit_in_tsconfig_produces_no_evidence(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"build": "tsc"}),
        "tsconfig.json": json.dumps(
            {"compilerOptions": {"noEmit": True, "outDir": "dist", "rootDir": "src"}}
        ),
        "src/a.ts": "x",
    }

    report = compare(tmp_path, {"dist/a.js": "x"}, source)

    assert assessment(report, "dist/a.js").classification is UNCERTAIN


def test_non_build_scripts_are_ignored(tmp_path: Path) -> None:
    source = {"package.json": manifest(scripts={"test": "tsc --outDir dist"}), "src/a.ts": "x"}

    report = compare(tmp_path, {"dist/a.js": "x"}, source)

    assert assessment(report, "dist/a.js").classification is UNCERTAIN


def test_custom_build_script_is_reported_but_not_trusted(tmp_path: Path) -> None:
    source = {"package.json": manifest(scripts={"build": "node scripts/build.js"}), "src/a.js": "x"}

    report = compare(tmp_path, {"dist/a.js": "x"}, source)

    assert assessment(report, "dist/a.js").classification is UNCERTAIN
    assert report.build.unrecognized_build_commands == ("node scripts/build.js",)


@pytest.mark.parametrize("out_dir", [".", "./", "../outside", "/abs", ""])
def test_output_directory_cannot_be_the_root_or_outside_it(tmp_path: Path, out_dir: str) -> None:
    source = {
        "package.json": manifest(scripts={"build": "tsc"}),
        "tsconfig.json": json.dumps({"compilerOptions": {"outDir": out_dir, "rootDir": "src"}}),
        "src/evil.ts": "x",
        "src/other.ts": "y",
    }

    report = compare(tmp_path, {"evil.js": "steal()"}, source)

    assert assessment(report, "evil.js").classification is UNCERTAIN


def test_source_counterpart_outside_the_compiler_root_does_not_count(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"build": "tsc"}),
        "tsconfig.json": json.dumps({"compilerOptions": {"outDir": "dist", "rootDir": "src"}}),
        "test/evil.ts": "x",
    }

    report = compare(tmp_path, {"dist/evil.js": "steal()"}, source)

    assert assessment(report, "dist/evil.js").classification is UNCERTAIN


@pytest.mark.parametrize(
    "name",
    ["dist/install.sh", "dist/payload.py", "dist/evil.exe", "dist/index.json", "dist/index.txt"],
)
def test_unexpected_file_type_in_output_directory_is_blocked(tmp_path: Path, name: str) -> None:
    stem = Path(name).stem
    source = {**TSC_SOURCE, f"src/{stem}.ts": "x"}

    report = compare(tmp_path, {name: "steal()"}, source)

    generated = assessment(report, name)
    assert generated.classification is UNCERTAIN
    assert any("not an expected output" in blocker for blocker in generated.blockers)


@pytest.mark.parametrize(
    "content",
    [b"\x7fELF\x02\x01\x01", b"\xcf\xfa\xed\xfe", b"MZ\x90\x00", b"\x00asm\x01", b"\x00\x01\x02"],
    ids=["elf", "mach-o", "pe", "wasm", "binary"],
)
def test_binary_in_output_directory_is_blocked_despite_other_evidence(
    tmp_path: Path, content: bytes
) -> None:
    """A .js name, a counterpart and an output directory do not excuse binary content."""
    report = compare(tmp_path, {"dist/index.js": content}, TSC_SOURCE)

    generated = assessment(report, "dist/index.js")
    assert generated.classification is UNCERTAIN
    assert any("Binary content" in blocker for blocker in generated.blockers)


@pytest.mark.parametrize(
    "script", ["node dist/index.js", 'node "dist/index.js"', "node ./dist/index.js"]
)
def test_file_run_by_an_install_script_is_blocked(tmp_path: Path, script: str) -> None:
    report = compare(
        tmp_path,
        {"dist/index.js": "x"},
        TSC_SOURCE,
        metadata=make_metadata(scripts={"postinstall": script}),
    )

    generated = assessment(report, "dist/index.js")
    assert generated.classification is UNCERTAIN
    assert any("install script" in blocker for blocker in generated.blockers)


def test_install_script_only_in_the_tarball_still_blocks(tmp_path: Path) -> None:
    """The registry's metadata and the tarball's package.json can disagree."""
    report = compare(
        tmp_path,
        {
            "package.json": manifest(scripts={"preinstall": "node dist/index.js"}),
            "dist/index.js": "x",
        },
        TSC_SOURCE,
    )

    assert assessment(report, "dist/index.js").classification is UNCERTAIN


@pytest.mark.parametrize(
    "payload", [b"\x00\x7fELF payload", b"\xc3\x28 invalid utf-8"], ids=["nul", "invalid-utf8"]
)
def test_binary_payload_after_a_text_start_is_blocked(tmp_path: Path, payload: bytes) -> None:
    """The inventory's content type samples only the start, so this file looks like text."""
    content = b"exports.a = 1;\n" * 1000 + payload

    report = compare(tmp_path, {"dist/index.js": content}, TSC_SOURCE)

    generated = assessment(report, "dist/index.js")
    assert generated.classification is UNCERTAIN
    assert any("after the start" in blocker for blocker in generated.blockers)


def test_text_too_large_to_check_is_blocked(tmp_path: Path) -> None:
    report = compare(
        tmp_path,
        {"dist/index.js": "x" * 200},
        TSC_SOURCE,
        ComparisonLimits(max_source_map_bytes=100),
    )

    generated = assessment(report, "dist/index.js")
    assert generated.classification is UNCERTAIN
    assert any("too large" in blocker for blocker in generated.blockers)


def test_unrelated_install_script_does_not_block(tmp_path: Path) -> None:
    report = compare(
        tmp_path,
        {"dist/index.js": "x"},
        TSC_SOURCE,
        metadata=make_metadata(scripts={"postinstall": "node dist/index.js.other"}),
    )

    assert assessment(report, "dist/index.js").classification is LIKELY


def test_source_map_embedding_different_source_is_blocked(tmp_path: Path) -> None:
    """Even with a real counterpart, this file admits it was not built from the repository."""
    package = {
        "dist/index.js": "steal()\n//# sourceMappingURL=index.js.map\n",
        "dist/index.js.map": _map(["../src/index.ts"], sourcesContent=["steal();\n"]),
    }

    report = compare(tmp_path, package, TSC_SOURCE)

    generated = assessment(report, "dist/index.js")
    assert generated.classification is UNCERTAIN
    assert any("embeds different content" in blocker for blocker in generated.blockers)


@pytest.mark.parametrize(
    "sources",
    [
        ["../src/missing.ts"],
        ["../../../etc/passwd"],
        ["/abs/src/a.ts"],
        ["https://evil.test/a.ts"],
        ["../node_modules/dep/index.js"],
        [],
    ],
    ids=["missing", "escape", "absolute", "url", "external-only", "empty"],
)
def test_source_map_not_resolving_to_the_repository_is_no_evidence(
    tmp_path: Path, sources: list[str]
) -> None:
    source = {"package.json": manifest(scripts={"build": "vite build"}), "src/a.ts": "x"}
    package = {
        "dist/chunk.js": "x\n//# sourceMappingURL=chunk.js.map\n",
        "dist/chunk.js.map": _map(sources),
    }

    report = compare(tmp_path, package, source)

    generated = assessment(report, "dist/chunk.js")
    assert generated.classification is UNCERTAIN
    assert EvidenceKind.SOURCE_MAP not in kinds(generated)


def test_one_unresolved_map_source_voids_the_map(tmp_path: Path) -> None:
    source = {"package.json": manifest(scripts={"build": "vite build"}), "src/a.ts": "x"}
    package = {
        "dist/chunk.js": "x\n//# sourceMappingURL=chunk.js.map\n",
        "dist/chunk.js.map": _map(["../src/a.ts", "../injected/evil.ts"]),
    }

    assert (
        assessment(compare(tmp_path, package, source), "dist/chunk.js").classification is UNCERTAIN
    )


@pytest.mark.parametrize(
    "content", ["{broken", "[1,2]", '{"sources":"x"}', '{"sources":[1]}', "[" * 100_000]
)
def test_malformed_source_map_is_no_evidence(tmp_path: Path, content: str) -> None:
    source = {"package.json": manifest(scripts={"build": "vite build"})}
    package = {"dist/a.js": "x\n//# sourceMappingURL=a.js.map\n", "dist/a.js.map": content}

    assert assessment(compare(tmp_path, package, source), "dist/a.js").classification is UNCERTAIN


def test_source_map_url_cannot_read_outside_the_package(tmp_path: Path) -> None:
    source = {"package.json": manifest(scripts={"build": "vite build"}), "src/a.ts": "x"}
    package = {"dist/a.js": "x\n//# sourceMappingURL=../../source/secret.map\n"}

    assert assessment(compare(tmp_path, package, source), "dist/a.js").classification is UNCERTAIN


@pytest.mark.parametrize(
    "package_json",
    [
        "{broken",
        "[]",
        '{"scripts": "tsc"}',
        '{"scripts": {"build": 5}}',
        '{"scripts": {"build": "tsc \'"}}',
    ],
)
def test_malformed_repository_manifest_gives_no_evidence(tmp_path: Path, package_json: str) -> None:
    report = compare(tmp_path, {"dist/a.js": "x"}, {"package.json": package_json, "src/a.ts": "x"})

    assert assessment(report, "dist/a.js").classification is UNCERTAIN


def test_malformed_tsconfig_gives_no_output_directory(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"build": "tsc"}),
        "tsconfig.json": "{not json",
        "src/a.ts": "x",
    }

    assert (
        assessment(compare(tmp_path, {"dist/a.js": "x"}, source), "dist/a.js").classification
        is UNCERTAIN
    )


def test_tsconfig_extends_cycle_terminates(tmp_path: Path) -> None:
    source = {
        "package.json": manifest(scripts={"build": "tsc"}),
        "tsconfig.json": '{"extends": "./tsconfig.other.json"}',
        "tsconfig.other.json": '{"extends": "./tsconfig.json"}',
    }

    report = compare(tmp_path, {"a.js": "x"}, source)

    assert assessment(report, "a.js").classification is UNCERTAIN


def test_tsconfig_link_is_not_followed(tmp_path: Path) -> None:
    source = {"package.json": manifest(scripts={"build": "tsc"}), "src/a.ts": "x"}

    report = compare(
        tmp_path, {"dist/a.js": "x"}, source, source_links={"tsconfig.json": "/etc/passwd"}
    )

    assert assessment(report, "dist/a.js").classification is UNCERTAIN


def test_likely_generated_without_support_cannot_be_constructed() -> None:
    with pytest.raises(ValueError, match="LIKELY_GENERATED"):
        GeneratedAssessment(classification=LIKELY)


def test_scripts_are_read_and_never_run(tmp_path: Path) -> None:
    sentinel = tmp_path / "ran"
    source = {
        "package.json": manifest(scripts={"build": f"touch {sentinel} && tsc --outDir dist"}),
        "webpack.config.js": f"require('fs').writeFileSync('{sentinel}', 'x')",
        "src/a.ts": "x",
    }

    compare(tmp_path, {"dist/a.js": "x"}, source)

    assert not sentinel.exists()


# Repository scope


def test_declared_directory_limits_the_comparison(tmp_path: Path) -> None:
    source = {
        "package.json": json.dumps({"name": "monorepo"}),
        "packages/demo/package.json": manifest(),
        "packages/demo/a.js": "a",
        "packages/other/b.js": "b",
    }

    report = compare(tmp_path, {"a.js": "a"}, source, match=matched("packages/demo"))

    assert report.scope.directory == "packages/demo"
    assert report.scope.method is ScopeMethod.DECLARED_DIRECTORY
    assert report.scope.manifest_name_matches is True
    assert file_named(report, "a.js").status is FileStatus.IDENTICAL
    assert {item.path for item in report.files} == {"a.js", "package.json"}


def test_build_config_is_read_from_the_package_directory(tmp_path: Path) -> None:
    source = {
        "package.json": json.dumps({"name": "monorepo"}),
        "tsconfig.base.json": json.dumps({"compilerOptions": {"rootDir": "packages/demo/src"}}),
        "packages/demo/package.json": manifest(scripts={"build": "tsc"}),
        "packages/demo/tsconfig.json": json.dumps(
            {"extends": "../../tsconfig.base.json", "compilerOptions": {"outDir": "dist"}}
        ),
        "packages/demo/src/a.ts": "x",
    }

    report = compare(tmp_path, {"dist/a.js": "x"}, source, match=matched("packages/demo"))

    assert assessment(report, "dist/a.js").classification is LIKELY


def test_package_is_located_by_its_manifest_name(tmp_path: Path) -> None:
    source = {
        "package.json": json.dumps({"name": "monorepo"}),
        "packages/demo/package.json": manifest(),
        "packages/other/package.json": json.dumps({"name": "other"}),
    }

    report = compare(tmp_path, {"package.json": manifest()}, source)

    assert report.scope.directory == "packages/demo"
    assert report.scope.method is ScopeMethod.MANIFEST_SEARCH
    assert any("Located the package" in warning for warning in report.warnings)


def test_ambiguous_package_location_is_reported(tmp_path: Path) -> None:
    source = {
        "a/package.json": manifest(),
        "b/package.json": manifest(),
    }

    report = compare(tmp_path, {"x.js": "x"}, source)

    assert report.scope.method is ScopeMethod.UNRESOLVED
    assert any("Could not tell" in warning for warning in report.warnings)


def test_missing_declared_directory_is_reported(tmp_path: Path) -> None:
    report = compare(
        tmp_path,
        {"package.json": manifest()},
        {"package.json": manifest()},
        match=matched("packages/gone"),
    )

    assert report.scope.method is ScopeMethod.REPOSITORY_ROOT
    assert any("not in the repository" in warning for warning in report.warnings)


@pytest.mark.parametrize("directory", ["../outside", "/abs"])
def test_escaping_declared_directory_is_refused(tmp_path: Path, directory: str) -> None:
    report = compare(
        tmp_path,
        {"package.json": manifest()},
        {"package.json": manifest()},
        match=matched(directory),
    )

    assert report.scope.directory == ""
    assert any("not in the repository" in warning for warning in report.warnings)


def test_version_disagreement_at_the_commit_is_a_warning(tmp_path: Path) -> None:
    report = compare(
        tmp_path,
        {"a": "a"},
        {"package.json": json.dumps({"name": "demo", "version": "0.9.0"})},
    )

    assert report.scope.manifest_version_matches is False
    assert any("0.9.0" in warning for warning in report.warnings)


# Refusing to compare without a match


def test_uncertain_match_cannot_be_compared(tmp_path: Path) -> None:
    uncertain = SourceMatch(
        status=MatchStatus.UNCERTAIN,
        reason=UncertainReason.NO_MATCHING_TAG,
        explanation="no tag",
    )

    with pytest.raises(SourceNotMatchedError):
        compare(tmp_path, {"a": "a"}, {"a": "a"}, match=uncertain)


# Limits and integrity


def test_file_over_the_diff_limit_keeps_hashes_without_a_diff(tmp_path: Path) -> None:
    report = compare(
        tmp_path,
        {"a.js": "a" * 200},
        {"a.js": "b" * 200},
        ComparisonLimits(max_diff_file_bytes=100),
    )

    item = file_named(report, "a.js")
    assert item.status is FileStatus.MODIFIED
    assert item.diff.status is DiffStatus.TOO_LARGE
    assert item.diff.unified is None
    assert item.package is not None and item.package.sha256 is not None


def test_too_many_lines_skips_the_diff(tmp_path: Path) -> None:
    report = compare(
        tmp_path, {"a.js": "x\n" * 50}, {"a.js": "y\n" * 50}, ComparisonLimits(max_diff_lines=10)
    )

    assert file_named(report, "a.js").diff.status is DiffStatus.TOO_LARGE


def test_long_diff_is_truncated_and_says_so(tmp_path: Path) -> None:
    report = compare(
        tmp_path,
        {"a.js": "x\n" * 500},
        {"a.js": "y\n" * 500},
        ComparisonLimits(max_diff_output_bytes=200),
    )

    diff = file_named(report, "a.js").diff
    assert diff.status is DiffStatus.TRUNCATED
    assert diff.unified is not None and len(diff.unified) <= 200
    assert diff.added_lines is None


def test_total_diff_budget_reaches_unexplained_files_first(tmp_path: Path) -> None:
    package = {
        "dist/index.js": "generated\n" * 50,
        "zz-evil.js": "steal()\n",
    }

    report = compare(tmp_path, package, TSC_SOURCE, ComparisonLimits(max_total_diff_bytes=40))

    assert file_named(report, "zz-evil.js").diff.status is DiffStatus.INCLUDED
    assert file_named(report, "dist/index.js").diff.status is DiffStatus.BUDGET_EXHAUSTED


def test_worst_case_diff_finishes_in_reasonable_time(tmp_path: Path) -> None:
    limit = ComparisonLimits.max_diff_lines - 1
    package = "\n".join(f"package line {index}" for index in range(limit))
    source = "\n".join(f"source line {index}" for index in range(limit))
    started = time.monotonic()

    report = compare(tmp_path, {"a.js": package}, {"a.js": source})

    assert time.monotonic() - started < 30
    assert file_named(report, "a.js").diff.status is DiffStatus.TRUNCATED


def test_changed_extracted_file_is_detected(tmp_path: Path) -> None:
    extracted = inventory(tmp_path, "x", {"a.js": "original"})
    (extracted.root / "a.js").write_text("tampered")

    with pytest.raises(ComparisonIntegrityError):
        FileTree(extracted).read("a.js", 1000)


def test_link_swapped_into_extraction_is_not_followed(tmp_path: Path) -> None:
    extracted = inventory(tmp_path, "x", {"a.js": "original"})
    (extracted.root / "a.js").unlink()
    (extracted.root / "a.js").symlink_to("/etc/passwd")

    with pytest.raises(OSError):
        FileTree(extracted).read("a.js", 1000)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("dist", "dist"),
        ("./dist/", "dist"),
        ("a/../b", "b"),
        (".", ""),
        ("", None),
        ("..", None),
        ("../a", None),
        ("a/../../b", None),
        ("/abs", None),
        ("..\\a", None),
    ],
)
def test_normalize_relative(path: str, expected: str | None) -> None:
    assert normalize_relative(path) == expected


def test_jsonc_parser_keeps_comment_like_text_in_strings() -> None:
    parsed = parse_json_with_comments(
        '{"a": "http://x /* y */", /* gone */ "b": ["c,]",], // gone\n}'
    )

    assert parsed == {"a": "http://x /* y */", "b": ["c,]"]}


# JSON output


def test_report_is_structured_json(tmp_path: Path) -> None:
    report = compare(
        tmp_path,
        {"dist/index.js": "ok\n", "evil.js": "steal()\n", "a.bin": b"\x00new"},
        {**TSC_SOURCE, "a.bin": b"\x00old"},
    )

    decoded = json.loads(report.model_dump_json())

    assert decoded["package_name"] == "demo"
    assert decoded["source_match"]["commit_sha"] == COMMIT
    assert decoded["summary"]["likely_generated"] == 1
    by_path = {item["path"]: item for item in decoded["files"]}
    assert by_path["a.bin"]["status"] == "BINARY_DIFFERENT"
    assert by_path["dist/index.js"]["generated"]["classification"] == "LIKELY_GENERATED"
    assert by_path["evil.js"]["generated"]["classification"] == "UNCERTAIN"
    assert by_path["evil.js"]["package"]["sha256"]
    assert "+steal()" in by_path["evil.js"]["diff"]["unified"]
    assert by_path["src/index.ts"]["status"] == "REMOVED"


def test_report_is_deterministic(tmp_path: Path) -> None:
    package = {"b.js": "2", "a.js": "1", "dist/index.js": "x"}
    source = dict(TSC_SOURCE) | {"a.js": "other"}

    (tmp_path / "1").mkdir()
    (tmp_path / "2").mkdir()
    first = compare(tmp_path / "1", package, source)
    second = compare(tmp_path / "2", package, source)

    assert first.model_dump_json() == second.model_dump_json()


def test_settings_build_comparison_limits() -> None:
    limits = Settings(comparison_max_diff_lines=9).comparison_limits()

    assert limits.max_diff_lines == 9


# End to end through the existing services


def _tar_gz(root: str, files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _packet(text: bytes) -> bytes:
    return f"{len(text) + 4:04x}".encode() + text


@pytest.mark.anyio
async def test_compare_release_runs_the_whole_pipeline(tmp_path: Path) -> None:
    source_files = {name: content.encode() for name, content in TSC_SOURCE.items()}
    tarball = _tar_gz(
        "package",
        {
            "package.json": source_files["package.json"],
            "dist/index.js": b"exports.a = 1;\n",
            "dist/evil.js": b"steal()\n",
        },
    )
    digest = hashlib.sha1(tarball, usedforsecurity=False).hexdigest()
    tarball_url = "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"
    document = {
        "versions": {
            "1.0.0": {
                "name": "demo",
                "version": "1.0.0",
                "gitHead": COMMIT,
                "repository": {"url": "git+https://github.com/acme/demo.git"},
                "dist": {"tarball": tarball_url, "shasum": digest},
            }
        }
    }
    refs = (
        _packet(b"# service=git-upload-pack\n")
        + b"0000"
        + _packet(f"{COMMIT} refs/tags/v1.0.0\n".encode())
        + b"0000"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == tarball_url:
            return httpx.Response(200, stream=httpx.ByteStream(tarball))
        if url == "https://registry.npmjs.org/demo":
            return httpx.Response(200, json=document)
        if request.url.host == "github.com":
            return httpx.Response(200, content=refs)
        assert url == f"https://codeload.github.com/acme/demo/tar.gz/{COMMIT}"
        return httpx.Response(200, stream=httpx.ByteStream(_tar_gz(f"demo-{COMMIT}", source_files)))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await compare_release(
        NpmAdapter(client), GitHubSourceResolver(client), "demo", "1.0.0", tmp_path
    )

    assert result.report is not None
    assert assessment(result.report, "dist/index.js").classification is LIKELY
    assert assessment(result.report, "dist/evil.js").classification is UNCERTAIN
    assert file_named(result.report, "package.json").status is FileStatus.IDENTICAL


@pytest.mark.anyio
async def test_compare_release_stops_when_source_is_uncertain(tmp_path: Path) -> None:
    tarball_url = "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"
    document = {
        "versions": {
            "1.0.0": {
                "name": "demo",
                "version": "1.0.0",
                "repository": {"url": "https://github.com/acme/demo"},
                "dist": {"tarball": tarball_url, "shasum": "a" * 40},
            }
        }
    }
    refs = (
        _packet(b"# service=git-upload-pack\n")
        + b"0000"
        + _packet(f"{COMMIT} refs/heads/main\n".encode())
        + b"0000"
    )
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        if request.url.host == "github.com":
            return httpx.Response(200, content=refs)
        return httpx.Response(200, json=document)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await compare_release(
        NpmAdapter(client), GitHubSourceResolver(client), "demo", "1.0.0", tmp_path
    )

    assert result.report is None
    assert result.source_match.status is MatchStatus.UNCERTAIN
    assert tarball_url not in requested
    assert not any("codeload" in url for url in requested)
    assert list(tmp_path.iterdir()) == []
