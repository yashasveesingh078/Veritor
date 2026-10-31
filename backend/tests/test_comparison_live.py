"""Comparison of real packages from npm and GitHub. Run with: pytest -m live"""

from pathlib import Path

import pytest

from app.adapters.http import RegistryLimits, create_registry_client
from app.adapters.npm import NpmAdapter
from app.comparison.models import ComparisonReport, FileStatus
from app.comparison.service import compare_release
from app.source.github import GitHubSourceResolver

pytestmark = [pytest.mark.live, pytest.mark.anyio]


async def report_for(name: str, version: str, work_dir: Path) -> ComparisonReport:
    limits = RegistryLimits()
    async with create_registry_client(limits) as client:
        result = await compare_release(
            NpmAdapter(client, limits),
            GitHubSourceResolver(client, limits),
            name,
            version,
            work_dir,
        )
    assert result.report is not None
    return result.report


async def test_plain_javascript_package_matches_its_source(tmp_path: Path) -> None:
    report = await report_for("left-pad", "1.3.0", tmp_path)

    by_path = {item.path: item for item in report.files}
    assert by_path["index.js"].status is FileStatus.IDENTICAL
    assert report.summary.identical > 0


async def test_compiled_typescript_package_has_likely_generated_output(tmp_path: Path) -> None:
    report = await report_for("ky", "1.7.4", tmp_path)

    assert report.scope.manifest_name_matches is True
    assert "tsc" in report.build.tools
    assert report.summary.likely_generated > 0


async def test_custom_build_stays_uncertain(tmp_path: Path) -> None:
    report = await report_for("hono", "4.6.16", tmp_path)

    assert report.summary.likely_generated == 0
    assert report.summary.uncertain > 0


async def test_install_script_target_is_never_likely_generated(tmp_path: Path) -> None:
    report = await report_for("esbuild", "0.28.2", tmp_path)

    install = next(item for item in report.files if item.path == "install.js")
    assert install.generated is not None
    assert install.generated.classification.value == "UNCERTAIN"
    assert any("install script" in blocker for blocker in install.generated.blockers)
