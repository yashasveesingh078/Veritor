import asyncio
from pathlib import Path

from app.adapters.base import PackageAdapter
from app.archives.extract import ExtractionLimits, extract_archive
from app.comparison.compare import compare_inventories
from app.comparison.models import ComparisonLimits, ReleaseComparison
from app.source.github import GitHubSourceResolver
from app.source.models import MatchStatus


async def compare_release(
    adapter: PackageAdapter,
    resolver: GitHubSourceResolver,
    name: str,
    version: str,
    work_dir: Path,
    extraction_limits: ExtractionLimits | None = None,
    comparison_limits: ComparisonLimits | None = None,
) -> ReleaseComparison:
    """Retrieve, extract and compare one release.

    Without an established source commit the result has no report, and nothing is
    downloaded. Retrieval and extraction failures are raised. ``work_dir`` is left in place
    for the caller, because the report refers to files within it.
    """
    metadata = await adapter.fetch_metadata(name, version)
    match = await resolver.resolve(metadata)
    if match.status is not MatchStatus.MATCHED:
        return ReleaseComparison(metadata=metadata, source_match=match)

    tarball = await adapter.download_artifact(metadata.artifacts[0], work_dir / "downloads")
    source_archive = await resolver.download_source(match, work_dir / "downloads")

    # Extraction and comparison block, so they run outside the event loop.
    package_inventory = await asyncio.to_thread(
        extract_archive, tarball.path, work_dir / "package", extraction_limits
    )
    source_inventory = await asyncio.to_thread(
        extract_archive, source_archive.path, work_dir / "source", extraction_limits
    )
    report = await asyncio.to_thread(
        compare_inventories,
        metadata,
        match,
        package_inventory,
        source_inventory,
        comparison_limits,
    )
    return ReleaseComparison(metadata=metadata, source_match=match, report=report)
