import asyncio
import gzip
import hashlib
import io
import json
import os
import stat
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Any

import pytest

from app.archives.errors import (
    ArchiveLimitExceededError,
    ExtractionStorageError,
    InvalidArchiveError,
    UnsafeArchiveError,
)
from app.archives.extract import MAX_METADATA_HEADER_BYTES, ExtractionLimits, extract_archive
from app.archives.models import (
    ContentType,
    EntryKind,
    FileInventory,
    FindingKind,
    InventoryEntry,
)
from app.config import Settings

ROOT = "package"


def member(
    name: str,
    content: bytes = b"",
    kind: bytes = tarfile.REGTYPE,
    mode: int = 0o644,
    linkname: str = "",
    size: int | None = None,
    pax: dict[str, str] | None = None,
) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode = mode
    info.linkname = linkname
    info.size = len(content) if size is None else size
    if pax:
        info.pax_headers = pax
    return info, content


def tar_bytes(
    members: list[tuple[tarfile.TarInfo, bytes]], tar_format: int = tarfile.PAX_FORMAT
) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tar_format) as tar:
        for info, content in members:
            tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def write_archive(tmp_path: Path, members: list[tuple[tarfile.TarInfo, bytes]], **kw: Any) -> Path:
    path = tmp_path / "archive.tgz"
    path.write_bytes(gzip.compress(tar_bytes(members, **kw)))
    return path


def extract(
    tmp_path: Path,
    members: list[tuple[tarfile.TarInfo, bytes]],
    limits: ExtractionLimits | None = None,
) -> FileInventory:
    return extract_archive(write_archive(tmp_path, members), tmp_path / "out", limits)


def entry_by_path(inventory: FileInventory, path: str) -> InventoryEntry:
    return next(entry for entry in inventory.entries if entry.path == path)


def assert_rejected(
    tmp_path: Path,
    members: list[tuple[tarfile.TarInfo, bytes]],
    error: type[Exception],
    limits: ExtractionLimits | None = None,
) -> None:
    """Rejection must leave no destination, and nothing beside it except the archive."""
    with pytest.raises(error):
        extract(tmp_path, members, limits)
    assert [path.name for path in tmp_path.iterdir()] == ["archive.tgz"]


# Path traversal


@pytest.mark.parametrize(
    "name",
    [
        "../evil.js",
        "../../../../etc/cron.d/evil",
        "package/../../evil.js",
        "package/../evil.js",
        "package/a/../../../evil.js",
        "/etc/passwd",
        "//etc/passwd",
        "..\\..\\evil.js",
        "package\\..\\..\\evil.js",
        "package/..\\..\\evil.js",
        "package/a\\..\\..\\evil.js",
        "\\windows\\evil.js",
        "C:\\windows\\evil.js",
        "c:/windows/evil.js",
        "package/evil\x00.js".replace("\x00", "\x01"),
        "package/line\nbreak.js",
        "package/\x7fdelete.js",
        "package/bad\udcffname.js",
    ],
)
def test_unsafe_path_rejects_the_whole_archive(tmp_path: Path, name: str) -> None:
    assert_rejected(
        tmp_path,
        [member("package/good.js", b"good"), member(name, b"evil")],
        UnsafeArchiveError,
    )


@pytest.mark.parametrize("name", ["../evil", "/abs/evil"])
def test_unsafe_directory_entry_is_rejected(tmp_path: Path, name: str) -> None:
    assert_rejected(tmp_path, [member(name, kind=tarfile.DIRTYPE)], UnsafeArchiveError)


def test_traversal_through_pax_path_is_rejected(tmp_path: Path) -> None:
    """A PAX header can replace the name that the plain tar header shows."""
    assert_rejected(
        tmp_path,
        [member("package/ok.js", b"x", pax={"path": "../../evil.js"})],
        UnsafeArchiveError,
    )


def test_traversal_through_gnu_long_name_is_rejected(tmp_path: Path) -> None:
    name = "package/" + "a/" * 60 + "../" * 70 + "evil.js"
    path = tmp_path / "archive.tgz"
    path.write_bytes(gzip.compress(tar_bytes([member(name, b"x")], tar_format=tarfile.GNU_FORMAT)))

    with pytest.raises(UnsafeArchiveError):
        extract_archive(path, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_nothing_is_written_outside_the_destination(tmp_path: Path) -> None:
    before = {path for path in tmp_path.parent.iterdir()}

    with pytest.raises(UnsafeArchiveError):
        extract(tmp_path, [member("package/a.js", b"a"), member("package/../../../x.js", b"x")])

    assert {path for path in tmp_path.parent.iterdir()} == before
    assert not (tmp_path / "x.js").exists()


# Links and special files


@pytest.mark.parametrize(
    ("target", "escapes"),
    [
        ("/etc/passwd", True),
        ("../../secret", True),
        ("a/../../../secret", True),
        ("..", True),
        ("..\\..\\secret", True),
        ("C:\\secret", True),
        ("other.js", False),
        ("./other.js", False),
        ("sub/../other.js", False),
    ],
)
def test_symlink_is_recorded_but_never_created(tmp_path: Path, target: str, escapes: bool) -> None:
    inventory = extract(tmp_path, [member("package/link", kind=tarfile.SYMTYPE, linkname=target)])

    entry = entry_by_path(inventory, "link")
    assert entry.kind is EntryKind.SYMLINK
    assert entry.link_target == target
    assert entry.link_escapes_root is escapes
    assert entry.sha256 == hashlib.sha256(target.encode()).hexdigest()
    assert entry.content_type is None
    assert not os.path.lexists(inventory.root / "link")
    assert (FindingKind.LINK_ESCAPES_ROOT in {f.kind for f in inventory.findings}) is escapes


def test_symlink_inside_a_subdirectory_is_resolved_from_there(tmp_path: Path) -> None:
    inventory = extract(
        tmp_path,
        [
            member("package/a/b/inside", kind=tarfile.SYMTYPE, linkname="../../ok"),
            member("package/a/b/outside", kind=tarfile.SYMTYPE, linkname="../../../no"),
        ],
    )

    assert entry_by_path(inventory, "a/b/inside").link_escapes_root is False
    assert entry_by_path(inventory, "a/b/outside").link_escapes_root is True


@pytest.mark.parametrize(
    "link_kind",
    [tarfile.SYMTYPE, tarfile.LNKTYPE],
    ids=["symlink", "hardlink"],
)
def test_writing_through_a_link_is_rejected(tmp_path: Path, link_kind: bytes) -> None:
    """The classic attack: declare `dir -> /target`, then write `dir/file`."""
    outside = tmp_path / "victim"
    members = [
        member("package/dir", kind=link_kind, linkname=str(outside)),
        member("package/dir/payload.js", b"evil"),
    ]

    with pytest.raises(UnsafeArchiveError):
        extract(tmp_path, members)

    assert not outside.exists()
    assert not (tmp_path / "out").exists()


def test_replacing_a_file_with_a_link_is_rejected(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [
            member("package/a.js", b"a"),
            member("package/a.js", kind=tarfile.SYMTYPE, linkname="/etc/passwd"),
        ],
        UnsafeArchiveError,
    )


@pytest.mark.parametrize(
    ("target", "escapes"),
    [
        ("package/real.js", False),
        ("other-root/real.js", True),
        ("/etc/passwd", True),
        ("package/../../etc/passwd", True),
    ],
)
def test_hardlink_is_recorded_but_never_created(tmp_path: Path, target: str, escapes: bool) -> None:
    inventory = extract(
        tmp_path,
        [
            member("package/real.js", b"real"),
            member("package/link.js", kind=tarfile.LNKTYPE, linkname=target),
        ],
    )

    entry = entry_by_path(inventory, "link.js")
    assert entry.kind is EntryKind.HARDLINK
    assert entry.link_escapes_root is escapes
    assert not (inventory.root / "link.js").exists()


@pytest.mark.parametrize(
    "kind",
    [tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE],
    ids=["character-device", "block-device", "fifo"],
)
def test_special_file_is_recorded_but_never_created(tmp_path: Path, kind: bytes) -> None:
    inventory = extract(tmp_path, [member("package/device", kind=kind)])

    entry = entry_by_path(inventory, "device")
    assert entry.kind is EntryKind.SPECIAL
    assert entry.sha256 is None
    assert not os.path.lexists(inventory.root / "device")
    assert [f.kind for f in inventory.findings] == [FindingKind.SPECIAL_FILE]


# Files that overlap or hide others


@pytest.mark.parametrize(
    "second",
    [
        member("package/a.js", b"second"),
        member("package/./a.js", b"second"),
        member("package//a.js", b"second"),
    ],
    ids=["exact", "dot-segment", "double-slash"],
)
def test_duplicate_path_is_rejected(tmp_path: Path, second: tuple[tarfile.TarInfo, bytes]) -> None:
    assert_rejected(tmp_path, [member("package/a.js", b"first"), second], UnsafeArchiveError)


def test_file_then_nested_file_is_rejected(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [member("package/a", b"file"), member("package/a/b.js", b"nested")],
        UnsafeArchiveError,
    )


def test_nested_file_then_file_is_rejected(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [member("package/a/b.js", b"nested"), member("package/a", b"file")],
        UnsafeArchiveError,
    )


def test_directory_over_file_is_rejected(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [member("package/a", b"file"), member("package/a", kind=tarfile.DIRTYPE)],
        UnsafeArchiveError,
    )


def test_collision_only_on_this_filesystem_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_open = os.open

    def colliding_open(path: Any, *args: Any, **kwargs: Any) -> int:
        if str(path).endswith("B.js"):
            raise FileExistsError(path)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", colliding_open)

    assert_rejected(
        tmp_path,
        [member("package/a.js", b"a"), member("package/B.js", b"b")],
        UnsafeArchiveError,
    )


def test_second_root_is_rejected(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [member("package/a.js", b"a"), member("other/index.js", b"evil")],
        UnsafeArchiveError,
    )


@pytest.mark.parametrize("name", ["top-level.js", "./top-level.js"])
def test_file_with_no_root_is_rejected(tmp_path: Path, name: str) -> None:
    assert_rejected(tmp_path, [member(name, b"x")], UnsafeArchiveError)


def test_entries_after_a_corrupt_header_cannot_be_hidden(tmp_path: Path) -> None:
    """tarfile stops silently at a corrupt header, so later files would go unseen."""
    good = tar_bytes([member("package/good.js", b"good")])
    hidden = tar_bytes([member("package/hidden.js", b"evil")])
    data = good.rstrip(b"\0")
    data += b"\0" * (-len(data) % 512)
    corrupt = bytearray(hidden)
    corrupt[148:156] = b"BADSUM\0 "
    path = tmp_path / "archive.tgz"
    path.write_bytes(gzip.compress(data + bytes(corrupt)))

    with pytest.raises(InvalidArchiveError):
        extract_archive(path, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_data_after_the_end_of_the_archive_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "archive.tgz"
    path.write_bytes(gzip.compress(tar_bytes([member("package/a.js", b"a")]) + b"hidden payload"))

    with pytest.raises(InvalidArchiveError):
        extract_archive(path, tmp_path / "out")


def test_second_tar_after_end_markers_is_rejected(tmp_path: Path) -> None:
    """GNU tar with --ignore-zeros would read this second archive, but tarfile would not."""
    path = tmp_path / "archive.tgz"
    path.write_bytes(
        gzip.compress(
            tar_bytes([member("package/a.js", b"a")])
            + tar_bytes([member("package/hidden.js", b"evil")])
        )
    )

    with pytest.raises(InvalidArchiveError):
        extract_archive(path, tmp_path / "out")


def test_trailing_zero_padding_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "archive.tgz"
    path.write_bytes(gzip.compress(tar_bytes([member("package/a.js", b"a")]) + b"\0" * 20480))

    inventory = extract_archive(path, tmp_path / "out")

    assert [entry.path for entry in inventory.entries] == ["a.js"]


# Resource limits


def test_compressed_archive_size_limit(tmp_path: Path) -> None:
    with pytest.raises(ArchiveLimitExceededError):
        extract(tmp_path, [member("package/a.js", b"a")], ExtractionLimits(max_archive_bytes=10))
    assert not (tmp_path / "out").exists()


def test_file_size_limit(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [member("package/a.js", b"x" * 11)],
        ArchiveLimitExceededError,
        ExtractionLimits(max_file_bytes=10),
    )


def test_total_size_limit_across_files(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [member(f"package/{i}.js", b"x" * 4000) for i in range(5)],
        ArchiveLimitExceededError,
        ExtractionLimits(max_total_bytes=15000),
    )


def test_total_limit_counts_files_as_written_not_only_declared(tmp_path: Path) -> None:
    """The limit is enforced on decompressed bytes, so headers cannot under-report."""
    assert_rejected(
        tmp_path,
        [member("package/a.bin", os.urandom(50_000))],
        ArchiveLimitExceededError,
        ExtractionLimits(max_total_bytes=20_000),
    )


def test_declared_size_is_checked_before_reading(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [member("package/a.js", b"", pax={"size": str(10**15)})],
        ArchiveLimitExceededError,
    )


def test_declared_file_size_over_the_limit_is_rejected(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [member("package/a.js", b"x", pax={"size": "11"})],
        ArchiveLimitExceededError,
        ExtractionLimits(max_file_bytes=10),
    )


def test_total_limit_counts_metadata_that_is_not_file_content(tmp_path: Path) -> None:
    """Headers are decompressed too, so an archive of tiny files with huge headers is caught."""
    padding = "x" * (200 * 1024)

    assert_rejected(
        tmp_path,
        [member(f"package/{i}.js", b"", pax={"comment": padding}) for i in range(10)],
        ArchiveLimitExceededError,
        ExtractionLimits(max_total_bytes=1024 * 1024),
    )


def test_gzip_bomb_stops_at_the_ratio_limit(tmp_path: Path) -> None:
    content = b"\0" * (64 * 1024 * 1024)

    assert_rejected(
        tmp_path,
        [member("package/bomb.bin", content)],
        ArchiveLimitExceededError,
        ExtractionLimits(max_compression_ratio=10),
    )


def test_compressible_small_archive_is_not_a_bomb(tmp_path: Path) -> None:
    inventory = extract(
        tmp_path,
        [member("package/zeros.bin", b"\0" * (1024 * 1024))],
        ExtractionLimits(max_compression_ratio=2),
    )

    assert entry_by_path(inventory, "zeros.bin").size_bytes == 1024 * 1024


def test_entry_count_limit_includes_empty_files_and_directories(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [member(f"package/{i}") for i in range(3)]
        + [member(f"package/d{i}", kind=tarfile.DIRTYPE) for i in range(3)],
        ArchiveLimitExceededError,
        ExtractionLimits(max_entries=5),
    )


def test_entries_at_the_limit_are_accepted(tmp_path: Path) -> None:
    inventory = extract(
        tmp_path,
        [member(f"package/{i}") for i in range(5)],
        ExtractionLimits(max_entries=5),
    )

    assert len(inventory.entries) == 5


def test_depth_limit(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [member("package/" + "d/" * 10 + "a.js", b"x")],
        ArchiveLimitExceededError,
        ExtractionLimits(max_depth=5),
    )


def test_path_length_limit(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [member("package/" + "d/" * 50 + "a.js", b"x")],
        ArchiveLimitExceededError,
        ExtractionLimits(max_path_bytes=50),
    )


def test_path_component_limit(tmp_path: Path) -> None:
    assert_rejected(tmp_path, [member("package/" + "a" * 256, b"x")], ArchiveLimitExceededError)


@pytest.mark.parametrize(
    "header_type",
    [tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK],
    ids=["pax", "pax-global", "gnu-long-name", "gnu-long-link"],
)
def test_oversized_metadata_header_is_refused_before_it_is_read(
    tmp_path: Path, header_type: bytes
) -> None:
    """tarfile would load this whole header into memory. This fails if the guard stops working."""
    size = MAX_METADATA_HEADER_BYTES + 1
    info = tarfile.TarInfo("package/header")
    info.type = header_type
    info.size = size
    path = tmp_path / "archive.tgz"
    path.write_bytes(gzip.compress(info.tobuf(tarfile.GNU_FORMAT) + b"\0" * (size + 512)))

    with pytest.raises(ArchiveLimitExceededError):
        extract_archive(path, tmp_path / "out")


def test_sparse_entry_is_rejected(tmp_path: Path) -> None:
    info = tarfile.TarInfo("package/sparse.bin")
    info.type = tarfile.GNUTYPE_SPARSE
    info.size = 0
    header = bytearray(info.tobuf(tarfile.GNU_FORMAT))
    path = tmp_path / "archive.tgz"
    path.write_bytes(gzip.compress(bytes(header) + b"\0" * 1024))

    with pytest.raises(UnsafeArchiveError):
        extract_archive(path, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_deadline_stops_extraction(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [member("package/a.js", b"x")],
        ArchiveLimitExceededError,
        ExtractionLimits(deadline_seconds=-1),
    )


def test_deadline_applies_while_a_file_is_being_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = iter(float(tick) for tick in range(10_000))
    monkeypatch.setattr(time, "monotonic", lambda: next(clock))

    assert_rejected(
        tmp_path,
        [member("package/a.bin", os.urandom(4 * 1024 * 1024))],
        ArchiveLimitExceededError,
        ExtractionLimits(deadline_seconds=5),
    )


# Invalid input


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not gzip at all",
        gzip.compress(b""),
        gzip.compress(b"this is not a tar archive at all" * 100),
    ],
    ids=["empty", "not-gzip", "empty-gzip", "gzip-not-tar"],
)
def test_invalid_archive_is_rejected(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "archive.tgz"
    path.write_bytes(content)

    with pytest.raises(InvalidArchiveError):
        extract_archive(path, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_plain_tar_without_gzip_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "archive.tar"
    path.write_bytes(tar_bytes([member("package/a.js", b"a")]))

    with pytest.raises(InvalidArchiveError):
        extract_archive(path, tmp_path / "out")


def test_truncated_gzip_is_rejected_and_cleaned_up(tmp_path: Path) -> None:
    data = gzip.compress(tar_bytes([member("package/a.bin", os.urandom(100_000))]))
    path = tmp_path / "archive.tgz"
    path.write_bytes(data[: len(data) // 2])

    with pytest.raises(InvalidArchiveError):
        extract_archive(path, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_corrupt_gzip_data_is_rejected(tmp_path: Path) -> None:
    data = bytearray(gzip.compress(tar_bytes([member("package/a.bin", os.urandom(50_000))])))
    data[len(data) // 2] ^= 0xFF
    path = tmp_path / "archive.tgz"
    path.write_bytes(bytes(data))

    with pytest.raises(InvalidArchiveError):
        extract_archive(path, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_entry_cut_short_is_rejected(tmp_path: Path) -> None:
    raw = tar_bytes([member("package/a.bin", b"x" * 5000)], tar_format=tarfile.USTAR_FORMAT)
    path = tmp_path / "archive.tgz"
    path.write_bytes(gzip.compress(raw[:1024]))

    with pytest.raises(InvalidArchiveError):
        extract_archive(path, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_archive_that_is_a_symlink_is_rejected(tmp_path: Path) -> None:
    real = write_archive(tmp_path, [member("package/a.js", b"a")])
    link = tmp_path / "link.tgz"
    link.symlink_to(real)

    with pytest.raises(InvalidArchiveError):
        extract_archive(link, tmp_path / "out")


def test_fifo_archive_is_rejected_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo.tgz"
    os.mkfifo(fifo)

    with pytest.raises(InvalidArchiveError):
        extract_archive(fifo, tmp_path / "out")


def test_missing_archive_is_a_storage_error(tmp_path: Path) -> None:
    with pytest.raises(ExtractionStorageError):
        extract_archive(tmp_path / "missing.tgz", tmp_path / "out")


# Destination


def test_existing_destination_is_refused_and_preserved(tmp_path: Path) -> None:
    destination = tmp_path / "out"
    destination.mkdir()
    keep = destination / "keep.txt"
    keep.write_text("keep")
    archive = write_archive(tmp_path, [member("package/a.js", b"a")])

    with pytest.raises(ExtractionStorageError):
        extract_archive(archive, destination)

    assert keep.read_text() == "keep"
    assert [path.name for path in destination.iterdir()] == ["keep.txt"]


def test_failed_write_is_a_storage_error_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_fdopen = os.fdopen

    def full_disk(descriptor: int, *args: Any, **kwargs: Any) -> Any:
        real_fdopen(descriptor).close()
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fdopen", full_disk)

    assert_rejected(tmp_path, [member("package/a.js", b"a")], ExtractionStorageError)


# Files are never executable, and nothing runs


@pytest.mark.parametrize("mode", [0o777, 0o755, 0o4755, 0o2755, 0o6777])
def test_written_files_are_private_and_never_executable(tmp_path: Path, mode: int) -> None:
    inventory = extract(tmp_path, [member("package/bin/tool", b"#!/bin/sh\necho hi\n", mode=mode)])

    written = stat.S_IMODE((inventory.root / "bin" / "tool").stat().st_mode)
    assert written == 0o600
    assert stat.S_IMODE((inventory.root / "bin").stat().st_mode) == 0o700
    assert stat.S_IMODE(inventory.root.stat().st_mode) == 0o700


def test_declared_directory_mode_is_not_applied(tmp_path: Path) -> None:
    inventory = extract(
        tmp_path,
        [
            member("package/open", kind=tarfile.DIRTYPE, mode=0o777),
            member("package/open/a.js", b"a"),
        ],
    )

    assert stat.S_IMODE((inventory.root / "open").stat().st_mode) == 0o700


def test_ownership_and_timestamps_are_not_applied(tmp_path: Path) -> None:
    info, content = member("package/a.js", b"a")
    info.uid, info.gid, info.mtime = 0, 0, 1
    inventory = extract(tmp_path, [(info, content)])

    details = (inventory.root / "a.js").stat()
    assert details.st_uid == os.getuid()
    assert details.st_mtime > 1


def test_nothing_is_executed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_: Any, **__: Any) -> None:
        raise AssertionError("a process was started")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(os, "posix_spawn", forbidden)
    monkeypatch.setattr(os, "fork", forbidden)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
    monkeypatch.setattr(asyncio, "create_subprocess_shell", forbidden)
    sentinel = tmp_path / "ran"
    script = f"#!/bin/sh\ntouch {sentinel}\n".encode()
    package_json = json.dumps({"scripts": {"postinstall": f"touch {sentinel}"}}).encode()

    inventory = extract(
        tmp_path,
        [
            member("package/package.json", package_json),
            member("package/install.sh", script, mode=0o755),
            member("package/setup.py", b"open('" + str(sentinel).encode() + b"', 'w')\n"),
        ],
    )

    assert len(inventory.entries) == 3
    assert not sentinel.exists()


def test_tarfile_extraction_api_is_never_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_: Any, **__: Any) -> None:
        raise AssertionError("tarfile's own extraction was used")

    monkeypatch.setattr(tarfile.TarFile, "extract", forbidden)
    monkeypatch.setattr(tarfile.TarFile, "extractall", forbidden)
    monkeypatch.setattr(tarfile.TarFile, "_extract_member", forbidden)

    assert extract(tmp_path, [member("package/a.js", b"a")]).entries


# Inventory


def test_inventory_records_requested_fields(tmp_path: Path) -> None:
    content = b"console.log('hi')\n"
    inventory = extract(tmp_path, [member("package/lib/Index.JS", content, mode=0o644)])

    assert inventory.entries == (
        InventoryEntry(
            path="lib/Index.JS",
            extension=".js",
            kind=EntryKind.REGULAR,
            size_bytes=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            content_type=ContentType.TEXT,
            mode="0644",
            is_executable=False,
        ),
    )
    assert (inventory.root / "lib" / "Index.JS").read_bytes() == content


def test_inventory_records_archive_details(tmp_path: Path) -> None:
    contents = [b"aaa", b"bbbbb"]
    archive = write_archive(
        tmp_path, [member("package/a", contents[0]), member("package/b", contents[1])]
    )

    inventory = extract_archive(archive, tmp_path / "out")

    assert inventory.root == tmp_path / "out"
    assert inventory.archive_root == "package"
    assert inventory.archive_size_bytes == archive.stat().st_size
    assert inventory.archive_sha256 == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert inventory.total_bytes == 8
    assert inventory.findings == ()


@pytest.mark.parametrize(
    ("mode", "text", "executable"),
    [
        (0o644, "0644", False),
        (0o755, "0755", True),
        (0o100, "0100", True),
        (0o010, "0010", True),
        (0o001, "0001", True),
        (0o4755, "4755", True),
        (0, "0000", False),
    ],
)
def test_declared_permissions_are_recorded(
    tmp_path: Path, mode: int, text: str, executable: bool
) -> None:
    entry = extract(tmp_path, [member("package/a", b"a", mode=mode)]).entries[0]

    assert (entry.mode, entry.is_executable) == (text, executable)


@pytest.mark.parametrize(("mode", "expected"), [(0o4755, True), (0o2755, True), (0o755, False)])
def test_setuid_and_setgid_are_reported(tmp_path: Path, mode: int, expected: bool) -> None:
    inventory = extract(tmp_path, [member("package/a", b"a", mode=mode)])

    assert (FindingKind.PRIVILEGED_MODE in {f.kind for f in inventory.findings}) is expected


@pytest.mark.parametrize(
    ("name", "extension"),
    [
        ("a.js", ".js"),
        ("a.d.ts", ".ts"),
        ("a.TAR.GZ", ".gz"),
        ("Makefile", ""),
        (".npmrc", ""),
        ("dir.x/file", ""),
    ],
)
def test_extension(tmp_path: Path, name: str, extension: str) -> None:
    assert extract(tmp_path, [member(f"package/{name}", b"x")]).entries[0].extension == extension


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"", ContentType.EMPTY),
        (b"plain text\n", ContentType.TEXT),
        ("héllo wörld".encode(), ContentType.TEXT),
        (b"#!/usr/bin/env node\n", ContentType.SCRIPT),
        (b"\x7fELF\x02\x01\x01", ContentType.ELF),
        (b"\xcf\xfa\xed\xfe\x07", ContentType.MACH_O),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x02", ContentType.MACH_O),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x34", ContentType.JAVA_CLASS),
        (b"MZ\x90\x00\x03", ContentType.PE),
        (b"MZ is also how this text starts\n", ContentType.TEXT),
        (b"\x00asm\x01\x00\x00\x00", ContentType.WASM),
        (b"\x1f\x8b\x08\x00", ContentType.GZIP),
        (b"PK\x03\x04", ContentType.ZIP),
        (b"\x89PNG\r\n\x1a\n", ContentType.PNG),
        (b"\xff\xd8\xff\xe0", ContentType.JPEG),
        (b"GIF89a", ContentType.GIF),
        (b"%PDF-1.7", ContentType.PDF),
        (b"\x00\x01\x02\x03", ContentType.BINARY),
        (b"\xff\xfe invalid utf-8 \xc3\x28", ContentType.BINARY),
    ],
)
def test_content_type_detection(tmp_path: Path, content: bytes, expected: ContentType) -> None:
    assert extract(tmp_path, [member("package/f", content)]).entries[0].content_type is expected


def test_multibyte_character_cut_by_the_sample_is_still_text(tmp_path: Path) -> None:
    content = b"a" * (8 * 1024 - 1) + "é".encode() + b"tail"

    assert extract(tmp_path, [member("package/f", content)]).entries[0].content_type is (
        ContentType.TEXT
    )


def test_content_is_labelled_by_bytes_not_by_extension(tmp_path: Path) -> None:
    entry = extract(tmp_path, [member("package/readme.txt", b"\x7fELF\x02")]).entries[0]

    assert entry.content_type is ContentType.ELF


def test_large_file_hash_covers_all_chunks(tmp_path: Path) -> None:
    content = os.urandom(300 * 1024)

    entry = extract(tmp_path, [member("package/big.bin", content)]).entries[0]

    assert entry.sha256 == hashlib.sha256(content).hexdigest()
    assert entry.size_bytes == len(content)


def test_entries_are_sorted_whatever_the_archive_order(tmp_path: Path) -> None:
    inventory = extract(
        tmp_path, [member("package/c.js"), member("package/a/b.js"), member("package/a.js")]
    )

    assert [entry.path for entry in inventory.entries] == ["a.js", "a/b.js", "c.js"]


def test_directories_and_root_prefix_variants_are_normalized(tmp_path: Path) -> None:
    inventory = extract(
        tmp_path,
        [
            member("./package/", kind=tarfile.DIRTYPE),
            member("./package/src/", kind=tarfile.DIRTYPE),
            member("./package/src/a.js", b"a"),
        ],
    )

    assert inventory.archive_root == "package"
    assert [entry.path for entry in inventory.entries] == ["src/a.js"]


def test_github_style_archive(tmp_path: Path) -> None:
    root = "demo-" + "a" * 40
    buffer = io.BytesIO()
    with tarfile.open(
        fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT, pax_headers={"comment": "a" * 40}
    ) as tar:
        for info, content in [
            member(f"{root}/", kind=tarfile.DIRTYPE, mode=0o775),
            member(f"{root}/src/index.js", b"x"),
            member(f"{root}/link", kind=tarfile.SYMTYPE, linkname="src/index.js", mode=0o777),
        ]:
            tar.addfile(info, io.BytesIO(content))
    path = tmp_path / "archive.tgz"
    path.write_bytes(gzip.compress(buffer.getvalue()))

    inventory = extract_archive(path, tmp_path / "out")

    assert inventory.archive_root == root
    assert [entry.path for entry in inventory.entries] == ["link", "src/index.js"]
    assert inventory.findings == ()


def test_inventory_can_be_serialized_to_json(tmp_path: Path) -> None:
    inventory = extract(
        tmp_path,
        [
            member("package/ünï.js", b"x"),
            member("package/link", kind=tarfile.SYMTYPE, linkname="/etc/passwd"),
        ],
    )

    decoded = json.loads(inventory.model_dump_json())

    assert {entry["path"] for entry in decoded["entries"]} == {"ünï.js", "link"}


def test_empty_archive_has_an_empty_inventory(tmp_path: Path) -> None:
    inventory = extract(tmp_path, [member("package/", kind=tarfile.DIRTYPE)])

    assert inventory.entries == ()
    assert inventory.total_bytes == 0


def test_settings_build_extraction_limits() -> None:
    limits = Settings(extraction_max_entries=7, extraction_deadline_seconds=9).extraction_limits()

    assert limits.max_entries == 7
    assert limits.deadline_seconds == 9
