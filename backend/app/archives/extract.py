"""Safely extract npm and GitHub gzip-compressed tar archives and inventory their files.

The archive is untrusted. ``TarFile.extract`` is never used: this module reads each entry
and writes regular files itself, so an entry cannot choose how it lands on disk.

- Only regular files are written, always with mode 0600, so nothing is executable.
- Links and device files are recorded in the inventory, but never created.
- Any entry that could escape the destination or hide content rejects the whole archive,
  because a partial inventory would look complete.

This function blocks. Async callers should run it with ``asyncio.to_thread``.
"""

import gzip
import hashlib
import os
import posixpath
import re
import shutil
import stat
import tarfile
import time
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from app.archives.errors import (
    ArchiveLimitExceededError,
    ExtractionError,
    ExtractionStorageError,
    InvalidArchiveError,
    UnsafeArchiveError,
)
from app.archives.models import (
    ContentType,
    EntryKind,
    FileInventory,
    FindingKind,
    InventoryEntry,
    InventoryFinding,
)

CHUNK_SIZE = 64 * 1024
SNIFF_SIZE = 8 * 1024
# Decompressed size below which a high compression ratio is not worth rejecting.
RATIO_CHECK_FLOOR_BYTES = 16 * 1024 * 1024
MAX_METADATA_HEADER_BYTES = 1024 * 1024
_METADATA_TYPES = {
    tarfile.GNUTYPE_LONGNAME,
    tarfile.GNUTYPE_LONGLINK,
    tarfile.XHDTYPE,
    tarfile.XGLTYPE,
    tarfile.SOLARIS_XHDTYPE,
}
_WINDOWS_DRIVE = re.compile(r"[A-Za-z]:")
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_PRIVILEGED_BITS = stat.S_ISUID | stat.S_ISGID
_EXECUTE_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
_MAGIC_NUMBERS: tuple[tuple[bytes, ContentType], ...] = (
    (b"\x7fELF", ContentType.ELF),
    (b"\xfe\xed\xfa\xce", ContentType.MACH_O),
    (b"\xfe\xed\xfa\xcf", ContentType.MACH_O),
    (b"\xce\xfa\xed\xfe", ContentType.MACH_O),
    (b"\xcf\xfa\xed\xfe", ContentType.MACH_O),
    (b"\x00asm", ContentType.WASM),
    (b"\x1f\x8b", ContentType.GZIP),
    (b"PK\x03\x04", ContentType.ZIP),
    (b"\x89PNG\r\n\x1a\n", ContentType.PNG),
    (b"\xff\xd8\xff", ContentType.JPEG),
    (b"GIF8", ContentType.GIF),
    (b"%PDF-", ContentType.PDF),
)


@dataclass(frozen=True)
class ExtractionLimits:
    max_archive_bytes: int = 1024 * 1024 * 1024
    max_total_bytes: int = 4 * 1024 * 1024 * 1024
    max_file_bytes: int = 1024 * 1024 * 1024
    max_entries: int = 200_000
    max_compression_ratio: int = 200
    max_path_bytes: int = 4096
    max_component_bytes: int = 255
    max_depth: int = 64
    deadline_seconds: float = 300.0


class _BoundedTarInfo(tarfile.TarInfo):
    """Refuse oversized metadata headers.

    ``tarfile`` reads a PAX or GNU long-name header fully into memory before returning, so
    a limit on the entries themselves would apply too late. This overrides a private
    method, and a test confirms it still takes effect.
    """

    def _proc_member(self, tarfile: Any) -> Any:  # noqa: A002 - the base class's name
        if self.type in _METADATA_TYPES and self.size > MAX_METADATA_HEADER_BYTES:
            raise ArchiveLimitExceededError("A metadata header exceeds the size limit")
        return super()._proc_member(tarfile)  # type: ignore[misc]


class _BoundedStream:
    """Decompress with limits that apply to every byte, including skipped data and headers."""

    def __init__(
        self, source: gzip.GzipFile, compressed_size: int, limits: ExtractionLimits
    ) -> None:
        self._source = source
        self._compressed_size = compressed_size
        self._limits = limits
        self._deadline = time.monotonic() + limits.deadline_seconds
        self.position = 0
        self.last_nonzero_position = -1

    def read(self, size: int = -1) -> bytes:
        self.check_deadline()
        data = self._source.read(size if size >= 0 else CHUNK_SIZE)
        stripped = len(data.rstrip(b"\0"))
        if stripped:
            self.last_nonzero_position = self.position + stripped - 1
        self.position += len(data)

        if self.position > self._limits.max_total_bytes:
            raise ArchiveLimitExceededError(
                f"Decompressed data exceeds {self._limits.max_total_bytes} bytes"
            )
        if (
            self.position > RATIO_CHECK_FLOOR_BYTES
            and self.position > self._compressed_size * self._limits.max_compression_ratio
        ):
            raise ArchiveLimitExceededError(
                f"Compression ratio exceeds {self._limits.max_compression_ratio}"
            )
        return data

    def check_deadline(self) -> None:
        if time.monotonic() > self._deadline:
            raise ArchiveLimitExceededError("Extraction exceeded its time limit")


class _Layout:
    """Track paths so that entries cannot overlap, overwrite or sit beneath each other."""

    def __init__(self) -> None:
        self.directories: set[str] = set()
        self.non_directories: set[str] = set()

    def add_directory(self, segments: tuple[str, ...]) -> None:
        path = "/".join(segments)
        if path in self.non_directories:
            raise UnsafeArchiveError(f"Directory conflicts with another entry: {path!r}")
        self.directories.add(path)

    def add_non_directory(self, segments: tuple[str, ...]) -> None:
        path = "/".join(segments)
        # Two entries with one path would let a reader see the first and an installer the last.
        if path in self.non_directories:
            raise UnsafeArchiveError(f"Duplicate entry: {path!r}")
        if path in self.directories:
            raise UnsafeArchiveError(f"File conflicts with a directory: {path!r}")
        self.non_directories.add(path)

    def add_parents(self, segments: tuple[str, ...]) -> None:
        for depth in range(1, len(segments)):
            parent = segments[:depth]
            path = "/".join(parent)
            # A file beneath a declared link would be written elsewhere by a real extractor.
            if path in self.non_directories:
                raise UnsafeArchiveError(f"Entry is nested beneath a file or link: {path!r}")
            self.directories.add(path)


def extract_archive(
    archive: Path, destination: Path, limits: ExtractionLimits | None = None
) -> FileInventory:
    """Extract a gzip-compressed tar archive into a new directory and inventory it.

    ``destination`` must not exist. It is removed again if extraction fails, so a directory
    is only ever left behind for an archive that passed every check.
    """
    limits = limits or ExtractionLimits()
    archive_size, archive_sha256 = _inspect_archive(archive, limits)

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Refusing an existing path means nothing already there can be overwritten or removed.
        destination.mkdir(mode=0o700)
    except OSError as exc:
        raise ExtractionStorageError(f"Cannot create destination {destination}") from exc

    try:
        archive_root, entries, total_bytes = _extract_entries(
            archive, archive_size, destination, limits
        )
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise

    return FileInventory(
        root=destination,
        archive_sha256=archive_sha256,
        archive_size_bytes=archive_size,
        archive_root=archive_root,
        entries=tuple(sorted(entries, key=lambda entry: entry.path)),
        total_bytes=total_bytes,
        findings=tuple(
            sorted(_findings(entries), key=lambda finding: (finding.path, finding.kind))
        ),
    )


def _inspect_archive(archive: Path, limits: ExtractionLimits) -> tuple[int, str]:
    try:
        # Opening without following links, and checking the type, also avoids blocking on a FIFO.
        details = archive.lstat()
        if not stat.S_ISREG(details.st_mode):
            raise InvalidArchiveError(f"Not a regular file: {archive}")
        if details.st_size > limits.max_archive_bytes:
            raise ArchiveLimitExceededError(f"Archive exceeds {limits.max_archive_bytes} bytes")
        hasher = hashlib.sha256()
        with archive.open("rb") as file:
            while chunk := file.read(CHUNK_SIZE):
                hasher.update(chunk)
    except OSError as exc:
        raise ExtractionStorageError(f"Cannot read archive {archive}") from exc
    return details.st_size, hasher.hexdigest()


def _extract_entries(
    archive: Path, archive_size: int, destination: Path, limits: ExtractionLimits
) -> tuple[str | None, list[InventoryEntry], int]:
    entries: list[InventoryEntry] = []
    layout = _Layout()
    archive_root: str | None = None
    total_bytes = 0
    count = 0

    try:
        with gzip.open(archive, "rb") as source:
            stream = _BoundedStream(source, archive_size, limits)
            with tarfile.open(
                fileobj=stream,  # type: ignore[call-overload]
                mode="r|",
                tarinfo=_BoundedTarInfo,
            ) as tar:
                for member in tar:
                    stream.check_deadline()
                    count += 1
                    if count > limits.max_entries:
                        raise ArchiveLimitExceededError(
                            f"Archive has more than {limits.max_entries} entries"
                        )

                    segments = _safe_segments(member.name, limits)
                    if not segments:
                        continue
                    if archive_root is None:
                        archive_root = segments[0]
                    elif segments[0] != archive_root:
                        # Installers merge every root into one, so paths could not be trusted.
                        raise UnsafeArchiveError(
                            f"Entry is outside the archive root: {member.name!r}"
                        )

                    relative = segments[1:]
                    if not relative:
                        if not member.isdir():
                            raise UnsafeArchiveError(
                                f"Entry is outside the archive root: {member.name!r}"
                            )
                        continue

                    layout.add_parents(relative)
                    if member.isdir():
                        layout.add_directory(relative)
                        continue
                    layout.add_non_directory(relative)

                    if member.isfile():
                        entry = _write_regular_file(
                            tar, member, relative, destination, limits, total_bytes, stream
                        )
                        total_bytes += entry.size_bytes
                    elif member.issym() or member.islnk():
                        entry = _link_entry(member, relative, archive_root)
                    else:
                        entry = _special_entry(member, relative)
                    entries.append(entry)

                end_of_archive = tar.offset

            # tarfile treats a corrupt header as the end of the archive, which would hide
            # every entry after it. Only zero padding may follow the end.
            while stream.read(CHUNK_SIZE):
                pass
            if stream.last_nonzero_position >= end_of_archive:
                raise InvalidArchiveError("Archive has unreadable data after its last entry")
    except ExtractionError:
        raise
    except (tarfile.TarError, EOFError, zlib.error, gzip.BadGzipFile) as exc:
        raise InvalidArchiveError(f"Archive is corrupt or truncated: {exc}") from exc
    except OSError as exc:
        raise ExtractionStorageError(f"Could not write extracted files: {exc}") from exc

    return archive_root, entries, total_bytes


def _safe_segments(name: str, limits: ExtractionLimits) -> tuple[str, ...]:
    """Return a normalized path, or raise if the name is unsafe on any platform."""
    if any(ord(char) < 0x20 or ord(char) == 0x7F or 0xD800 <= ord(char) <= 0xDFFF for char in name):
        raise UnsafeArchiveError(f"Entry name has control or invalid characters: {name!r}")
    if name.startswith(("/", "\\")) or _WINDOWS_DRIVE.match(name):
        raise UnsafeArchiveError(f"Entry has an absolute path: {name!r}")
    # A backslash separates paths on Windows, so it counts as one for finding "..".
    if ".." in name.replace("\\", "/").split("/"):
        raise UnsafeArchiveError(f"Entry path contains a parent reference: {name!r}")

    segments = tuple(segment for segment in name.split("/") if segment not in ("", "."))
    if len(name.encode()) > limits.max_path_bytes:
        raise ArchiveLimitExceededError(f"Entry path exceeds {limits.max_path_bytes} bytes")
    if len(segments) > limits.max_depth:
        raise ArchiveLimitExceededError(f"Entry path is deeper than {limits.max_depth} levels")
    if any(len(segment.encode()) > limits.max_component_bytes for segment in segments):
        raise ArchiveLimitExceededError(
            f"Entry path has a component over {limits.max_component_bytes} bytes"
        )
    return segments


def _write_regular_file(
    tar: tarfile.TarFile,
    member: tarfile.TarInfo,
    relative: tuple[str, ...],
    destination: Path,
    limits: ExtractionLimits,
    total_so_far: int,
    stream: _BoundedStream,
) -> InventoryEntry:
    path = "/".join(relative)
    # A sparse entry expands to far more data than the archive holds.
    if member.issparse():
        raise UnsafeArchiveError(f"Sparse entries are not supported: {path!r}")
    if member.size > limits.max_file_bytes:
        raise ArchiveLimitExceededError(f"File exceeds {limits.max_file_bytes} bytes: {path!r}")
    if total_so_far + member.size > limits.max_total_bytes:
        raise ArchiveLimitExceededError(f"Files exceed {limits.max_total_bytes} bytes")

    source = tar.extractfile(member)
    if source is None:
        raise InvalidArchiveError(f"Cannot read entry: {path!r}")

    target = destination.joinpath(*relative)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    hasher = hashlib.sha256()
    size = 0
    sniffed = b""
    try:
        # O_EXCL also catches names that collide only on this filesystem, such as by case.
        descriptor = os.open(target, _CREATE_FLAGS, 0o600)
    except FileExistsError as exc:
        raise UnsafeArchiveError(f"Entry collides with another on this disk: {path!r}") from exc
    except (IsADirectoryError, NotADirectoryError) as exc:
        raise UnsafeArchiveError(f"Entry conflicts with another on this disk: {path!r}") from exc

    with os.fdopen(descriptor, "wb") as output:
        while chunk := source.read(CHUNK_SIZE):
            stream.check_deadline()
            size += len(chunk)
            if size > limits.max_file_bytes:
                raise ArchiveLimitExceededError(
                    f"File exceeds {limits.max_file_bytes} bytes: {path!r}"
                )
            if not sniffed:
                sniffed = chunk[:SNIFF_SIZE]
            hasher.update(chunk)
            output.write(chunk)
    if size != member.size:
        raise InvalidArchiveError(f"Entry is shorter than its header declares: {path!r}")

    mode = stat.S_IMODE(member.mode)
    return InventoryEntry(
        path=path,
        extension=PurePosixPath(path).suffix.lower(),
        kind=EntryKind.REGULAR,
        size_bytes=size,
        sha256=hasher.hexdigest(),
        content_type=_detect_content_type(sniffed),
        mode=f"{mode:04o}",
        is_executable=bool(mode & _EXECUTE_BITS),
    )


def _link_entry(
    member: tarfile.TarInfo, relative: tuple[str, ...], archive_root: str
) -> InventoryEntry:
    """Record a link without creating it, keeping what it declared as evidence."""
    path = "/".join(relative)
    target = member.linkname
    target_bytes = target.encode(errors="surrogateescape")
    mode = stat.S_IMODE(member.mode)
    if member.issym():
        kind = EntryKind.SYMLINK
        escapes = _symlink_escapes(relative, target)
    else:
        kind = EntryKind.HARDLINK
        escapes = _hardlink_escapes(target, archive_root)
    return InventoryEntry(
        path=path,
        extension=PurePosixPath(path).suffix.lower(),
        kind=kind,
        size_bytes=len(target_bytes),
        sha256=hashlib.sha256(target_bytes).hexdigest(),
        content_type=None,
        mode=f"{mode:04o}",
        is_executable=bool(mode & _EXECUTE_BITS),
        link_target=target.encode(errors="replace").decode(),
        link_escapes_root=escapes,
    )


def _symlink_escapes(relative: tuple[str, ...], target: str) -> bool:
    normalized_target = target.replace("\\", "/")
    if normalized_target.startswith("/") or _WINDOWS_DRIVE.match(normalized_target):
        return True
    resolved = posixpath.normpath(posixpath.join(*relative[:-1], normalized_target))
    return resolved == ".." or resolved.startswith("../")


def _hardlink_escapes(target: str, archive_root: str) -> bool:
    normalized_target = target.replace("\\", "/")
    if normalized_target.startswith("/") or _WINDOWS_DRIVE.match(normalized_target):
        return True
    resolved = posixpath.normpath(normalized_target)
    return not resolved.startswith(f"{archive_root}/")


def _special_entry(member: tarfile.TarInfo, relative: tuple[str, ...]) -> InventoryEntry:
    path = "/".join(relative)
    mode = stat.S_IMODE(member.mode)
    return InventoryEntry(
        path=path,
        extension=PurePosixPath(path).suffix.lower(),
        kind=EntryKind.SPECIAL,
        size_bytes=0,
        sha256=None,
        content_type=None,
        mode=f"{mode:04o}",
        is_executable=bool(mode & _EXECUTE_BITS),
    )


def _detect_content_type(head: bytes) -> ContentType:
    if not head:
        return ContentType.EMPTY
    for magic, content_type in _MAGIC_NUMBERS:
        if head.startswith(magic):
            return content_type
    if head.startswith(b"\xca\xfe\xba\xbe"):
        # Java classes and universal Mach-O binaries share a magic number. Bytes 6-7 hold
        # the class file version, which is at least 45. In Mach-O they are small.
        return ContentType.JAVA_CLASS if head[6:8] >= b"\x00\x2d" else ContentType.MACH_O
    if head.startswith(b"#!"):
        return ContentType.SCRIPT
    if head.startswith(b"MZ") and b"\0" in head:
        return ContentType.PE
    if b"\0" in head or not _is_utf8_prefix(head):
        return ContentType.BINARY
    return ContentType.TEXT


def _is_utf8_prefix(head: bytes) -> bool:
    """Check for valid UTF-8, allowing for a character cut off at the end of the sample."""
    try:
        head.decode()
    except UnicodeDecodeError as exc:
        return exc.start >= len(head) - 3 and exc.reason == "unexpected end of data"
    return True


def _findings(entries: list[InventoryEntry]) -> list[InventoryFinding]:
    findings: list[InventoryFinding] = []
    for entry in entries:
        if entry.link_escapes_root:
            findings.append(
                InventoryFinding(
                    kind=FindingKind.LINK_ESCAPES_ROOT,
                    path=entry.path,
                    detail=f"Link points outside the archive: {entry.link_target!r}",
                )
            )
        if entry.kind is EntryKind.SPECIAL:
            findings.append(
                InventoryFinding(
                    kind=FindingKind.SPECIAL_FILE,
                    path=entry.path,
                    detail="Device, FIFO or other special file. It was not created.",
                )
            )
        if entry.mode is not None and int(entry.mode, 8) & _PRIVILEGED_BITS:
            findings.append(
                InventoryFinding(
                    kind=FindingKind.PRIVILEGED_MODE,
                    path=entry.path,
                    detail=f"Archive declares setuid or setgid (mode {entry.mode}).",
                )
            )
    return findings


__all__ = ["ExtractionLimits", "extract_archive"]
