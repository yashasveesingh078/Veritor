from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class EntryKind(StrEnum):
    REGULAR = "regular"
    SYMLINK = "symlink"
    HARDLINK = "hardlink"
    SPECIAL = "special"


class ContentType(StrEnum):
    """A label from the leading bytes of a file. It describes the file, not its safety."""

    EMPTY = "empty"
    TEXT = "text"
    SCRIPT = "script"
    BINARY = "binary"
    ELF = "elf"
    MACH_O = "mach_o"
    PE = "pe"
    WASM = "wasm"
    JAVA_CLASS = "java_class"
    GZIP = "gzip"
    ZIP = "zip"
    PNG = "png"
    JPEG = "jpeg"
    GIF = "gif"
    PDF = "pdf"


class FindingKind(StrEnum):
    LINK_ESCAPES_ROOT = "link_escapes_root"
    SPECIAL_FILE = "special_file"
    PRIVILEGED_MODE = "privileged_mode"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class InventoryEntry(_FrozenModel):
    path: str = Field(description="Path relative to the archive's root directory.")
    extension: str = Field(description="Lowercase final suffix with its dot, or an empty string.")
    kind: EntryKind
    size_bytes: int = Field(description="Bytes of content, or of the target path for a link.")
    sha256: str | None = Field(
        description="Hash of the content, or of the target path for a link. None if special."
    )
    content_type: ContentType | None = Field(description="None for anything but a regular file.")
    mode: str | None = Field(
        description="Permission bits declared in the archive, in octal. Never applied on disk."
    )
    is_executable: bool = Field(description="Whether the archive declares an execute bit.")
    link_target: str | None = None
    link_escapes_root: bool = False


class InventoryFinding(_FrozenModel):
    kind: FindingKind
    path: str
    detail: str


class FileInventory(_FrozenModel):
    root: Path = Field(description="The directory holding the extracted regular files.")
    archive_sha256: str
    archive_size_bytes: int
    archive_root: str | None = Field(description="The top-level directory removed from each path.")
    entries: tuple[InventoryEntry, ...] = Field(description="Every non-directory entry, by path.")
    total_bytes: int = Field(description="Total size of the regular files.")
    findings: tuple[InventoryFinding, ...]
