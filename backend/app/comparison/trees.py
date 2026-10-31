"""Read extracted files through their inventory, confirming each still matches its hash."""

import hashlib
import os
import posixpath

from app.archives.models import EntryKind, FileInventory, InventoryEntry


class ComparisonIntegrityError(Exception):
    """An extracted file no longer matches its inventory entry."""


def normalize_relative(path: str) -> str | None:
    """Return a clean relative path. The root is an empty string, and escapes return None."""
    cleaned = path.strip().replace("\\", "/")
    if not cleaned or cleaned.startswith("/") or "\0" in cleaned:
        return None
    normalized = posixpath.normpath(cleaned)
    if normalized == "..":
        return None
    if normalized.startswith("../"):
        return None
    return "" if normalized == "." else normalized


def is_within(path: str, directory: str) -> bool:
    return path.startswith(f"{directory}/")


class FileTree:
    """A view of an inventory, optionally limited to one subdirectory."""

    def __init__(self, inventory: FileInventory, directory: str = "") -> None:
        self._inventory = inventory
        self.directory = directory
        prefix = f"{directory}/" if directory else ""
        self.entries: dict[str, InventoryEntry] = {
            entry.path.removeprefix(prefix): entry
            for entry in inventory.entries
            if entry.path.startswith(prefix)
        }

    def read(self, path: str, max_bytes: int) -> bytes | None:
        """Return a regular file's bytes, or None if it is absent, not regular or too large."""
        entry = self.entries.get(path)
        if entry is None or entry.kind is not EntryKind.REGULAR or entry.size_bytes > max_bytes:
            return None
        target = self._inventory.root.joinpath(*entry.path.split("/"))
        descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as file:
            data = file.read(max_bytes + 1)
        if hashlib.sha256(data).hexdigest() != entry.sha256:
            raise ComparisonIntegrityError(f"Extracted file changed: {entry.path!r}")
        return data
