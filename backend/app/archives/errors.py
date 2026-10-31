class ExtractionError(Exception):
    """Base class for extraction failures. Nothing is left on disk after one of these."""


class InvalidArchiveError(ExtractionError):
    """The file is not a complete, well-formed gzip-compressed tar archive."""


class UnsafeArchiveError(ExtractionError):
    """An entry could write outside the destination or misrepresent the archive's contents."""


class ArchiveLimitExceededError(ExtractionError):
    """The archive exceeds a configured resource limit."""


class ExtractionStorageError(ExtractionError):
    """The destination cannot be used, or local storage failed."""
