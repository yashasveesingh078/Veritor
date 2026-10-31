class AdapterError(Exception):
    """Base class for every failure raised by a package adapter."""


class InvalidPackageRequestError(AdapterError):
    """The package name or version is not valid for the ecosystem."""


class RegistryNotFoundError(AdapterError):
    """The registry reports that a requested resource does not exist."""


class PackageNotFoundError(RegistryNotFoundError):
    """The package does not exist on the registry."""


class VersionNotFoundError(RegistryNotFoundError):
    """The package exists, but this version is not available."""


class RegistryUnavailableError(AdapterError):
    """The registry could not be reached or reported a temporary failure."""


class RegistryTimeoutError(RegistryUnavailableError):
    """The registry did not respond within the configured time."""


class InvalidRegistryResponseError(AdapterError):
    """The registry response is malformed or breaks a safety rule."""


class ResponseTooLargeError(AdapterError):
    """A response exceeds the configured size limit."""


class IntegrityVerificationError(AdapterError):
    """An artifact has no published hash, or does not match its published hash."""


class ArtifactStorageError(AdapterError):
    """A verified artifact could not be written to local storage."""
