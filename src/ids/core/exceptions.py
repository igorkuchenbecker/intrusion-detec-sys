"""Exception hierarchy.

A single root (:class:`IDSError`) lets each layer catch what this package
raises without resorting to a bare ``except Exception`` that would also
swallow genuine bugs.
"""

from __future__ import annotations

__all__ = [
    "IDSError",
    "ConfigurationError",
    "CaptureError",
    "PrivilegeError",
    "StorageError",
    "DetectionError",
]


class IDSError(Exception):
    """Base class for every error raised by this package."""


class ConfigurationError(IDSError):
    """Raised when user-supplied configuration is invalid."""


class CaptureError(IDSError):
    """Raised when packet capture cannot start or fails irrecoverably."""


class PrivilegeError(CaptureError):
    """Raised when capture is attempted without the required privileges."""


class StorageError(IDSError):
    """Raised when the database cannot be opened or a query fails."""


class DetectionError(IDSError):
    """Raised by a rule that cannot evaluate an event.

    The detection engine catches this per rule so one broken rule cannot stop
    the others or the pipeline.
    """
