"""Custom exceptions for ReconForge security and scanning operations."""


class ReconForgeError(Exception):
    """Base exception for all ReconForge errors."""


class ScopeViolationError(ReconForgeError):
    """Raised when an operation targets an IP address, CIDR, or port outside approved scope."""


class InvalidTargetError(ReconForgeError):
    """Raised when a target specification (IP, CIDR, or hostname) is syntactically invalid."""


class InvalidPortError(ReconForgeError):
    """Raised when a port or port range specification is invalid or out of legal range (1-65535)."""


class DNSResolutionError(ReconForgeError):
    """Raised when a hostname cannot be resolved or resolution times out."""


class ScanError(ReconForgeError):
    """Raised when an unrecoverable error occurs during network scanning."""


class ScanCancelledError(ReconForgeError):
    """Raised when an in-progress scan is explicitly cancelled."""


class ConfigurationError(ReconForgeError):
    """Raised when an invalid configuration is provided."""
