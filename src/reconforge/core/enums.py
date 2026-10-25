"""Core enumerations representing observable network states and scanner lifecycles."""

from enum import StrEnum


class PortState(StrEnum):
    """
    Observable states of a network transport port.

    Each state represents a factual, evidence-backed observation rather than an assumption.
    """

    OPEN = "open"
    """TCP three-way handshake successfully established and confirmed."""

    CLOSED = "closed"
    """TCP RST packet or active connection refusal received from target."""

    TIMEOUT = "timeout"
    """Connection attempt timed out without response. Inconclusive: host may be silent, dropped, or lagging."""

    FILTERED = "filtered"
    """ICMP administratively prohibited or explicit firewall drop indication observed."""

    UNREACHABLE = "unreachable"
    """Host or network unreachable error returned by the operating system networking stack."""

    ERROR = "error"
    """Operating system or socket exception occurred during the connection attempt."""

    NOT_SCANNED = "not_scanned"
    """Target was defined in assessment scope but skipped or cancelled prior to probe execution."""


class AddressFamily(StrEnum):
    """Internet Protocol address family."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"


class TransportProtocol(StrEnum):
    """Transport layer protocol."""

    TCP = "tcp"
    UDP = "udp"


class ScanStatus(StrEnum):
    """Lifecycle state of an assessment or scan job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ObservationConfidence(StrEnum):
    """Confidence level assigned to an observation or fingerprint."""

    HIGH = "high"
    """Direct, unambiguous evidence (e.g., protocol handshake and matching version string)."""

    MEDIUM = "medium"
    """Corroborated evidence or standard response signature without full version string."""

    LOW = "low"
    """Inferred based on weak heuristics, banners with unknown structures, or port defaults."""

    UNKNOWN = "unknown"
    """Port state confirmed but service or application identity is unverified."""
