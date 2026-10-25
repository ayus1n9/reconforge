"""Data models for scope definitions, scan configurations, and network observations."""

import ipaddress
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from reconforge.core.enums import (
    AddressFamily,
    PortState,
    ScanStatus,
    TransportProtocol,
)
from reconforge.core.exceptions import InvalidTargetError
from reconforge.utils.network import is_valid_hostname, parse_ip_or_network


class TargetScope(BaseModel):
    """Authorization boundary configuration.

    Scanning is strictly limited to targets and ports permitted by this model.
    """

    allowed_targets: list[str] = Field(
        ..., description="Explicitly authorized IP addresses, CIDRs, or hostnames."
    )
    excluded_targets: list[str] = Field(
        default_factory=list,
        description="Explicitly excluded targets (blacklisted even if inside an allowed CIDR).",
    )
    allowed_ports: str | list[int | str] = Field(
        default="1-1024",
        description="Authorized port ranges or lists (e.g., '80,443,8000-8080').",
    )
    allow_public_targets: bool = Field(
        default=False,
        description="Safety flag: If False, any target with a public IP is rejected.",
    )
    allow_cloud_metadata: bool = Field(
        default=False,
        description="Safety flag: If False, addresses like 169.254.169.254 are rejected.",
    )
    lab_mode: bool = Field(
        default=True,
        description="Explicit lab mode flag confirming assessment in an authorized isolated environment.",
    )
    description: str = Field(
        default="",
        description="Human-readable assessment context or authorization note.",
    )

    @field_validator("allowed_targets", "excluded_targets")
    @classmethod
    def validate_targets(cls, targets: list[str]) -> list[str]:
        cleaned_targets = []
        for t in targets:
            cleaned = t.strip()
            if not cleaned:
                continue
            # Validate that each target is either a valid IP/CIDR or valid RFC 1123 hostname
            try:
                parse_ip_or_network(cleaned)
            except InvalidTargetError as err:
                if not is_valid_hostname(cleaned):
                    raise InvalidTargetError(
                        f"Target '{cleaned}' is not a valid IP address, CIDR, or RFC 1123 hostname."
                    ) from err
            cleaned_targets.append(cleaned)

        return cleaned_targets


class ScanTarget(BaseModel):
    """A concrete, resolved assessment destination.

    The IP address is pinned to prevent DNS rebinding attacks.
    """

    ip: str = Field(..., description="Canonical IP address string.")
    hostname: str | None = Field(default=None, description="Original hostname if resolved via DNS.")
    address_family: AddressFamily = Field(..., description="IPv4 or IPv6.")
    is_pinned: bool = Field(
        default=True, description="Indicates IP is cryptographically/logically pinned."
    )

    @property
    def ip_obj(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        return ipaddress.ip_address(self.ip)


class PortObservation(BaseModel):
    """Empirical observation of a target port.

    Contains strictly factual data derived from network interaction.
    """

    target_ip: str
    hostname: str | None = None
    port: int
    protocol: TransportProtocol = TransportProtocol.TCP
    state: PortState
    response_time_ms: float | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    error_message: str | None = None
    source: str = "internal_tcp_connect"


class HostDiscoveryResult(BaseModel):
    """Result of conservative host discovery check."""

    target_ip: str
    hostname: str | None = None
    is_alive: bool
    responding_port: int | None = None
    latency_ms: float | None = None
    method: str = "tcp_probe"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanConfig(BaseModel):
    """Operational constraints for TCP discovery."""

    timeout_seconds: float = Field(default=2.0, ge=0.1, le=30.0)
    concurrency: int = Field(default=50, ge=1, le=500, description="Bounded concurrency ceiling.")
    rate_limit_per_second: int = Field(
        default=100, ge=0, description="Max probes per sec (0 = unthrottled)."
    )
    skip_host_discovery: bool = Field(
        default=True, description="Directly scan ports without pre-ping."
    )
    host_discovery_ports: list[int] = Field(default_factory=lambda: [80, 443, 22, 445])
    max_retries: int = Field(default=0, ge=0, le=2)


class ScanProgress(BaseModel):
    """Real-time progress telemetry."""

    total_targets: int
    total_probes: int
    completed_probes: int
    open_ports_count: int
    elapsed_seconds: float

    @property
    def percentage(self) -> float:
        if self.total_probes == 0:
            return 100.0
        return round((self.completed_probes / self.total_probes) * 100, 1)


class ScanSummary(BaseModel):
    """Final assessment summary statistics."""

    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    targets_assessed: int
    probes_attempted: int
    open_count: int
    closed_count: int
    filtered_count: int
    timeout_count: int
    unreachable_count: int
    error_count: int
    duration_seconds: float
    status: ScanStatus
