"""Data models for service fingerprinting and TLS metadata."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from reconforge.core.enums import ObservationConfidence, TransportProtocol


class TLSMetadata(BaseModel):
    """Observable TLS configuration and X.509 certificate metadata."""

    protocol_version: str | None = Field(
        default=None, description="Negotiated TLS version (e.g. TLSv1.3)."
    )
    cipher_suite: str | None = Field(default=None, description="Negotiated cipher suite.")
    subject_cn: str | None = Field(
        default=None, description="Common Name from certificate Subject."
    )
    issuer_cn: str | None = Field(
        default=None, description="Common Name of Certificate Authority Issuer."
    )
    subject_alt_names: list[str] = Field(
        default_factory=list, description="Subject Alternative Names (SANs)."
    )
    valid_from: datetime | None = Field(
        default=None, description="Certificate validity start date."
    )
    valid_until: datetime | None = Field(default=None, description="Certificate expiration date.")
    is_expired: bool = Field(default=False, description="True if current time exceeds valid_until.")
    is_self_signed: bool = Field(default=False, description="True if subject matches issuer.")
    serial_number: str | None = Field(default=None, description="Certificate serial number string.")


class ServiceFingerprint(BaseModel):
    """Empirically verified application service identification and metadata."""

    service_name: str = Field(
        default="unknown", description="Normalized service name (e.g. http, ssh)."
    )
    transport_protocol: TransportProtocol = Field(default=TransportProtocol.TCP)
    product: str | None = Field(
        default=None, description="Identified vendor or software product name."
    )
    version: str | None = Field(default=None, description="Identified software version string.")
    cpe_candidate: str | None = Field(
        default=None, description="Proposed CPE 2.3 identifier, if identifiable."
    )
    confidence: ObservationConfidence = Field(
        default=ObservationConfidence.UNKNOWN,
        description="Confidence level grounded in empirical evidence.",
    )
    banner_snippet: str | None = Field(
        default=None,
        description="Truncated, sanitized evidence snippet from protocol handshake.",
    )
    tls_info: TLSMetadata | None = Field(
        default=None, description="TLS certificate and cipher attributes."
    )
    probe_method: str = Field(
        default="generic_banner", description="Method utilized to obtain observation."
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    limitations: str | None = Field(
        default=None,
        description="Operational context or potential ambiguities in identification.",
    )
    source: str = Field(
        default="reconforge_internal", description="Originating engine (internal or nmap)."
    )
    extra_metadata: dict[str, Any] = Field(
        default_factory=dict, description="Safe auxiliary metadata."
    )
