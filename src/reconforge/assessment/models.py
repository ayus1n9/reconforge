"""Data models for exposure rules, conditions, and assessment findings."""

import re
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from reconforge.core.enums import (
    FindingCategory,
    FindingState,
    ObservationConfidence,
    SeverityLevel,
)


class RuleCondition(BaseModel):
    """Declarative criteria for evaluating network exposures on open ports and services."""

    ports: list[int] = Field(
        default_factory=list,
        description="Target transport port numbers (1-65535) that trigger this condition.",
    )
    protocols: list[str] = Field(
        default_factory=lambda: ["tcp"],
        description="Transport protocols to evaluate (e.g. 'tcp', 'udp').",
    )
    service_names: list[str] = Field(
        default_factory=list,
        description="Identified service names (e.g. 'http', 'ssh', 'redis').",
    )
    products: list[str] = Field(
        default_factory=list,
        description="Software product names (e.g. 'nginx', 'OpenSSH').",
    )
    version_pattern: str | None = Field(
        default=None,
        description="Regular expression to test against software version string.",
    )
    banner_pattern: str | None = Field(
        default=None,
        description="Regular expression to test against raw service banner snippet.",
    )
    tls_conditions: dict[str, Any] | None = Field(
        default=None,
        description="Cryptographic/TLS checks (e.g. {'expired': True}, {'self_signed': True}).",
    )
    require_all: bool = Field(
        default=False,
        description="If True, all specified conditions must match. If False, any condition matches.",
    )

    @field_validator("ports")
    @classmethod
    def validate_port_ranges(cls, v: list[int]) -> list[int]:
        for port in v:
            if not (1 <= port <= 65535):
                raise ValueError(f"Port number {port} is out of valid range (1-65535).")
        return v

    @field_validator("version_pattern", "banner_pattern")
    @classmethod
    def validate_regex_pattern(cls, v: str | None) -> str | None:
        if v:
            if len(v) > 500:
                raise ValueError("Regular expression pattern exceeds 500 character limit.")
            try:
                re.compile(v)
            except re.error as err:
                raise ValueError(f"Invalid regular expression '{v}': {err}") from err
        return v


class ExposureRuleDefinition(BaseModel):
    """Schema for declarative exposure detection rules."""

    id: str = Field(
        ...,
        pattern=r"^[A-Z0-9_\-]+$",
        description="Unique identifier for the exposure rule (e.g. 'EXP-CLEARTEXT-TELNET').",
    )
    name: str = Field(..., max_length=150, description="Human-readable rule name.")
    description: str = Field(
        ..., max_length=2000, description="Comprehensive explanation of the exposure and risk."
    )
    severity: SeverityLevel = Field(
        ..., description="Default severity classification of the exposure."
    )
    category: FindingCategory = Field(..., description="Category grouping for the exposure rule.")
    default_state: FindingState = Field(
        default=FindingState.POTENTIAL_EXPOSURE,
        description="Initial defensible finding state.",
    )
    conditions: RuleCondition = Field(
        ..., description="Criteria required to trigger this exposure rule."
    )
    remediation: str = Field(
        ..., max_length=2000, description="Actionable vendor-neutral remediation guidance."
    )
    references: list[str] = Field(
        default_factory=list,
        description="Standard reference links or identifiers (e.g. CWE, NIST SP 800-53).",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Metadata tags (e.g. ['encryption', 'cleartext', 'critical-service']).",
    )
    enabled: bool = Field(
        default=True, description="Whether this rule is active during evaluations."
    )


class Finding(BaseModel):
    """Concrete security finding produced by evaluating exposure rules against inventoried assets."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    assessment_id: str = Field(..., description="UUID of the assessment run.")
    asset_id: str = Field(..., description="UUID of the affected asset.")
    service_id: str | None = Field(
        default=None, description="UUID of the affected service, if applicable."
    )
    rule_id: str = Field(..., description="ID of the triggering exposure rule.")
    cve_id: str | None = Field(
        default=None, description="Correlated CVE identifier, if applicable."
    )
    title: str = Field(..., max_length=255)
    description: str = Field(...)
    severity: SeverityLevel
    state: FindingState = Field(default=FindingState.POTENTIAL_EXPOSURE)
    confidence: ObservationConfidence = Field(default=ObservationConfidence.HIGH)
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Empirical evidence backing this finding (e.g. port, protocol, banner, TLS details).",
    )
    remediation_guidance: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
