"""Data models and enumerations for vulnerability intelligence and CVE correlation."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from reconforge.core.enums import SeverityLevel


class CVEMatchLevel(StrEnum):
    """Calibrated confidence rating indicating the certainty of a CVE correlation."""

    STRONG_CANDIDATE = "strong_candidate"
    """Exact vendor, product, and version range matched with uncompromised evidence."""

    POSSIBLE_MATCH = "possible_match"
    """Product matches, but version string is ambiguous or falls within an unconfirmed range."""

    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    """Product identified, but software version is unknown, redacted, or unobserved in banner."""

    MANUAL_VERIFICATION_REQUIRED = "manual_verification_required"
    """Distro-specific packaging (e.g. Debian/Ubuntu/RHEL backports) or custom compilation detected."""


class CVEItem(BaseModel):
    """Normalized Common Vulnerabilities and Exposures (CVE) intelligence document."""

    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$", description="Official CVE identifier.")
    description: str = Field(
        ..., description="Vulnerability technical description and impact summary."
    )
    cvss_v3_score: float | None = Field(
        default=None, ge=0.0, le=10.0, description="CVSS v3.x base score."
    )
    cvss_v3_vector: str | None = Field(default=None, description="CVSS v3.x vector string.")
    severity: SeverityLevel = Field(
        default=SeverityLevel.MEDIUM, description="Normalized severity classification."
    )
    cwe_ids: list[str] = Field(default_factory=list, description="Associated CWE identifiers.")
    affected_cpes: list[str] = Field(
        default_factory=list, description="Affected CPE 2.3 criteria strings."
    )
    version_criteria: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Version boundaries (e.g., versionStartIncluding, versionEndExcluding).",
    )
    references: list[str] = Field(
        default_factory=list, description="Advisory URLs and vendor bulletins."
    )
    published_date: datetime | None = Field(
        default=None, description="Publication timestamp in UTC."
    )
    last_modified_date: datetime | None = Field(
        default=None, description="Last modification timestamp in UTC."
    )
    is_known_exploited: bool = Field(
        default=False,
        description="Flag indicating listing in CISA Known Exploited Vulnerabilities catalog.",
    )


class CVECorrelationResult(BaseModel):
    """Evidence-backed result of correlating a network service against vulnerability intelligence."""

    cve: CVEItem
    match_level: CVEMatchLevel
    matched_cpe: str
    matched_version: str | None = None
    evidence_rationale: str
    remediation: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
