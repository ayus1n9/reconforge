"""Domain models for structured security assessment reports."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from reconforge.scoring.models import AssessmentRiskPosture


class ReportMetadata(BaseModel):
    """Administrative and versioning metadata for an assessment report."""

    title: str = Field(
        default="ReconForge Attack-Surface Exposure & Security Intelligence Report",
        description="Official title of the generated report.",
    )
    assessment_id: str = Field(..., description="Unique UUID of the referenced assessment.")
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Report generation timestamp in UTC."
    )
    scanner_version: str = Field(
        default="0.6.0", description="ReconForge platform release version."
    )
    classification: str = Field(
        default="CONFIDENTIAL - INTERNAL SECURITY ASSESSMENT",
        description="Information classification marking.",
    )
    organization: str = Field(
        default="Authorized Security Operations", description="Organization or team name."
    )


class FindingSummary(BaseModel):
    """Normalized finding representation for multi-format report exports."""

    id: str = Field(..., description="Finding UUID.")
    rule_id: str = Field(..., description="Exposure rule or CVE identifier.")
    cve_id: str | None = Field(default=None, description="Correlated CVE identifier.")
    title: str = Field(..., description="Short finding title.")
    severity: str = Field(
        ..., description="Severity classification (critical, high, medium, low, info)."
    )
    priority: str = Field(default="P4", description="Remediation priority tier (P1-P5).")
    state: str = Field(..., description="Finding lifecycle state.")
    target_ip: str = Field(..., description="Asset canonical IP address.")
    port: int | None = Field(default=None, description="Target transport port.")
    description: str = Field(..., description="Vulnerability description or exposure rationale.")
    remediation_guidance: str | None = Field(
        default=None, description="Actionable remediation steps and mitigation guidance."
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Observable technical parameters and proof."
    )


class AssetSummary(BaseModel):
    """Normalized asset overview included in assessment report."""

    id: str = Field(..., description="Asset UUID.")
    ip_address: str = Field(..., description="Canonical IP address.")
    criticality: str = Field(default="medium", description="Asset criticality tier.")
    risk_score: float = Field(default=0.0, description="Calculated attack-surface score.")
    risk_level: str = Field(default="NEGLIGIBLE", description="Risk level designation.")
    services_count: int = Field(default=0, description="Total exposed network services.")
    open_ports: list[int] = Field(default_factory=list, description="List of open port numbers.")
    findings_count: int = Field(default=0, description="Count of active security findings.")


class AssessmentReport(BaseModel):
    """Complete, self-contained assessment report document."""

    metadata: ReportMetadata
    scope_config: dict[str, Any] = Field(
        default_factory=dict, description="Authorized target boundaries."
    )
    coverage_metrics: dict[str, Any] = Field(
        default_factory=dict, description="Scan execution metrics."
    )
    risk_posture: AssessmentRiskPosture
    assets: list[AssetSummary] = Field(default_factory=list)
    findings: list[FindingSummary] = Field(default_factory=list)
    remediation_roadmap: list[dict[str, Any]] = Field(
        default_factory=list, description="Prioritized remediation actions."
    )
