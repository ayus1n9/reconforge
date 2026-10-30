"""Data models for attack-surface scoring, component breakdown, and risk posture."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from reconforge.core.enums import AssetCriticality, RiskPriority


class ScoreBreakdown(BaseModel):
    """Component breakdown explaining how an attack-surface score was derived."""

    exposure_base: float = Field(
        ...,
        ge=0.0,
        description="Base score from open port count and sensitive cleartext/management protocols.",
    )
    findings_subtotal: float = Field(
        ..., ge=0.0, description="Weighted sum of active security findings and potential exposures."
    )
    criticality_factor: float = Field(
        ...,
        ge=0.1,
        description="Asset criticality multiplier (e.g. 1.5 for critical, 0.8 for low).",
    )
    threat_multiplier: float = Field(
        ..., ge=1.0, description="Threat intelligence multiplier (e.g. 1.35 if listed in CISA KEV)."
    )
    raw_score: float = Field(..., ge=0.0, description="Unclamped mathematical composite score.")
    final_score: float = Field(
        ..., ge=0.0, le=100.0, description="Normalized score clamped to the 0.0 to 100.0 scale."
    )
    component_explanations: list[str] = Field(
        default_factory=list,
        description="Step-by-step human-readable audit trail of scoring factors.",
    )


class AssetRiskScore(BaseModel):
    """Defensible, multi-factor risk score for an individual network asset."""

    asset_id: str = Field(..., description="Unique asset identifier UUID.")
    ip_address: str = Field(..., description="Canonical IP address of the target asset.")
    criticality: AssetCriticality = Field(
        default=AssetCriticality.MEDIUM, description="Assigned asset criticality."
    )
    score: float = Field(..., ge=0.0, le=100.0, description="Final risk score on 0.0-100.0 scale.")
    risk_level: str = Field(
        ..., description="Categorical risk tier (CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE)."
    )
    top_priority: RiskPriority = Field(
        ..., description="Highest urgency remediation priority (P1-P5)."
    )
    breakdown: ScoreBreakdown = Field(..., description="Transparent mathematical breakdown.")
    active_findings_count: int = Field(
        default=0, ge=0, description="Count of unmitigated findings."
    )
    open_services_count: int = Field(
        default=0, ge=0, description="Count of open network transport services."
    )


class AssessmentRiskPosture(BaseModel):
    """Aggregate risk posture and prioritized threat profile for an assessment run."""

    assessment_id: str = Field(..., description="Assessment execution UUID.")
    overall_score: float = Field(
        ..., ge=0.0, le=100.0, description="Composite assessment posture score on 0.0-100.0 scale."
    )
    risk_level: str = Field(
        ..., description="Composite risk level (CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE)."
    )
    assessed_assets_count: int = Field(default=0, ge=0, description="Total assets evaluated.")
    assets_at_risk_count: int = Field(default=0, ge=0, description="Assets with risk score > 0.")
    priority_distribution: dict[str, int] = Field(
        default_factory=dict, description="Count of findings per priority tier (P1..P5)."
    )
    severity_distribution: dict[str, int] = Field(
        default_factory=dict, description="Count of findings per severity rating."
    )
    asset_scores: list[AssetRiskScore] = Field(
        default_factory=list, description="List of per-asset risk evaluations."
    )
    key_exposure_drivers: list[str] = Field(
        default_factory=list,
        description="Primary technical conditions elevating attack-surface risk.",
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Calculation timestamp."
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional context or scope summary."
    )
