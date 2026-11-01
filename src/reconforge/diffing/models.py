"""Domain models for assessment differencing, attack-surface drift, and coverage change detection."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class ScopeOverlapType(StrEnum):
    """Classification of target and port scope boundary overlap."""

    IDENTICAL = "identical"
    SUPERSET = "superset"
    SUBSET = "subset"
    PARTIAL_OVERLAP = "partial_overlap"
    DISJOINT = "disjoint"


class ChangeCertainty(StrEnum):
    """Certainty rating of observed change, preventing false remediation claims."""

    DEFINITIVE = "definitive"
    UNCERTAIN_SCOPE_MISMATCH = "uncertain_scope_mismatch"
    UNCERTAIN_REACHABILITY = "uncertain_reachability"


class RiskDirection(StrEnum):
    """Direction of overall attack-surface risk drift."""

    IMPROVED = "improved"
    DEGRADED = "degraded"
    STABLE = "stable"


class CoverageDelta(BaseModel):
    """Detailed comparison of assessment scope, ports, duration, and scanner versions."""

    base_scope_config: dict[str, Any] = Field(default_factory=dict)
    target_scope_config: dict[str, Any] = Field(default_factory=dict)
    base_targets: list[str] = Field(default_factory=list)
    target_targets: list[str] = Field(default_factory=list)
    common_targets: list[str] = Field(default_factory=list)
    unscanned_targets: list[str] = Field(default_factory=list)
    new_targets: list[str] = Field(default_factory=list)
    base_ports_count: int = 0
    target_ports_count: int = 0
    common_ports_count: int = 0
    unscanned_ports_count: int = 0
    new_ports_count: int = 0
    overlap_type: ScopeOverlapType = ScopeOverlapType.IDENTICAL
    is_coverage_complete: bool = True
    scanner_version_change: str | None = None
    warnings: list[str] = Field(default_factory=list)


class HostDelta(BaseModel):
    """Change detected in observed network host inventory."""

    ip_address: str
    hostnames: list[str] = Field(default_factory=list)
    criticality: str = "medium"
    change_type: str = "retained"  # "added", "removed", "retained"
    certainty: ChangeCertainty = ChangeCertainty.DEFINITIVE
    reason: str | None = None


class PortDelta(BaseModel):
    """Change detected in transport port state between assessments."""

    ip_address: str
    port: int
    protocol: str = "tcp"
    service_name: str = "unknown"
    product: str | None = None
    version: str | None = None
    change_type: str = "opened"  # "opened", "closed", "uncertain"
    certainty: ChangeCertainty = ChangeCertainty.DEFINITIVE
    reason: str | None = None


class ServiceModificationDelta(BaseModel):
    """Change detected in service identification, versioning, or confidence."""

    ip_address: str
    port: int
    protocol: str = "tcp"
    old_service_name: str
    new_service_name: str
    old_product: str | None = None
    new_product: str | None = None
    old_version: str | None = None
    new_version: str | None = None
    old_confidence: str
    new_confidence: str
    is_upgrade: bool = False
    notes: str | None = None


class FindingDelta(BaseModel):
    """Change detected in exposure rule finding or vulnerability state."""

    finding_id: str
    rule_id: str
    cve_id: str | None = None
    title: str
    severity: str
    priority: str
    target_ip: str
    port: int | None = None
    change_type: str = "new"  # "new", "resolved", "persisting", "regressed"
    certainty: ChangeCertainty = ChangeCertainty.DEFINITIVE
    resolution_reason: str | None = None


class RiskDelta(BaseModel):
    """Mathematical and categorical shift in attack-surface risk posture."""

    base_score: float
    target_score: float
    score_delta: float
    base_risk_level: str
    target_risk_level: str
    direction: RiskDirection
    priority_changes: dict[str, int] = Field(default_factory=dict)


class AssessmentDiff(BaseModel):
    """Comprehensive, explainable diff report comparing two assessment states."""

    diff_id: str = Field(default_factory=lambda: str(uuid4()))
    base_assessment_id: str
    target_assessment_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    coverage: CoverageDelta
    added_hosts: list[HostDelta] = Field(default_factory=list)
    removed_hosts: list[HostDelta] = Field(default_factory=list)
    retained_hosts_count: int = 0
    opened_ports: list[PortDelta] = Field(default_factory=list)
    closed_ports: list[PortDelta] = Field(default_factory=list)
    uncertain_ports: list[PortDelta] = Field(default_factory=list)
    modified_services: list[ServiceModificationDelta] = Field(default_factory=list)
    new_findings: list[FindingDelta] = Field(default_factory=list)
    resolved_findings: list[FindingDelta] = Field(default_factory=list)
    persisting_findings: list[FindingDelta] = Field(default_factory=list)
    regressed_findings: list[FindingDelta] = Field(default_factory=list)
    risk: RiskDelta
    summary_narrative: list[str] = Field(default_factory=list)
