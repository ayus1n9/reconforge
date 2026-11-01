"""Pydantic request and response schemas for ReconForge REST API."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    """Health status response."""

    status: str = "ok"
    version: str
    timestamp: str


class SystemInfoResponse(BaseModel):
    """System information and operational metrics."""

    version: str
    python_version: str
    platform: str
    database_status: str
    total_assets: int
    total_assessments: int
    total_findings: int
    rules_count: int
    cached_cves_count: int
    nmap_available: bool


class ScopeValidationRequest(BaseModel):
    """Scope verification request."""

    targets: list[str] = Field(
        ..., min_length=1, description="List of IP addresses, hostnames, or CIDRs"
    )
    ports: str = Field(
        default="21,22,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443",
        description="Port list or ranges",
    )
    allow_public: bool = Field(default=False, description="Authorize public IP addresses")
    excluded_targets: list[str] = Field(
        default_factory=list, description="Explicit target exclusions"
    )


class ScopeValidationResponse(BaseModel):
    """Scope validation results."""

    valid: bool
    total_targets: int
    allowed_targets: list[str]
    allowed_ports_count: int
    warnings: list[str] = Field(default_factory=list)
    error: str | None = None


class AssessmentLaunchRequest(BaseModel):
    """Parameters to launch an asynchronous network discovery assessment."""

    name: str = Field(default="Assessment", max_length=150)
    targets: list[str] = Field(..., min_length=1)
    ports: str = Field(default="21,22,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443")
    concurrency: int = Field(default=50, ge=1, le=500)
    rate_limit: int = Field(default=100, ge=0, le=5000)
    timeout: float = Field(default=2.0, ge=0.1, le=30.0)
    allow_public: bool = False
    host_discovery: bool = False
    fingerprint: bool = True
    use_nmap: bool = False
    assess: bool = True
    correlate_cves: bool = False


class AssessmentLaunchResponse(BaseModel):
    """Immediate response after queuing a background assessment."""

    assessment_id: str
    name: str
    status: str
    message: str


class AssessmentProgressResponse(BaseModel):
    """Active probe execution progress."""

    assessment_id: str
    status: str
    completed_probes: int
    total_probes: int
    percent_complete: float
    elapsed_seconds: float


class AssessmentListItem(BaseModel):
    """Summary of an assessment execution run."""

    id: str
    name: str
    status: str
    start_time: datetime
    end_time: datetime | None
    risk_score: float | None
    findings_count: int = 0
    assets_count: int = 0


class AssessmentDetailResponse(BaseModel):
    """Detailed view of an assessment including scope, coverage, and posture."""

    id: str
    name: str
    status: str
    scanner_version: str
    scope_config: dict[str, Any]
    start_time: datetime
    end_time: datetime | None
    coverage_metrics: dict[str, Any]
    risk_score: float | None
    risk_posture: dict[str, Any] | None
    error_summary: str | None
    live_progress: AssessmentProgressResponse | None = None
    findings_count: int = 0


class ServiceDetailResponse(BaseModel):
    """Identified network transport service."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    port: int
    protocol: str
    service_name: str
    product: str | None = None
    version: str | None = None
    confidence: str
    banner_snippet: str | None = None
    cpe_candidate: str | None = None
    tls_metadata: dict[str, Any] | None = None
    first_observed_at: datetime
    last_observed_at: datetime


class AssetListItem(BaseModel):
    """Summary representation of a network asset."""

    id: str
    ip_address: str
    address_family: str
    observed_hostnames: list[str]
    criticality: str
    services_count: int
    risk_score: float | None
    last_observed_at: datetime


class AssetDetailResponse(BaseModel):
    """Detailed asset record with services and risk information."""

    id: str
    ip_address: str
    address_family: str
    observed_hostnames: list[str]
    asset_type: str
    criticality: str
    first_observed_at: datetime
    last_observed_at: datetime
    discovery_sources: list[str]
    risk_score: float | None
    risk_breakdown: dict[str, Any] | None
    services: list[ServiceDetailResponse]
    findings_count: int = 0


class FindingListItem(BaseModel):
    """Summary item for a finding."""

    id: str
    assessment_id: str
    asset_id: str
    target_ip: str | None = None
    port: int | None = None
    rule_id: str
    cve_id: str | None = None
    title: str
    severity: str
    priority: str
    state: str
    created_at: datetime


class FindingDetailResponse(BaseModel):
    """Comprehensive finding details with evidence and remediation."""

    id: str
    assessment_id: str
    asset_id: str
    service_id: str | None = None
    target_ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    rule_id: str
    cve_id: str | None = None
    title: str
    description: str
    severity: str
    priority: str
    state: str
    evidence: dict[str, Any]
    remediation_guidance: str | None = None
    created_at: datetime
    updated_at: datetime


class FindingStateUpdateRequest(BaseModel):
    """Finding lifecycle state modification."""

    state: str = Field(..., description="confirmed, false_positive, accepted_risk, needs_review")
    reason: str | None = Field(default=None, description="Auditable justification note")


class AssessmentPostureResponse(BaseModel):
    """Risk posture breakdown for an assessment."""

    assessment_id: str
    risk_score: float
    risk_level: str
    priority_distribution: dict[str, int]
    asset_scores: list[dict[str, Any]]


class AssetScoreDetailResponse(BaseModel):
    """Mathematical asset scoring explanation."""

    asset_id: str
    ip_address: str
    criticality: str
    risk_score: float
    risk_level: str
    exposure_base: float
    findings_weighted: float
    criticality_multiplier: float
    threat_multiplier: float
    component_explanations: list[str]


class DiffRequest(BaseModel):
    """Assessment IDs to compare."""

    base_id: str
    target_id: str


class SnapshotImportResponse(BaseModel):
    """Result of snapshot import."""

    imported_assessment_id: str
    assessment_name: str
    assets_count: int
    services_count: int
    findings_count: int
    message: str
