export interface HealthResponse {
  status: string;
  version: string;
  timestamp: string;
}

export interface SystemInfoResponse {
  version: string;
  python_version: string;
  platform: string;
  database_status: string;
  total_assets: number;
  total_assessments: number;
  total_findings: number;
  rules_count: number;
  cached_cves_count: number;
  nmap_available: boolean;
}

export interface ScopeValidationRequest {
  targets: string[];
  ports?: string;
  allow_public?: boolean;
  excluded_targets?: string[];
}

export interface ScopeValidationResponse {
  valid: boolean;
  total_targets: number;
  allowed_targets: string[];
  allowed_ports_count: number;
  warnings: string[];
  error?: string | null;
}

export interface AssessmentLaunchRequest {
  name?: string;
  targets: string[];
  ports?: string;
  concurrency?: number;
  rate_limit?: number;
  timeout?: number;
  allow_public?: boolean;
  host_discovery?: boolean;
  fingerprint?: boolean;
  use_nmap?: boolean;
  assess?: boolean;
  correlate_cves?: boolean;
}

export interface AssessmentLaunchResponse {
  assessment_id: string;
  name: string;
  status: string;
  message: string;
}

export interface AssessmentProgressResponse {
  assessment_id: string;
  status: string;
  completed_probes: number;
  total_probes: number;
  percent_complete: number;
  elapsed_seconds: number;
}

export interface AssessmentListItem {
  id: string;
  name: string;
  status: string;
  start_time: string;
  end_time?: string | null;
  risk_score?: number | null;
  findings_count: number;
  assets_count: number;
}

export interface AssessmentDetailResponse {
  id: string;
  name: string;
  status: string;
  scanner_version: string;
  scope_config: Record<string, any>;
  start_time: string;
  end_time?: string | null;
  coverage_metrics: Record<string, any>;
  risk_score?: number | null;
  risk_posture?: {
    risk_score?: number;
    risk_level?: string;
    priority_distribution?: Record<string, number>;
  } | null;
  error_summary?: string | null;
  live_progress?: AssessmentProgressResponse | null;
  findings_count: number;
}

export interface ServiceDetailResponse {
  id: string;
  port: number;
  protocol: string;
  service_name: string;
  product?: string | null;
  version?: string | null;
  confidence: string;
  banner_snippet?: string | null;
  cpe_candidate?: string | null;
  tls_metadata?: Record<string, any> | null;
  first_observed_at: string;
  last_observed_at: string;
}

export interface AssetListItem {
  id: string;
  ip_address: string;
  address_family: string;
  observed_hostnames: string[];
  criticality: string;
  services_count: number;
  risk_score?: number | null;
  last_observed_at: string;
}

export interface AssetDetailResponse {
  id: string;
  ip_address: string;
  address_family: string;
  observed_hostnames: string[];
  asset_type: string;
  criticality: string;
  first_observed_at: string;
  last_observed_at: string;
  discovery_sources: string[];
  risk_score?: number | null;
  risk_breakdown?: Record<string, any> | null;
  services: ServiceDetailResponse[];
  findings_count: number;
}

export interface FindingListItem {
  id: string;
  assessment_id: string;
  asset_id: string;
  target_ip?: string | null;
  port?: number | null;
  rule_id: string;
  cve_id?: string | null;
  title: string;
  severity: string;
  priority: string;
  state: string;
  created_at: string;
}

export interface FindingDetailResponse {
  id: string;
  assessment_id: string;
  asset_id: string;
  service_id?: string | null;
  target_ip?: string | null;
  port?: number | null;
  protocol?: string | null;
  rule_id: string;
  cve_id?: string | null;
  title: string;
  description: string;
  severity: string;
  priority: string;
  state: string;
  evidence: Record<string, any>;
  remediation_guidance?: string | null;
  created_at: string;
  updated_at: string;
}

export interface FindingStateUpdateRequest {
  state: string;
  reason?: string | null;
}

export interface AssessmentPostureResponse {
  assessment_id: string;
  risk_score: number;
  risk_level: string;
  priority_distribution: Record<string, number>;
  asset_scores: Array<{
    asset_id: string;
    ip_address: string;
    criticality: string;
    risk_score: number;
    risk_level: string;
  }>;
}

export interface AssetScoreDetailResponse {
  asset_id: string;
  ip_address: string;
  criticality: string;
  risk_score: number;
  risk_level: string;
  exposure_base: number;
  findings_weighted: number;
  criticality_multiplier: number;
  threat_multiplier: number;
  component_explanations: string[];
}

export interface PortDeltaItem {
  ip: string;
  port: number;
  protocol: string;
  service_name?: string | null;
  certainty: string;
}

export interface ServiceModificationDeltaItem {
  ip: string;
  port: number;
  base_product?: string | null;
  target_product?: string | null;
  base_version?: string | null;
  target_version?: string | null;
  is_upgrade: boolean;
}

export interface FindingDeltaItem {
  finding_id: string;
  rule_id: string;
  title: string;
  severity: string;
  priority: string;
  ip?: string | null;
  port?: number | null;
}

export interface AssessmentDiffResponse {
  base_assessment_id: string;
  target_assessment_id: string;
  executive_summary: string[];
  coverage_delta: {
    scope_overlap: string;
    base_targets_count: number;
    target_targets_count: number;
    base_ports_count: number;
    target_ports_count: number;
  };
  host_delta: {
    added_hosts: string[];
    removed_hosts: string[];
    retained_hosts: string[];
  };
  port_delta: {
    opened_ports: PortDeltaItem[];
    closed_ports: PortDeltaItem[];
    uncertain_ports: PortDeltaItem[];
  };
  service_modification_delta: {
    modifications: ServiceModificationDeltaItem[];
  };
  finding_delta: {
    new_findings: FindingDeltaItem[];
    resolved_findings: FindingDeltaItem[];
    persisting_findings: FindingDeltaItem[];
    regressed_findings: FindingDeltaItem[];
  };
  risk_delta: {
    base_score: number;
    target_score: number;
    score_delta: number;
    drift_direction: string;
    priority_deltas: Record<string, number>;
  };
}

export interface SnapshotImportResponse {
  imported_assessment_id: string;
  assessment_name: string;
  assets_count: number;
  services_count: number;
  findings_count: number;
  message: string;
}
