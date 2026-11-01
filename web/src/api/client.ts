import {
  AssessmentDetailResponse,
  AssessmentDiffResponse,
  AssessmentLaunchRequest,
  AssessmentLaunchResponse,
  AssessmentListItem,
  AssessmentPostureResponse,
  AssetDetailResponse,
  AssetListItem,
  AssetScoreDetailResponse,
  FindingDetailResponse,
  FindingListItem,
  FindingStateUpdateRequest,
  HealthResponse,
  ScopeValidationRequest,
  ScopeValidationResponse,
  SnapshotImportResponse,
  SystemInfoResponse,
} from './types';

class ApiClient {
  private baseUrl: string;
  private apiKey: string | null = null;

  constructor() {
    this.baseUrl = (import.meta as any).env?.VITE_API_BASE_URL || '/api/v1';
    this.apiKey = localStorage.getItem('reconforge_api_key');
  }

  public setApiKey(key: string | null) {
    this.apiKey = key;
    if (key) {
      localStorage.setItem('reconforge_api_key', key);
    } else {
      localStorage.removeItem('reconforge_api_key');
    }
  }

  public getApiKey(): string | null {
    return this.apiKey;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers: Record<string, string> = {
      Accept: 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    };

    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    if (options.body && typeof options.body === 'string' && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    const response = await fetch(url, { ...options, headers });

    if (!response.ok) {
      let errorMsg = `HTTP Error ${response.status}: ${response.statusText}`;
      try {
        const errorJson = await response.json();
        if (errorJson.detail) {
          errorMsg = typeof errorJson.detail === 'string' ? errorJson.detail : JSON.stringify(errorJson.detail);
        }
      } catch {
        // Fallback to text
      }
      throw new Error(errorMsg);
    }

    return response.json();
  }

  // System
  async getHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>('/health');
  }

  async getSystemInfo(): Promise<SystemInfoResponse> {
    return this.request<SystemInfoResponse>('/system');
  }

  // Scope
  async validateScope(req: ScopeValidationRequest): Promise<ScopeValidationResponse> {
    return this.request<ScopeValidationResponse>('/scope/validate', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  // Assessments
  async launchAssessment(req: AssessmentLaunchRequest): Promise<AssessmentLaunchResponse> {
    return this.request<AssessmentLaunchResponse>('/assessments', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async getAssessments(params?: { skip?: number; limit?: number; status?: string }): Promise<AssessmentListItem[]> {
    const query = new URLSearchParams();
    if (params?.skip !== undefined) query.set('skip', params.skip.toString());
    if (params?.limit !== undefined) query.set('limit', params.limit.toString());
    if (params?.status) query.set('status', params.status);
    const qs = query.toString() ? `?${query.toString()}` : '';
    return this.request<AssessmentListItem[]>(`/assessments${qs}`);
  }

  async getAssessmentDetail(id: string): Promise<AssessmentDetailResponse> {
    return this.request<AssessmentDetailResponse>(`/assessments/${id}`);
  }

  async cancelAssessment(id: string): Promise<{ message: string; assessment_id: string; status: string }> {
    return this.request(`/assessments/${id}/cancel`, { method: 'POST' });
  }

  async deleteAssessment(id: string): Promise<{ message: string; assessment_id: string }> {
    return this.request(`/assessments/${id}`, { method: 'DELETE' });
  }

  // Assets
  async getAssets(params?: { search?: string; criticality?: string; skip?: number; limit?: number }): Promise<AssetListItem[]> {
    const query = new URLSearchParams();
    if (params?.search) query.set('search', params.search);
    if (params?.criticality) query.set('criticality', params.criticality);
    if (params?.skip !== undefined) query.set('skip', params.skip.toString());
    if (params?.limit !== undefined) query.set('limit', params.limit.toString());
    const qs = query.toString() ? `?${query.toString()}` : '';
    return this.request<AssetListItem[]>(`/assets${qs}`);
  }

  async getAssetDetail(idOrIp: string): Promise<AssetDetailResponse> {
    return this.request<AssetDetailResponse>(`/assets/${encodeURIComponent(idOrIp)}`);
  }

  // Findings
  async getFindings(params?: {
    severity?: string;
    priority?: string;
    state?: string;
    assessment_id?: string;
    asset_id?: string;
    skip?: number;
    limit?: number;
  }): Promise<FindingListItem[]> {
    const query = new URLSearchParams();
    if (params?.severity) query.set('severity', params.severity);
    if (params?.priority) query.set('priority', params.priority);
    if (params?.state) query.set('state', params.state);
    if (params?.assessment_id) query.set('assessment_id', params.assessment_id);
    if (params?.asset_id) query.set('asset_id', params.asset_id);
    if (params?.skip !== undefined) query.set('skip', params.skip.toString());
    if (params?.limit !== undefined) query.set('limit', params.limit.toString());
    const qs = query.toString() ? `?${query.toString()}` : '';
    return this.request<FindingListItem[]>(`/findings${qs}`);
  }

  async getFindingDetail(id: string): Promise<FindingDetailResponse> {
    return this.request<FindingDetailResponse>(`/findings/${id}`);
  }

  async updateFindingState(id: string, req: FindingStateUpdateRequest): Promise<FindingDetailResponse> {
    return this.request<FindingDetailResponse>(`/findings/${id}/state`, {
      method: 'PATCH',
      body: JSON.stringify(req),
    });
  }

  // Scoring
  async getAssessmentPosture(id: string): Promise<AssessmentPostureResponse> {
    return this.request<AssessmentPostureResponse>(`/scoring/${id}`);
  }

  async getAssetScore(assessmentId: string, assetId: string): Promise<AssetScoreDetailResponse> {
    return this.request<AssetScoreDetailResponse>(`/scoring/${assessmentId}/assets/${assetId}`);
  }

  // Diff
  async diffAssessments(baseId: string, targetId: string): Promise<AssessmentDiffResponse> {
    return this.request<AssessmentDiffResponse>('/diff', {
      method: 'POST',
      body: JSON.stringify({ base_id: baseId, target_id: targetId }),
    });
  }

  async diffSnapshots(baseSnapshot: any, targetSnapshot: any): Promise<AssessmentDiffResponse> {
    return this.request<AssessmentDiffResponse>('/diff/snapshots', {
      method: 'POST',
      body: JSON.stringify({ base_snapshot: baseSnapshot, target_snapshot: targetSnapshot }),
    });
  }

  // Reports
  async downloadReport(assessmentId: string, format: 'html' | 'json' | 'markdown' | 'csv'): Promise<void> {
    const url = `${this.baseUrl}/reports/${assessmentId}?format=${format}`;
    const headers: Record<string, string> = {};
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const response = await fetch(url, { headers });
    if (!response.ok) {
      throw new Error(`Failed to download report: ${response.statusText}`);
    }

    const blob = await response.blob();
    const blobUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = blobUrl;
    const extensions: Record<string, string> = {
      html: 'html',
      json: 'json',
      markdown: 'md',
      csv: 'csv',
    };
    link.download = `reconforge_report_${assessmentId.slice(0, 8)}.${extensions[format] || 'txt'}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(blobUrl);
  }

  // Snapshots
  async exportSnapshot(assessmentId: string): Promise<void> {
    const url = `${this.baseUrl}/snapshots/export/${assessmentId}`;
    const headers: Record<string, string> = {};
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const response = await fetch(url, { headers });
    if (!response.ok) {
      throw new Error(`Failed to export snapshot: ${response.statusText}`);
    }

    const blob = await response.blob();
    const blobUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = `snapshot_${assessmentId.slice(0, 8)}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(blobUrl);
  }

  async importSnapshot(snapshotData: any): Promise<SnapshotImportResponse> {
    return this.request<SnapshotImportResponse>('/snapshots/import', {
      method: 'POST',
      body: JSON.stringify(snapshotData),
    });
  }
}

export const api = new ApiClient();
