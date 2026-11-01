import React, { useState, useEffect } from 'react';
import { 
  Play, 
  Target, 
  ShieldCheck, 
  AlertTriangle, 
  XOctagon, 
  Trash2, 
  FileText, 
  RefreshCw, 
  CheckCircle2,
  Activity
} from 'lucide-react';
import { api } from '../api/client';
import { 
  AssessmentListItem, 
  AssessmentDetailResponse, 
  ScopeValidationResponse 
} from '../api/types';

interface AssessmentLaunchViewProps {
  onNavigate: (tab: string, meta?: any) => void;
}

export const AssessmentLaunchView: React.FC<AssessmentLaunchViewProps> = ({ onNavigate }) => {
  // Form State
  const [assessmentName, setAssessmentName] = useState('Production Perimeter Audit');
  const [targetsInput, setTargetsInput] = useState('127.0.0.1');
  const [portsInput, setPortsInput] = useState('21,22,25,53,80,110,143,443,445,3306,3389,5432,6379,8000,8080,8443');
  const [concurrency, setConcurrency] = useState(50);
  const [timeout, setTimeoutVal] = useState(2.0);
  const [fingerprint, setFingerprint] = useState(true);
  const [correlateCves, setCorrelateCves] = useState(true);
  const [allowPublic, setAllowPublic] = useState(false);

  // Validation State
  const [validating, setValidating] = useState(false);
  const [scopeResult, setScopeResult] = useState<ScopeValidationResponse | null>(null);

  // Launch & Polling State
  const [launching, setLaunching] = useState(false);
  const [activeAssessmentId, setActiveAssessmentId] = useState<string | null>(null);
  const [activeDetail, setActiveDetail] = useState<AssessmentDetailResponse | null>(null);
  const [cancelling, setCancelling] = useState(false);

  // List & History State
  const [assessments, setAssessments] = useState<AssessmentListItem[]>([]);
  const [loadingList, setLoadingList] = useState(false);
  const [selectedDetail, setSelectedDetail] = useState<AssessmentDetailResponse | null>(null);

  // Quick port presets
  const applyPreset = (preset: 'common' | 'web' | 'db' | 'top100') => {
    switch (preset) {
      case 'common':
        setPortsInput('21,22,25,53,80,110,143,443,445,3306,3389,5432,6379,8000,8080,8443');
        break;
      case 'web':
        setPortsInput('80,443,8000,8080,8443,8888,9000,9443');
        break;
      case 'db':
        setPortsInput('1433,1521,3306,5432,6379,27017');
        break;
      case 'top100':
        setPortsInput('20,21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080');
        break;
    }
  };

  const loadAssessments = async () => {
    setLoadingList(true);
    try {
      const res = await api.getAssessments({ limit: 20 });
      setAssessments(res);

      // If there is any active running assessment, track it
      const running = res.find((a) => a.status === 'running' || a.status === 'pending');
      if (running && !activeAssessmentId) {
        setActiveAssessmentId(running.id);
      }
    } catch {
      // Ignore
    } finally {
      setLoadingList(false);
    }
  };

  useEffect(() => {
    loadAssessments();
  }, []);

  // Poll active assessment if running
  useEffect(() => {
    if (!activeAssessmentId) return;

    let isSubscribed = true;
    const poll = async () => {
      try {
        const detail = await api.getAssessmentDetail(activeAssessmentId);
        if (!isSubscribed) return;
        setActiveDetail(detail);

        if (detail.status === 'completed' || detail.status === 'failed' || detail.status === 'cancelled') {
          // Finished
          loadAssessments();
          setTimeout(() => {
            if (isSubscribed) setActiveAssessmentId(null);
          }, 4000);
        }
      } catch {
        // Stop polling on error
        if (isSubscribed) setActiveAssessmentId(null);
      }
    };

    poll();
    const interval = setInterval(poll, 1000);
    return () => {
      isSubscribed = false;
      clearInterval(interval);
    };
  }, [activeAssessmentId]);

  const handleValidateScope = async () => {
    setValidating(true);
    setScopeResult(null);
    try {
      const targets = targetsInput.split(',').map((t) => t.trim()).filter(Boolean);
      const res = await api.validateScope({
        targets,
        ports: portsInput,
        allow_public: allowPublic,
      });
      setScopeResult(res);
    } catch (err: any) {
      setScopeResult({
        valid: false,
        total_targets: 0,
        allowed_targets: [],
        allowed_ports_count: 0,
        warnings: [],
        error: err.message,
      });
    } finally {
      setValidating(false);
    }
  };

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    setLaunching(true);
    try {
      const targets = targetsInput.split(',').map((t) => t.trim()).filter(Boolean);
      const res = await api.launchAssessment({
        name: assessmentName.trim() || 'Network Assessment',
        targets,
        ports: portsInput,
        concurrency,
        timeout,
        allow_public: allowPublic,
        fingerprint,
        correlate_cves: correlateCves,
        assess: true,
      });
      setActiveAssessmentId(res.assessment_id);
      loadAssessments();
    } catch (err: any) {
      alert(`Launch failed: ${err.message}`);
    } finally {
      setLaunching(false);
    }
  };

  const handleCancel = async () => {
    if (!activeAssessmentId) return;
    setCancelling(true);
    try {
      await api.cancelAssessment(activeAssessmentId);
    } catch (err: any) {
      alert(`Cancel failed: ${err.message}`);
    } finally {
      setCancelling(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this assessment record?')) return;
    try {
      await api.deleteAssessment(id);
      loadAssessments();
      if (selectedDetail?.id === id) setSelectedDetail(null);
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  const handleViewDetail = async (id: string) => {
    try {
      const d = await api.getAssessmentDetail(id);
      setSelectedDetail(d);
    } catch (err: any) {
      alert(`Failed to load details: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header */}
      <div className="bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm">
        <h1 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
          <Target className="w-5 h-5 text-emerald-400" />
          <span>Launch Network Discovery & Exposure Assessment</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Configure scope boundaries, asynchronous concurrency ceilings, service fingerprinting, and automated NVD/KEV vulnerability correlation.
        </p>
      </div>

      {/* Active Live Assessment Banner */}
      {activeAssessmentId && activeDetail && (
        <div className="bg-gradient-to-r from-emerald-950/40 via-slate-900 to-cyan-950/40 border border-emerald-500/40 p-6 rounded-2xl shadow-xl space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 bg-emerald-500/20 text-emerald-400 rounded-xl border border-emerald-500/30 animate-pulse">
                <Activity className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-semibold text-slate-100 text-sm flex items-center space-x-2">
                  <span>Running: {activeDetail.name}</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    {activeDetail.status.toUpperCase()}
                  </span>
                </h3>
                <p className="text-xs font-mono text-slate-400 mt-0.5">
                  ID: {activeDetail.id}
                </p>
              </div>
            </div>

            {activeDetail.status === 'running' && (
              <button
                onClick={handleCancel}
                disabled={cancelling}
                className="flex items-center space-x-1.5 px-3 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 rounded-xl text-xs font-semibold transition-colors"
              >
                <XOctagon className="w-4 h-4" />
                <span>{cancelling ? 'Cancelling...' : 'Cancel Assessment'}</span>
              </button>
            )}
          </div>

          {/* Progress Bar & Telemetry */}
          {activeDetail.live_progress && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-300">
                  Probes: {activeDetail.live_progress.completed_probes} / {activeDetail.live_progress.total_probes}
                </span>
                <span className="text-emerald-400 font-bold">
                  {activeDetail.live_progress.percent_complete.toFixed(1)}%
                </span>
              </div>
              <div className="w-full h-2.5 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
                <div
                  className="h-full bg-gradient-to-r from-emerald-500 to-cyan-400 transition-all duration-300"
                  style={{ width: `${Math.min(100, activeDetail.live_progress.percent_complete)}%` }}
                />
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span>Elapsed: {activeDetail.live_progress.elapsed_seconds.toFixed(1)}s</span>
                <span>Asynchronous Semaphore Concurrency Active</span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Main Grid: Config Form & History */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Launch Form (7 cols) */}
        <div className="lg:col-span-7 bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm">
          <form onSubmit={handleLaunch} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Assessment Name
              </label>
              <input
                type="text"
                value={assessmentName}
                onChange={(e) => setAssessmentName(e.target.value)}
                className="w-full px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
                placeholder="e.g., Staging Environment Discovery"
                required
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-xs font-medium text-slate-300">
                  Target Scope (IPs, CIDRs, Hostnames)
                </label>
                <button
                  type="button"
                  onClick={handleValidateScope}
                  disabled={validating}
                  className="text-[11px] text-emerald-400 hover:text-emerald-300 font-medium flex items-center space-x-1"
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>{validating ? 'Validating...' : 'Validate Scope Guard'}</span>
                </button>
              </div>
              <textarea
                value={targetsInput}
                onChange={(e) => setTargetsInput(e.target.value)}
                rows={2}
                className="w-full px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 font-mono focus:outline-none focus:border-emerald-500"
                placeholder="127.0.0.1, 192.168.1.0/24, api.corp.internal"
                required
              />
              <p className="text-[11px] text-slate-500 mt-1">
                SSRF cloud metadata targets (<code className="text-slate-400">169.254.169.254</code>) are strictly denied by backend guards.
              </p>
            </div>

            {/* Scope Validation Output Badge */}
            {scopeResult && (
              <div className={`p-3 rounded-xl border text-xs space-y-1 ${
                scopeResult.valid
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
              }`}>
                <div className="flex items-center space-x-2 font-semibold">
                  {scopeResult.valid ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-rose-400" />}
                  <span>{scopeResult.valid ? 'Scope Validation Passed' : 'Scope Authorization Blocked'}</span>
                </div>
                {scopeResult.error && <p className="text-[11px]">{scopeResult.error}</p>}
                {scopeResult.valid && (
                  <p className="text-[11px] text-slate-300">
                    Authorized {scopeResult.total_targets} target(s) across {scopeResult.allowed_ports_count} port(s).
                  </p>
                )}
                {scopeResult.warnings.length > 0 && (
                  <ul className="list-disc pl-4 text-[10px] text-amber-300">
                    {scopeResult.warnings.map((w, idx) => <li key={idx}>{w}</li>)}
                  </ul>
                )}
              </div>
            )}

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-xs font-medium text-slate-300">
                  Target Port Specification
                </label>
                <div className="flex items-center space-x-1.5">
                  <span className="text-[10px] text-slate-500">Presets:</span>
                  <button type="button" onClick={() => applyPreset('common')} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 hover:bg-slate-700">Common</button>
                  <button type="button" onClick={() => applyPreset('web')} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 hover:bg-slate-700">Web</button>
                  <button type="button" onClick={() => applyPreset('db')} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 hover:bg-slate-700">DB</button>
                  <button type="button" onClick={() => applyPreset('top100')} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 hover:bg-slate-700">Top 100</button>
                </div>
              </div>
              <input
                type="text"
                value={portsInput}
                onChange={(e) => setPortsInput(e.target.value)}
                className="w-full px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 font-mono focus:outline-none focus:border-emerald-500"
                placeholder="80,443,8000-8080"
                required
              />
            </div>

            {/* Concurrency & Timeout */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Worker Concurrency ({concurrency} workers)
                </label>
                <input
                  type="range"
                  min="5"
                  max="200"
                  step="5"
                  value={concurrency}
                  onChange={(e) => setConcurrency(parseInt(e.target.value))}
                  className="w-full accent-emerald-500"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Socket Timeout ({timeout.toFixed(1)}s)
                </label>
                <input
                  type="range"
                  min="0.5"
                  max="10.0"
                  step="0.5"
                  value={timeout}
                  onChange={(e) => setTimeoutVal(parseFloat(e.target.value))}
                  className="w-full accent-emerald-500"
                />
              </div>
            </div>

            {/* Checkboxes */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-slate-800/80">
              <label className="flex items-center space-x-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={fingerprint}
                  onChange={(e) => setFingerprint(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-800 text-emerald-500 focus:ring-0"
                />
                <span>Active Service Fingerprinting</span>
              </label>

              <label className="flex items-center space-x-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={correlateCves}
                  onChange={(e) => setCorrelateCves(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-800 text-emerald-500 focus:ring-0"
                />
                <span>Correlate NVD CVEs & CISA KEV</span>
              </label>

              <label className="flex items-center space-x-2 text-xs text-slate-300 cursor-pointer sm:col-span-2">
                <input
                  type="checkbox"
                  checked={allowPublic}
                  onChange={(e) => setAllowPublic(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-800 text-amber-500 focus:ring-0"
                />
                <span className="text-amber-400">Authorize Public IP Scanning (Requires explicit permission)</span>
              </label>
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={launching || !!activeAssessmentId}
              className="w-full flex items-center justify-center space-x-2 py-2.5 px-4 bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-800 disabled:text-slate-500 text-slate-950 font-bold rounded-xl text-xs shadow-lg shadow-emerald-500/20 transition-all mt-4"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>{launching ? 'Queuing Task...' : activeAssessmentId ? 'Scan in Progress...' : 'Launch Assessment'}</span>
            </button>
          </form>
        </div>

        {/* Assessment History (5 cols) */}
        <div className="lg:col-span-5 bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="font-semibold text-slate-200 text-sm">Assessment Runs</h2>
              <button
                onClick={loadAssessments}
                disabled={loadingList}
                className="p-1.5 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-800 transition-colors"
                title="Refresh List"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${loadingList ? 'animate-spin' : ''}`} />
              </button>
            </div>

            <div className="space-y-2 max-h-[460px] overflow-y-auto pr-1">
              {assessments.length === 0 ? (
                <p className="text-xs text-slate-500 py-6 text-center">No assessments found.</p>
              ) : (
                assessments.map((a) => (
                  <div
                    key={a.id}
                    className={`p-3 rounded-xl border transition-all text-xs flex items-center justify-between ${
                      selectedDetail?.id === a.id
                        ? 'bg-slate-800/80 border-emerald-500/40 shadow-sm'
                        : 'bg-slate-950/60 border-slate-800/60 hover:border-slate-700'
                    }`}
                  >
                    <div 
                      onClick={() => handleViewDetail(a.id)}
                      className="cursor-pointer flex-1 mr-2"
                    >
                      <div className="font-medium text-slate-200 flex items-center space-x-1.5">
                        <span className="truncate max-w-[140px]">{a.name}</span>
                        <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded-full ${
                          a.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400' :
                          a.status === 'running' ? 'bg-cyan-500/10 text-cyan-400' : 'bg-slate-800 text-slate-400'
                        }`}>
                          {a.status}
                        </span>
                      </div>
                      <div className="flex items-center space-x-3 text-[10px] text-slate-500 mt-1 font-mono">
                        <span>{a.assets_count} assets</span>
                        <span>•</span>
                        <span>{a.findings_count} findings</span>
                        <span>•</span>
                        <span>Score: {a.risk_score !== null ? a.risk_score?.toFixed(1) : '—'}</span>
                      </div>
                    </div>

                    <div className="flex items-center space-x-1">
                      <button
                        onClick={() => onNavigate('reports', { assessmentId: a.id })}
                        title="Export Report"
                        className="p-1.5 text-slate-400 hover:text-emerald-400 hover:bg-slate-800 rounded-lg transition-colors"
                      >
                        <FileText className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleDelete(a.id)}
                        title="Delete Record"
                        className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded-lg transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800/80 text-[11px] text-slate-500 flex items-center justify-between">
            <span>Total: {assessments.length} runs</span>
            <span className="text-emerald-500 font-mono">SQLite WAL Storage</span>
          </div>
        </div>
      </div>

      {/* Assessment Detail Modal */}
      {selectedDetail && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-2xl w-full max-w-2xl p-6 shadow-2xl relative max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div>
                <h3 className="font-bold text-slate-100 text-base">{selectedDetail.name}</h3>
                <p className="text-xs font-mono text-slate-400">ID: {selectedDetail.id}</p>
              </div>
              <button
                onClick={() => setSelectedDetail(null)}
                className="text-slate-400 hover:text-slate-200 text-sm"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 font-mono">Status</span>
                <p className="text-xs font-semibold text-emerald-400 uppercase">{selectedDetail.status}</p>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 font-mono">Risk Score</span>
                <p className="text-xs font-semibold text-rose-400 font-mono">
                  {selectedDetail.risk_score?.toFixed(1) ?? '—'}
                </p>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 font-mono">Findings</span>
                <p className="text-xs font-semibold text-slate-200 font-mono">{selectedDetail.findings_count}</p>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 font-mono">Version</span>
                <p className="text-xs font-semibold text-slate-200 font-mono">{selectedDetail.scanner_version}</p>
              </div>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <h4 className="font-semibold text-slate-300 mb-1">Scope Configuration</h4>
                <pre className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                  {JSON.stringify(selectedDetail.scope_config, null, 2)}
                </pre>
              </div>

              <div>
                <h4 className="font-semibold text-slate-300 mb-1">Coverage Metrics</h4>
                <pre className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                  {JSON.stringify(selectedDetail.coverage_metrics, null, 2)}
                </pre>
              </div>
            </div>

            <div className="flex items-center justify-end space-x-2 mt-6 pt-3 border-t border-slate-800">
              <button
                onClick={() => {
                  const id = selectedDetail.id;
                  setSelectedDetail(null);
                  onNavigate('reports', { assessmentId: id });
                }}
                className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold rounded-xl text-xs transition-colors"
              >
                Generate Audit Reports
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
