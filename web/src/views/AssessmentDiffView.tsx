import React, { useState, useEffect } from 'react';
import { 
  GitCompare, 
  ArrowRight, 
  TrendingDown, 
  TrendingUp, 
  Minus, 
  AlertTriangle, 
  FileJson, 
  Sparkles
} from 'lucide-react';
import { api } from '../api/client';
import { 
  AssessmentListItem, 
  AssessmentDiffResponse 
} from '../api/types';

export const AssessmentDiffView: React.FC = () => {
  const [assessments, setAssessments] = useState<AssessmentListItem[]>([]);
  const [baseId, setBaseId] = useState('');
  const [targetId, setTargetId] = useState('');
  const [diffResult, setDiffResult] = useState<AssessmentDiffResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Snapshot JSON upload alternative
  const [baseSnapshotText, setBaseSnapshotText] = useState('');
  const [targetSnapshotText, setTargetSnapshotText] = useState('');
  const [useSnapshots, setUseSnapshots] = useState(false);

  useEffect(() => {
    const loadList = async () => {
      try {
        const res = await api.getAssessments({ limit: 50 });
        setAssessments(res);
        if (res.length >= 2) {
          setBaseId(res[1].id);
          setTargetId(res[0].id);
        } else if (res.length === 1) {
          setBaseId(res[0].id);
          setTargetId(res[0].id);
        }
      } catch {
        // Ignore
      }
    };
    loadList();
  }, []);

  const handleDiff = async () => {
    setLoading(true);
    setError(null);
    setDiffResult(null);

    try {
      if (useSnapshots) {
        if (!baseSnapshotText || !targetSnapshotText) {
          throw new Error('Please provide both Base and Target snapshot JSON data.');
        }
        const baseJson = JSON.parse(baseSnapshotText);
        const targetJson = JSON.parse(targetSnapshotText);
        const res = await api.diffSnapshots(baseJson, targetJson);
        setDiffResult(res);
      } else {
        if (!baseId || !targetId) {
          throw new Error('Please select both Base and Target assessments.');
        }
        const res = await api.diffAssessments(baseId, targetId);
        setDiffResult(res);
      }
    } catch (err: any) {
      setError(err.message || 'Assessment differencing failed.');
    } finally {
      setLoading(false);
    }
  };

  const getDriftBadge = (dir: string, delta: number) => {
    if (dir === 'improved') {
      return (
        <div className="flex items-center space-x-1.5 px-3 py-1 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded-xl text-xs font-bold">
          <TrendingDown className="w-4 h-4" />
          <span>IMPROVED ({delta.toFixed(1)} pts)</span>
        </div>
      );
    }
    if (dir === 'degraded') {
      return (
        <div className="flex items-center space-x-1.5 px-3 py-1 bg-rose-500/10 border border-rose-500/30 text-rose-400 rounded-xl text-xs font-bold">
          <TrendingUp className="w-4 h-4" />
          <span>DEGRADED (+{delta.toFixed(1)} pts)</span>
        </div>
      );
    }
    return (
      <div className="flex items-center space-x-1.5 px-3 py-1 bg-slate-800 border border-slate-700 text-slate-300 rounded-xl text-xs font-bold">
        <Minus className="w-4 h-4" />
        <span>STABLE (0.0 pts)</span>
      </div>
    );
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header */}
      <div className="bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm">
        <h1 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
          <GitCompare className="w-5 h-5 text-emerald-400" />
          <span>Coverage-Aware Assessment Differencing</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Mathematically compare two assessment runs or standalone JSON snapshots. Enforces coverage certainty to eliminate false remediation claims.
        </p>
      </div>

      {/* Selectors Card */}
      <div className="bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Compare Datasets
          </h2>
          <button
            onClick={() => setUseSnapshots(!useSnapshots)}
            className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center space-x-1"
          >
            <FileJson className="w-3.5 h-3.5" />
            <span>{useSnapshots ? 'Switch to Database Runs' : 'Switch to Raw JSON Snapshots'}</span>
          </button>
        </div>

        {!useSnapshots ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                Base Assessment (Earlier / Baseline)
              </label>
              <select
                value={baseId}
                onChange={(e) => setBaseId(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
              >
                {assessments.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({new Date(a.start_time).toLocaleDateString()}) - {a.id.slice(0, 8)}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                Target Assessment (Later / Comparison)
              </label>
              <select
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
              >
                {assessments.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({new Date(a.start_time).toLocaleDateString()}) - {a.id.slice(0, 8)}
                  </option>
                ))}
              </select>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                Base Snapshot JSON
              </label>
              <textarea
                value={baseSnapshotText}
                onChange={(e) => setBaseSnapshotText(e.target.value)}
                rows={4}
                placeholder="Paste base snapshot JSON payload here..."
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-[11px] text-slate-300 font-mono focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                Target Snapshot JSON
              </label>
              <textarea
                value={targetSnapshotText}
                onChange={(e) => setTargetSnapshotText(e.target.value)}
                rows={4}
                placeholder="Paste target snapshot JSON payload here..."
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-[11px] text-slate-300 font-mono focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>
        )}

        {error && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-xs text-rose-300 flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <button
          onClick={handleDiff}
          disabled={loading}
          className="flex items-center justify-center space-x-2 w-full py-2.5 bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-800 text-slate-950 font-bold rounded-xl text-xs shadow-lg shadow-emerald-500/20 transition-all"
        >
          <GitCompare className="w-4 h-4" />
          <span>{loading ? 'Computing Coverage & Delta Model...' : 'Execute Semantic Differencing'}</span>
        </button>
      </div>

      {/* Differencing Results */}
      {diffResult && (
        <div className="space-y-6">
          {/* Executive Overview Banner */}
          <div className="bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
              <div>
                <h3 className="font-bold text-slate-100 text-base flex items-center space-x-2">
                  <span>Attack-Surface Posture Drift</span>
                  <Sparkles className="w-4 h-4 text-emerald-400" />
                </h3>
                <p className="text-xs font-mono text-slate-400 mt-0.5">
                  Scope Overlap: <span className="text-cyan-400 font-semibold">{diffResult.coverage_delta.scope_overlap.toUpperCase()}</span>
                </p>
              </div>

              {getDriftBadge(diffResult.risk_delta.drift_direction, diffResult.risk_delta.score_delta)}
            </div>

            {/* Score Comparison */}
            <div className="grid grid-cols-3 gap-3 text-center py-2">
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 font-mono">Baseline Risk</span>
                <p className="text-base font-bold font-mono text-slate-200">
                  {diffResult.risk_delta.base_score.toFixed(1)}
                </p>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 font-mono">Comparison Risk</span>
                <p className="text-base font-bold font-mono text-slate-200">
                  {diffResult.risk_delta.target_score.toFixed(1)}
                </p>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 font-mono">Score Variance (Δ)</span>
                <p className={`text-base font-bold font-mono ${
                  diffResult.risk_delta.score_delta < 0 ? 'text-emerald-400' :
                  diffResult.risk_delta.score_delta > 0 ? 'text-rose-400' : 'text-slate-400'
                }`}>
                  {diffResult.risk_delta.score_delta > 0 ? `+${diffResult.risk_delta.score_delta.toFixed(1)}` : diffResult.risk_delta.score_delta.toFixed(1)}
                </p>
              </div>
            </div>

            {/* Executive Summary Bullets */}
            <div>
              <h4 className="font-semibold text-xs text-slate-300 mb-2">Executive SOC Briefing</h4>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {diffResult.executive_summary.map((line, idx) => (
                  <li key={idx} className="flex items-start space-x-2 bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/60">
                    <span className="text-emerald-400 font-bold">•</span>
                    <span>{line}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Deltas: Ports & Service Upgrades */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Port Transitions */}
            <div className="bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm space-y-3">
              <h3 className="font-semibold text-slate-200 text-sm flex items-center justify-between">
                <span>Port State Transitions</span>
                <span className="text-xs font-mono text-slate-400">
                  +{diffResult.port_delta.opened_ports.length} / -{diffResult.port_delta.closed_ports.length}
                </span>
              </h3>

              {diffResult.port_delta.opened_ports.length === 0 && diffResult.port_delta.closed_ports.length === 0 ? (
                <p className="text-xs text-slate-500 py-4 text-center">No open or closed port transitions detected.</p>
              ) : (
                <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                  {diffResult.port_delta.opened_ports.map((p, idx) => (
                    <div key={`open-${idx}`} className="p-2.5 bg-rose-500/10 border border-rose-500/20 rounded-xl text-xs flex items-center justify-between font-mono">
                      <span className="text-rose-400 font-bold">+ OPENED: {p.ip}:{p.port} ({p.service_name || 'unknown'})</span>
                      <span className="text-[10px] text-slate-400 uppercase">{p.certainty}</span>
                    </div>
                  ))}
                  {diffResult.port_delta.closed_ports.map((p, idx) => (
                    <div key={`close-${idx}`} className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-xs flex items-center justify-between font-mono">
                      <span className="text-emerald-400 font-bold">- CLOSED: {p.ip}:{p.port} ({p.service_name || 'unknown'})</span>
                      <span className="text-[10px] text-slate-400 uppercase">{p.certainty}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Service & Version Upgrades */}
            <div className="bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm space-y-3">
              <h3 className="font-semibold text-slate-200 text-sm flex items-center justify-between">
                <span>Service Version Modifications</span>
                <span className="text-xs font-mono text-slate-400">
                  {diffResult.service_modification_delta.modifications.length} modifications
                </span>
              </h3>

              {diffResult.service_modification_delta.modifications.length === 0 ? (
                <p className="text-xs text-slate-500 py-4 text-center">No service or software version changes detected.</p>
              ) : (
                <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                  {diffResult.service_modification_delta.modifications.map((m, idx) => (
                    <div key={`mod-${idx}`} className="p-3 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-200 font-bold">{m.ip}:{m.port}</span>
                        {m.is_upgrade && (
                          <span className="text-[10px] bg-emerald-500/10 text-emerald-400 px-2 py-0.5 rounded border border-emerald-500/20">
                            VERSION UPGRADE
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-400 flex items-center space-x-2">
                        <span>{m.base_product || '—'} {m.base_version || ''}</span>
                        <ArrowRight className="w-3 h-3 text-cyan-400" />
                        <span className="text-emerald-300 font-semibold">{m.target_product || '—'} {m.target_version || ''}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Finding Lifecycle Deltas */}
          <div className="bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm space-y-3">
            <h3 className="font-semibold text-slate-200 text-sm flex items-center justify-between">
              <span>Vulnerability Findings Remediation & Ingress</span>
              <span className="text-xs font-mono text-slate-400">
                +{diffResult.finding_delta.new_findings.length} new / -{diffResult.finding_delta.resolved_findings.length} resolved
              </span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h4 className="text-xs font-semibold text-rose-400 mb-2">New Security Exposures</h4>
                {diffResult.finding_delta.new_findings.length === 0 ? (
                  <p className="text-xs text-slate-500 py-2">No new findings introduced.</p>
                ) : (
                  <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                    {diffResult.finding_delta.new_findings.map((f, idx) => (
                      <div key={`nf-${idx}`} className="p-2 bg-rose-500/10 border border-rose-500/20 rounded-lg text-xs">
                        <span className="font-bold text-rose-300">[{f.priority.toUpperCase()}] {f.title}</span>
                        <div className="text-[10px] font-mono text-slate-400">{f.ip}:{f.port}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <h4 className="text-xs font-semibold text-emerald-400 mb-2">Remediated Vulnerabilities</h4>
                {diffResult.finding_delta.resolved_findings.length === 0 ? (
                  <p className="text-xs text-slate-500 py-2">No findings remediated.</p>
                ) : (
                  <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                    {diffResult.finding_delta.resolved_findings.map((f, idx) => (
                      <div key={`rf-${idx}`} className="p-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-xs">
                        <span className="font-bold text-emerald-300">[{f.priority.toUpperCase()}] {f.title}</span>
                        <div className="text-[10px] font-mono text-slate-400">{f.ip}:{f.port}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
