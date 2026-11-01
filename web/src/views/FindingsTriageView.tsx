import React, { useState, useEffect } from 'react';
import { 
  AlertTriangle, 
  CheckCircle2, 
  Flame, 
  RefreshCw,
  Edit3
} from 'lucide-react';
import { api } from '../api/client';
import { FindingListItem, FindingDetailResponse } from '../api/types';

interface FindingsTriageViewProps {
  onNavigate?: (tab: string, meta?: any) => void;
  initialTargetIp?: string;
}

export const FindingsTriageView: React.FC<FindingsTriageViewProps> = ({ initialTargetIp }) => {
  const [findings, setFindings] = useState<FindingListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');
  const [priorityFilter, setPriorityFilter] = useState('');
  const [stateFilter, setStateFilter] = useState('');
  const [targetIpFilter, setTargetIpFilter] = useState(initialTargetIp || '');
  const [selectedFinding, setSelectedFinding] = useState<FindingDetailResponse | null>(null);

  // State update form
  const [newState, setNewState] = useState('');
  const [updateReason, setUpdateReason] = useState('');
  const [updating, setUpdating] = useState(false);
  const [updateSuccess, setUpdateSuccess] = useState(false);

  const fetchFindings = async () => {
    setLoading(true);
    try {
      const res = await api.getFindings({
        severity: severityFilter || undefined,
        priority: priorityFilter || undefined,
        state: stateFilter || undefined,
        limit: 100,
      });
      const filtered = targetIpFilter.trim() 
        ? res.filter((f) => f.target_ip?.includes(targetIpFilter.trim()))
        : res;
      setFindings(filtered);
    } catch {
      setFindings([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [severityFilter, priorityFilter, stateFilter, targetIpFilter]);

  const handleSelectFinding = async (id: string) => {
    setSelectedFinding(null);
    setUpdateSuccess(false);
    try {
      const d = await api.getFindingDetail(id);
      setSelectedFinding(d);
      setNewState(d.state);
      setUpdateReason('');
    } catch (err: any) {
      alert(`Failed to load finding: ${err.message}`);
    }
  };

  const handleUpdateState = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFinding) return;
    setUpdating(true);
    setUpdateSuccess(false);
    try {
      const updated = await api.updateFindingState(selectedFinding.id, {
        state: newState,
        reason: updateReason.trim() || undefined,
      });
      setSelectedFinding(updated);
      setUpdateSuccess(true);
      fetchFindings();
    } catch (err: any) {
      alert(`Update failed: ${err.message}`);
    } finally {
      setUpdating(false);
    }
  };

  const getSeverityBadge = (sev: string) => {
    const s = sev.toLowerCase();
    if (s === 'critical') return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
    if (s === 'high') return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    if (s === 'medium') return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
    if (s === 'low') return 'bg-sky-500/10 text-sky-400 border-sky-500/20';
    return 'bg-slate-800 text-slate-400 border-slate-700';
  };

  const getPriorityBadge = (pri: string) => {
    const p = pri.toLowerCase();
    if (p === 'p1') return 'bg-rose-500 text-slate-950 font-bold';
    if (p === 'p2') return 'bg-amber-500 text-slate-950 font-bold';
    if (p === 'p3') return 'bg-yellow-500 text-slate-950 font-bold';
    if (p === 'p4') return 'bg-sky-500 text-slate-950 font-bold';
    return 'bg-slate-700 text-slate-200';
  };

  const getStateBadge = (st: string) => {
    const s = st.toLowerCase();
    if (s === 'confirmed') return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
    if (s === 'false_positive') return 'text-slate-400 bg-slate-800 border-slate-700';
    if (s === 'accepted_risk') return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
    return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20';
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header */}
      <div className="bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
            <AlertTriangle className="w-5 h-5 text-rose-400" />
            <span>Vulnerabilities & Exposure Triage</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Prioritized findings catalog with CISA KEV exploitation tags, CVSS metrics, and auditable lifecycle transitions.
          </p>
        </div>
        <button
          onClick={fetchFindings}
          className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs border border-slate-700 transition-colors self-start sm:self-auto"
          title="Refresh Findings"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Filters Bar */}
      <div className="bg-slate-900/60 border border-slate-800/80 p-4 rounded-2xl shadow-sm flex flex-wrap items-center gap-3">
        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-400 font-medium">Target IP:</span>
          <input
            type="text"
            value={targetIpFilter}
            onChange={(e) => setTargetIpFilter(e.target.value)}
            placeholder="Filter by IP..."
            className="w-36 px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
          />
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-400 font-medium">Severity:</span>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-300 py-1.5 px-3 rounded-xl focus:outline-none focus:border-emerald-500"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="informational">Informational</option>
          </select>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-400 font-medium">Priority:</span>
          <select
            value={priorityFilter}
            onChange={(e) => setPriorityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-300 py-1.5 px-3 rounded-xl focus:outline-none focus:border-emerald-500"
          >
            <option value="">All Priorities</option>
            <option value="p1">P1 (Immediate)</option>
            <option value="p2">P2 (High)</option>
            <option value="p3">P3 (Medium)</option>
            <option value="p4">P4 (Low)</option>
            <option value="p5">P5 (Info)</option>
          </select>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-400 font-medium">Lifecycle State:</span>
          <select
            value={stateFilter}
            onChange={(e) => setStateFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-300 py-1.5 px-3 rounded-xl focus:outline-none focus:border-emerald-500"
          >
            <option value="">All States</option>
            <option value="confirmed">Confirmed</option>
            <option value="potential_vulnerability">Potential Vulnerability</option>
            <option value="potential_exposure">Potential Exposure</option>
            <option value="needs_review">Needs Review</option>
            <option value="false_positive">False Positive</option>
            <option value="accepted_risk">Accepted Risk</option>
          </select>
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-6 shadow-sm">
        {loading ? (
          <div className="text-center py-12 text-xs text-slate-400 space-y-2">
            <RefreshCw className="w-6 h-6 text-emerald-400 animate-spin mx-auto" />
            <p>Loading security findings...</p>
          </div>
        ) : findings.length === 0 ? (
          <div className="text-center py-12 text-slate-500 text-xs">
            No findings match your filter criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono">
                  <th className="pb-3 pl-2">Priority</th>
                  <th className="pb-3">Severity</th>
                  <th className="pb-3">Title & Rule</th>
                  <th className="pb-3">Target Endpoint</th>
                  <th className="pb-3">CVE / Identifier</th>
                  <th className="pb-3">State</th>
                  <th className="pb-3 text-right pr-2">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {findings.map((f) => (
                  <tr key={f.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 pl-2">
                      <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono ${getPriorityBadge(f.priority)}`}>
                        {f.priority.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3">
                      <span className={`inline-block px-2 py-0.5 rounded-full text-[10px] font-mono border ${getSeverityBadge(f.severity)}`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="py-3 font-medium text-slate-200">
                      <div>{f.title}</div>
                      <div className="text-[10px] font-mono text-slate-500">{f.rule_id}</div>
                    </td>
                    <td className="py-3 font-mono text-slate-300">
                      {f.target_ip ? `${f.target_ip}${f.port ? `:${f.port}` : ''}` : '—'}
                    </td>
                    <td className="py-3 font-mono">
                      {f.cve_id ? (
                        <span className="text-rose-400 font-semibold bg-rose-500/10 px-1.5 py-0.5 rounded border border-rose-500/20 text-[11px]">
                          {f.cve_id}
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="py-3">
                      <span className={`inline-block px-2 py-0.5 rounded-full text-[10px] font-mono border ${getStateBadge(f.state)}`}>
                        {f.state}
                      </span>
                    </td>
                    <td className="py-3 text-right pr-2">
                      <button
                        onClick={() => handleSelectFinding(f.id)}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-[11px] font-medium transition-colors"
                      >
                        Triage
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Finding Detail / Triage Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-2xl w-full max-w-3xl p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center space-x-3">
                <span className={`px-2.5 py-1 rounded-lg text-xs font-mono ${getPriorityBadge(selectedFinding.priority)}`}>
                  {selectedFinding.priority.toUpperCase()}
                </span>
                <div>
                  <h3 className="font-bold text-slate-100 text-base">{selectedFinding.title}</h3>
                  <p className="text-xs font-mono text-slate-400">
                    Rule ID: {selectedFinding.rule_id} {selectedFinding.cve_id ? `• ${selectedFinding.cve_id}` : ''}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="text-slate-400 hover:text-slate-200 text-sm"
              >
                ✕
              </button>
            </div>

            {/* Evidence & KEV tags */}
            {selectedFinding.evidence?.is_cisa_kev && (
              <div className="mb-4 p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl flex items-center space-x-2 text-rose-400 text-xs font-semibold">
                <Flame className="w-4 h-4 flex-shrink-0 animate-bounce" />
                <span>CISA Known Exploited Vulnerability (Active in the wild - Immediate Remediation Required)</span>
              </div>
            )}

            <div className="space-y-4 text-xs">
              <div>
                <h4 className="font-semibold text-slate-300 mb-1">Description</h4>
                <p className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-slate-300 leading-relaxed">
                  {selectedFinding.description}
                </p>
              </div>

              {selectedFinding.remediation_guidance && (
                <div>
                  <h4 className="font-semibold text-emerald-400 mb-1">Remediation Guidance</h4>
                  <p className="p-3 bg-emerald-950/20 rounded-xl border border-emerald-500/30 text-emerald-300 leading-relaxed font-mono text-[11px]">
                    {selectedFinding.remediation_guidance}
                  </p>
                </div>
              )}

              <div>
                <h4 className="font-semibold text-slate-300 mb-1">Evidence Payload</h4>
                <pre className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-400 overflow-x-auto max-h-40">
                  {JSON.stringify(selectedFinding.evidence, null, 2)}
                </pre>
              </div>

              {/* Lifecycle State Transition Form */}
              <div className="pt-4 border-t border-slate-800/80">
                <h4 className="font-semibold text-slate-200 text-sm mb-2 flex items-center space-x-1.5">
                  <Edit3 className="w-4 h-4 text-cyan-400" />
                  <span>Update Finding Lifecycle State</span>
                </h4>

                <form onSubmit={handleUpdateState} className="space-y-3 bg-slate-950 p-4 rounded-xl border border-slate-800">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-[11px] font-medium text-slate-400 mb-1">
                        New Lifecycle State
                      </label>
                      <select
                        value={newState}
                        onChange={(e) => setNewState(e.target.value)}
                        className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
                      >
                        <option value="confirmed">Confirmed</option>
                        <option value="false_positive">False Positive</option>
                        <option value="accepted_risk">Accepted Risk</option>
                        <option value="needs_review">Needs Review</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-[11px] font-medium text-slate-400 mb-1">
                        Audit Note / Justification
                      </label>
                      <input
                        type="text"
                        value={updateReason}
                        onChange={(e) => setUpdateReason(e.target.value)}
                        placeholder="e.g., Compensating WAF control in place"
                        className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
                      />
                    </div>
                  </div>

                  {updateSuccess && (
                    <div className="text-[11px] text-emerald-400 bg-emerald-500/10 p-2 rounded border border-emerald-500/20 flex items-center space-x-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>State updated successfully. Audit history preserved in evidence.</span>
                    </div>
                  )}

                  <div className="flex justify-end pt-1">
                    <button
                      type="submit"
                      disabled={updating}
                      className="px-4 py-1.5 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold rounded-lg text-xs transition-colors"
                    >
                      {updating ? 'Saving...' : 'Apply State Change'}
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
