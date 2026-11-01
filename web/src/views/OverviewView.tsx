import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Server, 
  Target, 
  AlertOctagon, 
  ArrowUpRight, 
  Cpu, 
  Sparkles, 
  RefreshCw 
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer, 
  Cell
} from 'recharts';
import { api } from '../api/client';
import { 
  SystemInfoResponse, 
  AssessmentListItem, 
  AssessmentPostureResponse 
} from '../api/types';

interface OverviewViewProps {
  onNavigate: (tab: string, meta?: any) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({ onNavigate }) => {
  const [system, setSystem] = useState<SystemInfoResponse | null>(null);
  const [assessments, setAssessments] = useState<AssessmentListItem[]>([]);
  const [posture, setPosture] = useState<AssessmentPostureResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [sysRes, assessRes] = await Promise.all([
        api.getSystemInfo(),
        api.getAssessments({ limit: 5 }),
      ]);
      setSystem(sysRes);
      setAssessments(assessRes);

      if (assessRes.length > 0) {
        try {
          const postureRes = await api.getAssessmentPosture(assessRes[0].id);
          setPosture(postureRes);
        } catch {
          // Posture may not be calculated if scan has no assets
        }
      }
    } catch (err: any) {
      setError(err.message || 'Failed to connect to ReconForge API');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const getScoreColor = (score: number) => {
    if (score < 25) return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
    if (score < 50) return 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10';
    if (score < 75) return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
    return 'text-rose-400 border-rose-500/30 bg-rose-500/10';
  };

  const getPriorityData = () => {
    if (!posture || !posture.priority_distribution) {
      return [
        { name: 'P1 (Immediate)', count: 0, color: '#f43f5e' },
        { name: 'P2 (High)', count: 0, color: '#f59e0b' },
        { name: 'P3 (Medium)', count: 0, color: '#eab308' },
        { name: 'P4 (Low)', count: 0, color: '#0ea5e9' },
        { name: 'P5 (Info)', count: 0, color: '#64748b' },
      ];
    }
    const p = posture.priority_distribution;
    return [
      { name: 'P1', fullName: 'Immediate', count: p['p1'] || 0, color: '#f43f5e' },
      { name: 'P2', fullName: 'High', count: p['p2'] || 0, color: '#f59e0b' },
      { name: 'P3', fullName: 'Medium', count: p['p3'] || 0, color: '#eab308' },
      { name: 'P4', fullName: 'Low', count: p['p4'] || 0, color: '#0ea5e9' },
      { name: 'P5', fullName: 'Info', count: p['p5'] || 0, color: '#64748b' },
    ];
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-3">
        <RefreshCw className="w-8 h-8 text-emerald-400 animate-spin" />
        <p className="text-xs text-slate-400">Loading ReconForge Intelligence State...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 bg-rose-500/10 border border-rose-500/30 rounded-2xl text-center space-y-3 max-w-lg mx-auto my-12">
        <AlertOctagon className="w-10 h-10 text-rose-400 mx-auto" />
        <h3 className="font-semibold text-rose-200">Unable to Connect to API</h3>
        <p className="text-xs text-slate-400">{error}</p>
        <p className="text-[11px] text-slate-500">
          Ensure <code className="text-emerald-400">reconforge serve</code> is active on <code className="text-emerald-400">http://127.0.0.1:8000</code>.
        </p>
        <button
          onClick={fetchData}
          className="mt-2 px-4 py-1.5 bg-rose-500 text-slate-950 font-semibold text-xs rounded-lg hover:bg-rose-400"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  const latestScore = posture ? posture.risk_score : assessments[0]?.risk_score ?? 0;
  const latestLevel = posture ? posture.risk_level : 'UNKNOWN';

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Top Banner / Heading */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-gradient-to-r from-slate-900/90 via-slate-900/50 to-slate-950 p-6 rounded-2xl border border-slate-800 shadow-xl">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
            <span>Perimeter Attack Surface Posture</span>
            <Sparkles className="w-4 h-4 text-emerald-400" />
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time exposure telemetry, mathematical asset risk scores, and deterministic remediations.
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={() => onNavigate('assessments')}
            className="flex items-center space-x-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold text-xs rounded-xl shadow-lg shadow-emerald-500/20 transition-all"
          >
            <Target className="w-4 h-4" />
            <span>Launch New Scan</span>
          </button>
          <button
            onClick={fetchData}
            title="Refresh Metrics"
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs border border-slate-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-2xl shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Total Assets</span>
            <Server className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono">
            {system?.total_assets ?? 0}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Verified host perimeter</p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-2xl shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Total Findings</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono">
            {system?.total_findings ?? 0}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Identified exposures & CVEs</p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-2xl shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Assessments Run</span>
            <Target className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono">
            {system?.total_assessments ?? 0}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Historical scan baselines</p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-2xl shadow-sm">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Active Rules & KEV</span>
            <Cpu className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 font-mono">
            {system?.rules_count ?? 0}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            {system?.cached_cves_count ?? 0} CVEs cached
          </p>
        </div>
      </div>

      {/* Main Analytics: Posture Gauge & Priority Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Posture Score Card */}
        <div className="bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl flex flex-col justify-between shadow-sm">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-semibold text-slate-200 text-sm">Attack Surface Posture</h2>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                Latest Assessment
              </span>
            </div>
            <p className="text-xs text-slate-400 mb-6 leading-relaxed">
              Max-anchored multi-factor composite score (0-100) weighting exposure baselines, verified findings, asset criticalities, and CISA KEV threats.
            </p>
          </div>

          <div className="flex flex-col items-center justify-center my-4">
            <div className={`w-36 h-36 rounded-full border-4 flex flex-col items-center justify-center shadow-2xl transition-all ${getScoreColor(latestScore)}`}>
              <span className="text-4xl font-extrabold font-mono tracking-tighter">
                {latestScore.toFixed(1)}
              </span>
              <span className="text-[11px] font-semibold uppercase tracking-wider mt-1 opacity-90">
                {latestLevel}
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mt-4 text-center">
              Target risk ceiling: &lt; 25.0 (Low Risk Baseline)
            </p>
          </div>

          <button
            onClick={() => onNavigate('findings')}
            className="w-full mt-4 flex items-center justify-center space-x-1.5 py-2 px-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition-colors"
          >
            <span>Review Vulnerability Queue</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Priority Tier Distribution Chart */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-1">
              <h2 className="font-semibold text-slate-200 text-sm">Remediation Urgency (P1 - P5)</h2>
              <span className="text-[10px] text-slate-400 font-mono">Deterministic Splicing</span>
            </div>
            <p className="text-xs text-slate-400 mb-4">
              P1 Immediate (KEV/Critical) down to P5 Informational network observations.
            </p>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={getPriorityData()} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                  labelStyle={{ color: '#94a3b8' }}
                />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {getPriorityData().map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-5 gap-2 pt-4 border-t border-slate-800/80 text-center">
            {getPriorityData().map((item) => (
              <div key={item.name} className="flex flex-col items-center">
                <span className="text-[11px] font-mono text-slate-400">{item.name}</span>
                <span className="text-sm font-bold font-mono" style={{ color: item.color }}>
                  {item.count}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Assessments Table */}
      <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-6 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="font-semibold text-slate-200 text-sm">Recent Assessments</h2>
            <p className="text-xs text-slate-400">Execution baselines recorded in local SQLite database.</p>
          </div>
          <button
            onClick={() => onNavigate('assessments')}
            className="text-xs text-emerald-400 hover:text-emerald-300 font-medium flex items-center space-x-1"
          >
            <span>View All Runs</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {assessments.length === 0 ? (
          <div className="text-center py-8 text-slate-500 text-xs">
            No assessments recorded yet. Launch your first scan to establish a security baseline.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono">
                  <th className="pb-3 pl-2">Assessment Name</th>
                  <th className="pb-3">Status</th>
                  <th className="pb-3">Started</th>
                  <th className="pb-3">Assets</th>
                  <th className="pb-3">Findings</th>
                  <th className="pb-3">Risk Score</th>
                  <th className="pb-3 text-right pr-2">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {assessments.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 pl-2 font-medium text-slate-200">
                      <div>{a.name}</div>
                      <div className="text-[10px] font-mono text-slate-500">{a.id.slice(0, 8)}...</div>
                    </td>
                    <td className="py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-mono ${
                        a.status === 'completed'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : a.status === 'running'
                          ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 animate-pulse'
                          : 'bg-slate-800 text-slate-400'
                      }`}>
                        {a.status}
                      </span>
                    </td>
                    <td className="py-3 text-slate-400 font-mono text-[11px]">
                      {new Date(a.start_time).toLocaleString()}
                    </td>
                    <td className="py-3 text-slate-300 font-mono">{a.assets_count}</td>
                    <td className="py-3 text-slate-300 font-mono">{a.findings_count}</td>
                    <td className="py-3">
                      {a.risk_score !== null && a.risk_score !== undefined ? (
                        <span className={`font-mono font-bold ${
                          a.risk_score < 25 ? 'text-emerald-400' :
                          a.risk_score < 50 ? 'text-yellow-400' :
                          a.risk_score < 75 ? 'text-amber-400' : 'text-rose-400'
                        }`}>
                          {a.risk_score.toFixed(1)}
                        </span>
                      ) : (
                        <span className="text-slate-600 font-mono">—</span>
                      )}
                    </td>
                    <td className="py-3 text-right pr-2">
                      <button
                        onClick={() => onNavigate('reports', { assessmentId: a.id })}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-[11px] font-medium transition-colors"
                      >
                        Export
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
