import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Download, 
  FileCode, 
  Table, 
  FileJson, 
  Upload, 
  CheckCircle2, 
  AlertTriangle 
} from 'lucide-react';
import { api } from '../api/client';
import { AssessmentListItem, SnapshotImportResponse } from '../api/types';

interface ReportsViewProps {
  initialAssessmentId?: string;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ initialAssessmentId }) => {
  const [assessments, setAssessments] = useState<AssessmentListItem[]>([]);
  const [selectedId, setSelectedId] = useState<string>(initialAssessmentId || '');
  const [downloadingFormat, setDownloadingFormat] = useState<string | null>(null);

  // Snapshot import state
  const [snapshotText, setSnapshotText] = useState('');
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState<SnapshotImportResponse | null>(null);
  const [importError, setImportError] = useState<string | null>(null);

  useEffect(() => {
    const loadList = async () => {
      try {
        const res = await api.getAssessments({ limit: 50 });
        setAssessments(res);
        if (!selectedId && res.length > 0) {
          setSelectedId(res[0].id);
        }
      } catch {
        // Ignore
      }
    };
    loadList();
  }, []);

  const handleDownload = async (format: 'html' | 'json' | 'markdown' | 'csv') => {
    if (!selectedId) return;
    setDownloadingFormat(format);
    try {
      await api.downloadReport(selectedId, format);
    } catch (err: any) {
      alert(`Report download failed: ${err.message}`);
    } finally {
      setDownloadingFormat(null);
    }
  };

  const handleExportSnapshot = async () => {
    if (!selectedId) return;
    setDownloadingFormat('snapshot');
    try {
      await api.exportSnapshot(selectedId);
    } catch (err: any) {
      alert(`Snapshot export failed: ${err.message}`);
    } finally {
      setDownloadingFormat(null);
    }
  };

  const handleImportSnapshot = async (e: React.FormEvent) => {
    e.preventDefault();
    setImporting(true);
    setImportResult(null);
    setImportError(null);
    try {
      if (!snapshotText.trim()) throw new Error('Please provide snapshot JSON data.');
      const parsed = JSON.parse(snapshotText);
      const res = await api.importSnapshot(parsed);
      setImportResult(res);
      setSnapshotText('');
      // Reload assessments list
      const updated = await api.getAssessments({ limit: 50 });
      setAssessments(updated);
    } catch (err: any) {
      setImportError(err.message || 'Snapshot import failed.');
    } finally {
      setImporting(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header */}
      <div className="bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm">
        <h1 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
          <FileText className="w-5 h-5 text-emerald-400" />
          <span>Audit Reports & Snapshot Persistence</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Export SOC-ready multi-format intelligence reports or backup point-in-time assessment snapshots for air-gapped archival.
        </p>
      </div>

      {/* Report Generator Panel */}
      <div className="bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm space-y-6">
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-2">
            Select Assessment Execution
          </label>
          <select
            value={selectedId}
            onChange={(e) => setSelectedId(e.target.value)}
            className="w-full md:w-1/2 px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
          >
            {assessments.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({new Date(a.start_time).toLocaleDateString()}) - {a.id.slice(0, 8)}
              </option>
            ))}
          </select>
        </div>

        {/* Format Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* HTML */}
          <div className="bg-slate-950 p-5 rounded-2xl border border-slate-800/80 hover:border-emerald-500/40 transition-all flex flex-col justify-between space-y-4">
            <div>
              <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded-xl w-fit mb-3">
                <FileText className="w-5 h-5" />
              </div>
              <h3 className="font-bold text-slate-100 text-sm">HTML Executive Audit</h3>
              <p className="text-xs text-slate-400 mt-1">
                Self-contained, interactive HTML document formatted for C-suite briefings and client presentations.
              </p>
            </div>
            <button
              onClick={() => handleDownload('html')}
              disabled={!selectedId || downloadingFormat === 'html'}
              className="flex items-center justify-center space-x-1.5 w-full py-2 bg-slate-800 hover:bg-emerald-500 hover:text-slate-950 text-slate-200 text-xs font-semibold rounded-xl transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{downloadingFormat === 'html' ? 'Generating...' : 'Download HTML'}</span>
            </button>
          </div>

          {/* JSON */}
          <div className="bg-slate-950 p-5 rounded-2xl border border-slate-800/80 hover:border-cyan-500/40 transition-all flex flex-col justify-between space-y-4">
            <div>
              <div className="p-2 bg-cyan-500/10 text-cyan-400 rounded-xl w-fit mb-3">
                <FileCode className="w-5 h-5" />
              </div>
              <h3 className="font-bold text-slate-100 text-sm">JSON SIEM Feed</h3>
              <p className="text-xs text-slate-400 mt-1">
                Structured JSON schema payload suitable for SIEM, SOAR, and automated CI/CD pipeline consumption.
              </p>
            </div>
            <button
              onClick={() => handleDownload('json')}
              disabled={!selectedId || downloadingFormat === 'json'}
              className="flex items-center justify-center space-x-1.5 w-full py-2 bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 text-slate-200 text-xs font-semibold rounded-xl transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{downloadingFormat === 'json' ? 'Generating...' : 'Download JSON'}</span>
            </button>
          </div>

          {/* Markdown */}
          <div className="bg-slate-950 p-5 rounded-2xl border border-slate-800/80 hover:border-amber-500/40 transition-all flex flex-col justify-between space-y-4">
            <div>
              <div className="p-2 bg-amber-500/10 text-amber-400 rounded-xl w-fit mb-3">
                <FileText className="w-5 h-5" />
              </div>
              <h3 className="font-bold text-slate-100 text-sm">Markdown Report</h3>
              <p className="text-xs text-slate-400 mt-1">
                GitHub-Flavored Markdown summary with priority breakdowns and remediation roadmaps.
              </p>
            </div>
            <button
              onClick={() => handleDownload('markdown')}
              disabled={!selectedId || downloadingFormat === 'markdown'}
              className="flex items-center justify-center space-x-1.5 w-full py-2 bg-slate-800 hover:bg-amber-500 hover:text-slate-950 text-slate-200 text-xs font-semibold rounded-xl transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{downloadingFormat === 'markdown' ? 'Generating...' : 'Download MD'}</span>
            </button>
          </div>

          {/* CSV */}
          <div className="bg-slate-950 p-5 rounded-2xl border border-slate-800/80 hover:border-rose-500/40 transition-all flex flex-col justify-between space-y-4">
            <div>
              <div className="p-2 bg-rose-500/10 text-rose-400 rounded-xl w-fit mb-3">
                <Table className="w-5 h-5" />
              </div>
              <h3 className="font-bold text-slate-100 text-sm">Hardened CSV</h3>
              <p className="text-xs text-slate-400 mt-1">
                Spreadsheet export fortified against formula injection attacks (CWE-1236) by control character neutralization.
              </p>
            </div>
            <button
              onClick={() => handleDownload('csv')}
              disabled={!selectedId || downloadingFormat === 'csv'}
              className="flex items-center justify-center space-x-1.5 w-full py-2 bg-slate-800 hover:bg-rose-500 hover:text-slate-950 text-slate-200 text-xs font-semibold rounded-xl transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{downloadingFormat === 'csv' ? 'Generating...' : 'Download CSV'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Snapshot Persistence & Import */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Export Snapshot */}
        <div className="bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm space-y-4">
          <div className="flex items-center space-x-2">
            <FileJson className="w-5 h-5 text-emerald-400" />
            <h2 className="font-semibold text-slate-200 text-sm">Export Point-in-Time Snapshot</h2>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Exports a schema v1.1.0 JSON snapshot containing complete point-in-time asset records, observed services, findings, and risk posture. Enables standalone offline diffing and cold archival.
          </p>

          <button
            onClick={handleExportSnapshot}
            disabled={!selectedId || downloadingFormat === 'snapshot'}
            className="flex items-center justify-center space-x-2 px-4 py-2 bg-slate-800 hover:bg-emerald-500 hover:text-slate-950 text-slate-200 text-xs font-semibold rounded-xl transition-all"
          >
            <Download className="w-4 h-4" />
            <span>{downloadingFormat === 'snapshot' ? 'Exporting...' : 'Export Snapshot JSON'}</span>
          </button>
        </div>

        {/* Import Snapshot */}
        <div className="bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm space-y-4">
          <div className="flex items-center space-x-2">
            <Upload className="w-5 h-5 text-cyan-400" />
            <h2 className="font-semibold text-slate-200 text-sm">Import External Snapshot</h2>
          </div>
          <p className="text-xs text-slate-400">
            Paste or load an untrusted assessment snapshot JSON. The backend validates schema constraints and populates your asset inventory.
          </p>

          <form onSubmit={handleImportSnapshot} className="space-y-3">
            <textarea
              value={snapshotText}
              onChange={(e) => setSnapshotText(e.target.value)}
              rows={3}
              placeholder="Paste snapshot JSON payload here..."
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-[11px] text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
            />

            {importResult && (
              <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-xs text-emerald-300 space-y-1">
                <div className="flex items-center space-x-1.5 font-bold">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>{importResult.message}</span>
                </div>
                <div className="text-[11px] text-slate-400 font-mono">
                  Imported {importResult.assets_count} assets and {importResult.findings_count} findings.
                </div>
              </div>
            )}

            {importError && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-xs text-rose-300 flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                <span>{importError}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={importing}
              className="flex items-center justify-center space-x-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold rounded-xl transition-all"
            >
              <Upload className="w-4 h-4" />
              <span>{importing ? 'Validating & Importing...' : 'Import into Database'}</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
