import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  Layers, 
  AlertTriangle, 
  GitCompare, 
  FileText, 
  Settings, 
  Key, 
  CheckCircle2, 
  RefreshCw
} from 'lucide-react';
import { api } from '../../api/client';
import { HealthResponse } from '../../api/types';

interface ShellProps {
  currentTab: string;
  onTabChange: (tab: string) => void;
  children: React.ReactNode;
}

export const Shell: React.FC<ShellProps> = ({ currentTab, onTabChange, children }) => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [isHealthLoading, setIsHealthLoading] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState(api.getApiKey() || '');
  const [saveMsg, setSaveMsg] = useState('');

  const checkHealth = async () => {
    setIsHealthLoading(true);
    try {
      const res = await api.getHealth();
      setHealth(res);
    } catch {
      setHealth(null);
    } finally {
      setIsHealthLoading(false);
    }
  };

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleSaveApiKey = (e: React.FormEvent) => {
    e.preventDefault();
    api.setApiKey(apiKeyInput.trim() || null);
    setSaveMsg('API Key updated successfully');
    setTimeout(() => setSaveMsg(''), 3000);
    checkHealth();
  };

  const navItems = [
    { id: 'overview', label: 'Posture Overview', icon: Activity },
    { id: 'assessments', label: 'Scan & Assess', icon: Shield },
    { id: 'inventory', label: 'Asset Inventory', icon: Layers },
    { id: 'findings', label: 'Vulnerabilities', icon: AlertTriangle },
    { id: 'diff', label: 'Diff & Drift', icon: GitCompare },
    { id: 'reports', label: 'Reports & Export', icon: FileText },
  ];

  return (
    <div className="flex flex-col min-h-screen bg-[#090d16] text-slate-100">
      {/* Top Navigation Bar */}
      <header className="sticky top-0 z-50 bg-[#0c1222]/90 backdrop-blur-md border-b border-slate-800/80 px-4 lg:px-8 py-3 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-xl flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-500/10">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400 bg-clip-text text-transparent">
                ReconForge
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                v0.9.0
              </span>
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block">
              Attack Surface Management & Exposure Intelligence
            </p>
          </div>
        </div>

        {/* Desktop Navigation Tabs */}
        <nav className="hidden md:flex items-center space-x-1 bg-slate-900/60 p-1 rounded-xl border border-slate-800">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-emerald-500 text-slate-950 font-semibold shadow-md shadow-emerald-500/20'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Controls & Health */}
        <div className="flex items-center space-x-3">
          {/* Health Badge */}
          <div 
            onClick={checkHealth}
            title={health ? `API Online (${health.version})` : 'API Disconnected'}
            className="cursor-pointer flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-mono border transition-colors bg-slate-900/60 hover:bg-slate-800/80"
          >
            {isHealthLoading ? (
              <RefreshCw className="w-3 h-3 text-cyan-400 animate-spin" />
            ) : health ? (
              <>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span className="text-emerald-400 text-[11px]">API Online</span>
              </>
            ) : (
              <>
                <span className="w-2 h-2 rounded-full bg-rose-400"></span>
                <span className="text-rose-400 text-[11px]">Offline</span>
              </>
            )}
          </div>

          {/* Settings / API Key Button */}
          <button
            onClick={() => setIsSettingsOpen(!isSettingsOpen)}
            className={`p-2 rounded-lg border text-xs transition-colors ${
              api.getApiKey()
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
            title="Configure API Key"
          >
            <Settings className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* Mobile Navigation bar */}
      <div className="md:hidden flex overflow-x-auto bg-[#0c1222] border-b border-slate-800 p-2 space-x-1 scrollbar-none">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`flex-shrink-0 flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium ${
                isActive
                  ? 'bg-emerald-500 text-slate-950 font-semibold'
                  : 'text-slate-400 hover:bg-slate-800'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>

      {/* Settings Modal Drawer */}
      {isSettingsOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-2xl w-full max-w-md p-6 shadow-2xl relative animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Key className="w-5 h-5 text-emerald-400" />
                <h3 className="font-semibold text-slate-100 text-base">API Authentication Settings</h3>
              </div>
              <button 
                onClick={() => setIsSettingsOpen(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-400 mb-4 leading-relaxed">
              When ReconForge is started with <code className="text-emerald-400">--api-key &lt;secret&gt;</code>, provide the secret key here. It will be passed in the <code className="text-emerald-400">X-API-Key</code> request header.
            </p>

            <form onSubmit={handleSaveApiKey} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                  ReconForge API Key
                </label>
                <input
                  type="password"
                  placeholder="Leave empty for unauthenticated local development"
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                  className="w-full px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              {saveMsg && (
                <div className="flex items-center space-x-2 text-xs text-emerald-400 bg-emerald-500/10 p-2.5 rounded-lg border border-emerald-500/20">
                  <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                  <span>{saveMsg}</span>
                </div>
              )}

              <div className="flex items-center justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setApiKeyInput('');
                    api.setApiKey(null);
                    setSaveMsg('API Key cleared');
                    setTimeout(() => setSaveMsg(''), 2000);
                  }}
                  className="px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800"
                >
                  Clear Key
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold rounded-lg text-xs shadow-md transition-all"
                >
                  Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <main className="flex-1 p-4 lg:p-8 max-w-7xl mx-auto w-full">
        {children}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-[#070b13] px-6 py-4 text-center text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2">
        <div className="flex items-center space-x-2">
          <span>ReconForge v0.9.0</span>
          <span>•</span>
          <span className="text-emerald-500 font-medium">Local-First Defensive Intelligence</span>
        </div>
        <div className="flex items-center space-x-4">
          <a 
            href="/docs" 
            target="_blank" 
            rel="noreferrer" 
            className="hover:text-emerald-400 transition-colors"
          >
            Swagger API Docs
          </a>
          <a 
            href="/redoc" 
            target="_blank" 
            rel="noreferrer" 
            className="hover:text-emerald-400 transition-colors"
          >
            ReDoc
          </a>
          <a 
            href="https://github.com/ayus1n9/reconforge" 
            target="_blank" 
            rel="noreferrer" 
            className="hover:text-emerald-400 transition-colors"
          >
            GitHub Repository
          </a>
        </div>
      </footer>
    </div>
  );
};
