import React, { useState, useEffect } from 'react';
import { 
  Layers, 
  Search, 
  Filter, 
  Server, 
  Globe, 
  RefreshCw 
} from 'lucide-react';
import { api } from '../api/client';
import { 
  AssetListItem, 
  AssetDetailResponse 
} from '../api/types';

interface AssetInventoryViewProps {
  onNavigate: (tab: string, meta?: any) => void;
}

export const AssetInventoryView: React.FC<AssetInventoryViewProps> = ({ onNavigate }) => {
  const [assets, setAssets] = useState<AssetListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [criticalityFilter, setCriticalityFilter] = useState('');
  const [selectedAsset, setSelectedAsset] = useState<AssetDetailResponse | null>(null);

  const fetchAssets = async () => {
    setLoading(true);
    try {
      const res = await api.getAssets({
        search: search.trim() || undefined,
        criticality: criticalityFilter || undefined,
        limit: 100,
      });
      setAssets(res);
    } catch {
      setAssets([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, [criticalityFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchAssets();
  };

  const handleSelectAsset = async (idOrIp: string) => {
    setSelectedAsset(null);
    try {
      const detail = await api.getAssetDetail(idOrIp);
      setSelectedAsset(detail);
    } catch (err: any) {
      alert(`Failed to load asset: ${err.message}`);
    }
  };

  const getCriticalityBadge = (crit: string) => {
    const c = crit.toLowerCase();
    if (c === 'critical') return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
    if (c === 'high') return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    if (c === 'medium') return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
    return 'bg-sky-500/10 text-sky-400 border-sky-500/20';
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header */}
      <div className="bg-slate-900/60 border border-slate-800/80 p-6 rounded-2xl shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
            <Layers className="w-5 h-5 text-emerald-400" />
            <span>Perimeter Asset Inventory</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Normalized inventory of discovered host endpoints, active transport listeners, and application banners.
          </p>
        </div>
        <button
          onClick={fetchAssets}
          className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs border border-slate-700 transition-colors self-start sm:self-auto"
          title="Refresh Assets"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900/60 border border-slate-800/80 p-4 rounded-2xl shadow-sm flex flex-col md:flex-row items-center gap-3">
        <form onSubmit={handleSearchSubmit} className="flex-1 w-full relative">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by IP address or observed hostname..."
            className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-emerald-500 font-mono"
          />
        </form>

        <div className="flex items-center space-x-2 w-full md:w-auto">
          <Filter className="w-4 h-4 text-slate-500" />
          <select
            value={criticalityFilter}
            onChange={(e) => setCriticalityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-300 py-2 px-3 rounded-xl focus:outline-none focus:border-emerald-500"
          >
            <option value="">All Criticalities</option>
            <option value="critical">Critical Only</option>
            <option value="high">High Only</option>
            <option value="medium">Medium Only</option>
            <option value="low">Low Only</option>
          </select>
        </div>
      </div>

      {/* Assets Grid / Table */}
      <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-6 shadow-sm">
        {loading ? (
          <div className="text-center py-12 text-xs text-slate-400 space-y-2">
            <RefreshCw className="w-6 h-6 text-emerald-400 animate-spin mx-auto" />
            <p>Loading asset inventory...</p>
          </div>
        ) : assets.length === 0 ? (
          <div className="text-center py-12 text-slate-500 text-xs">
            No assets match your search criteria.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {assets.map((asset) => (
              <div
                key={asset.id}
                onClick={() => handleSelectAsset(asset.id)}
                className="bg-slate-950/80 border border-slate-800 hover:border-emerald-500/50 p-5 rounded-2xl transition-all cursor-pointer hover:shadow-lg hover:shadow-emerald-500/5 flex flex-col justify-between group"
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-2">
                      <Server className="w-4 h-4 text-slate-400 group-hover:text-emerald-400 transition-colors" />
                      <span className="font-mono font-bold text-slate-100 text-sm">
                        {asset.ip_address}
                      </span>
                    </div>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${getCriticalityBadge(asset.criticality)}`}>
                      {asset.criticality}
                    </span>
                  </div>

                  {asset.observed_hostnames.length > 0 ? (
                    <div className="flex items-center space-x-1 text-slate-400 text-xs mb-3 font-mono">
                      <Globe className="w-3 h-3 text-cyan-400" />
                      <span className="truncate">{asset.observed_hostnames.join(', ')}</span>
                    </div>
                  ) : (
                    <div className="text-[11px] text-slate-600 font-mono mb-3">No hostname mapped</div>
                  )}
                </div>

                <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center space-x-3 text-slate-400">
                    <span>{asset.services_count} port(s) open</span>
                    <span>•</span>
                    <span className="text-[11px] text-slate-500">{asset.address_family}</span>
                  </div>
                  {asset.risk_score !== null && asset.risk_score !== undefined && (
                    <span className={`font-bold ${
                      asset.risk_score < 25 ? 'text-emerald-400' :
                      asset.risk_score < 50 ? 'text-yellow-400' :
                      asset.risk_score < 75 ? 'text-amber-400' : 'text-rose-400'
                    }`}>
                      {asset.risk_score.toFixed(1)}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Asset Detail Slideout Modal */}
      {selectedAsset && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-2xl w-full max-w-3xl p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
              <div className="flex items-center space-x-3">
                <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-400">
                  <Server className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="font-bold text-slate-100 text-base font-mono">
                    {selectedAsset.ip_address}
                  </h3>
                  <p className="text-xs text-slate-400">
                    Host ID: <span className="font-mono">{selectedAsset.id}</span>
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedAsset(null)}
                className="text-slate-400 hover:text-slate-200 text-sm"
              >
                ✕
              </button>
            </div>

            {/* Quick Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 font-mono">Criticality</span>
                <p className={`text-xs font-semibold capitalize ${
                  selectedAsset.criticality === 'critical' ? 'text-rose-400' :
                  selectedAsset.criticality === 'high' ? 'text-amber-400' : 'text-slate-200'
                }`}>
                  {selectedAsset.criticality}
                </p>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 font-mono">Open Ports</span>
                <p className="text-xs font-semibold text-emerald-400 font-mono">
                  {selectedAsset.services.length}
                </p>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 font-mono">Findings</span>
                <p className="text-xs font-semibold text-rose-400 font-mono">
                  {selectedAsset.findings_count}
                </p>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 font-mono">Family</span>
                <p className="text-xs font-semibold text-slate-200 font-mono">{selectedAsset.address_family}</p>
              </div>
            </div>

            {/* Observed Services Table */}
            <div className="space-y-4">
              <h4 className="font-semibold text-slate-200 text-sm flex items-center justify-between">
                <span>Observed Transport Services ({selectedAsset.services.length})</span>
              </h4>

              {selectedAsset.services.length === 0 ? (
                <p className="text-xs text-slate-500 py-4 text-center">No open ports detected on this host.</p>
              ) : (
                <div className="space-y-3">
                  {selectedAsset.services.map((svc) => (
                    <div
                      key={svc.id}
                      className="p-4 bg-slate-950 rounded-xl border border-slate-800/80 space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span className="font-mono font-bold text-emerald-400 text-sm">
                            {svc.port}/{svc.protocol}
                          </span>
                          <span className="text-xs font-medium text-slate-200">
                            {svc.service_name}
                          </span>
                          {svc.product && (
                            <span className="text-[11px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                              {svc.product} {svc.version || ''}
                            </span>
                          )}
                        </div>
                        <span className="text-[10px] font-mono text-slate-500 uppercase">
                          {svc.confidence}
                        </span>
                      </div>

                      {svc.cpe_candidate && (
                        <div className="text-[11px] font-mono text-slate-400">
                          <span className="text-slate-500">CPE:</span> {svc.cpe_candidate}
                        </div>
                      )}

                      {svc.banner_snippet && (
                        <pre className="p-2.5 bg-slate-900 rounded-lg text-[10px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap">
                          {svc.banner_snippet}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="flex items-center justify-end space-x-3 mt-6 pt-4 border-t border-slate-800">
              <button
                onClick={() => {
                  const ip = selectedAsset.ip_address;
                  setSelectedAsset(null);
                  onNavigate('findings', { targetIp: ip });
                }}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium transition-colors"
              >
                View Findings for this Host
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
