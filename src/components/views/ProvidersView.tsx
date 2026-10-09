import React, { useState } from 'react';
import { 
  Server, 
  Cpu, 
  Activity, 
  CheckCircle, 
  XCircle, 
  RefreshCw, 
  Shield, 
  Sliders,
  AlertTriangle,
  Info
} from 'lucide-react';
import { AIProviderMetadata, UserRole } from '../../core/types';

interface ProvidersViewProps {
  providers: AIProviderMetadata[];
  activeProviderId: string;
  onSelectActiveProvider: (id: string) => Promise<void>;
  userRole: UserRole;
  authToken?: string;
}

export const ProvidersView: React.FC<ProvidersViewProps> = ({
  providers,
  activeProviderId,
  onSelectActiveProvider,
  userRole,
  authToken = 'AEGIS_SECURE_TOKEN_2026'
}) => {
  const [healthStatus, setHealthStatus] = useState<Record<string, { status: string; latencyMs: number; message?: string }>>({});
  const [checkingHealth, setCheckingHealth] = useState(false);

  const runHealthProbes = async () => {
    setCheckingHealth(true);
    try {
      const res = await fetch('/api/providers/health', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      if (res.ok) {
        const data = await res.json();
        setHealthStatus(data);
      }
    } catch (e) {
      console.error('Provider health check failed:', e);
    } finally {
      setCheckingHealth(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
        <div>
          <h2 className="text-base font-bold text-slate-100 font-mono flex items-center space-x-2">
            <Server className="w-4 h-4 text-cyan-400" />
            <span>AI PROVIDER ABSTRACTION &amp; PROXY MANAGEMENT</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Pluggable AI provider adapters. Requests are routed only after passing through the boundary policy engine.
          </p>
        </div>

        <button
          onClick={runHealthProbes}
          disabled={checkingHealth}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs transition-colors cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${checkingHealth ? 'animate-spin text-cyan-400' : ''}`} />
          <span>PROBE ENDPOINT HEALTH</span>
        </button>
      </div>

      {/* Provider Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
        {providers.map((p) => {
          const isActive = p.id === activeProviderId;
          const probe = healthStatus[p.id];

          return (
            <div
              key={p.id}
              className={`p-5 rounded-xl border transition-all flex flex-col justify-between space-y-4 ${
                isActive
                  ? 'bg-slate-900 border-cyan-500/50 shadow-[0_0_15px_rgba(6,182,212,0.15)]'
                  : 'bg-slate-900/60 border-slate-800'
              }`}
            >
              <div>
                <div className="flex justify-between items-start mb-2">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300">
                      {p.type}
                    </span>
                    {isActive && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 border border-cyan-800 text-cyan-300">
                        ACTIVE ROUTE
                      </span>
                    )}
                  </div>

                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                    p.environmentStatus === 'CONFIGURED' ? 'bg-emerald-950 text-emerald-300 border-emerald-800' :
                    p.environmentStatus === 'SIMULATED' ? 'bg-amber-950 text-amber-300 border-amber-800' :
                    'bg-slate-800 text-slate-400 border-slate-700'
                  }`}>
                    {p.environmentStatus}
                  </span>
                </div>

                <h3 className="text-sm font-bold text-slate-100">{p.name}</h3>
                <div className="text-[11px] text-cyan-400 mt-0.5">Model: {p.model}</div>
                <p className="text-[11px] text-slate-400 mt-2 leading-relaxed">{p.description}</p>
              </div>

              {/* Health Probe Result */}
              {probe && (
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px] space-y-1">
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">Endpoint Status:</span>
                    <span className={`font-bold flex items-center space-x-1 ${
                      probe.status === 'HEALTHY' ? 'text-emerald-400' : 'text-amber-400'
                    }`}>
                      {probe.status === 'HEALTHY' ? <CheckCircle className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                      <span>{probe.status} ({probe.latencyMs}ms)</span>
                    </span>
                  </div>
                  {probe.message && <div className="text-[10px] text-slate-500">{probe.message}</div>}
                </div>
              )}

              {/* Activation Control */}
              <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[10px] text-slate-500">
                  {p.isAvailable ? 'Ready for traffic routing' : 'Unavailable (Check API Key)'}
                </span>

                {userRole === 'ADMIN' ? (
                  <button
                    disabled={isActive}
                    onClick={() => onSelectActiveProvider(p.id)}
                    className={`px-3 py-1.5 rounded text-xs font-bold transition-all ${
                      isActive
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 cursor-default'
                        : 'bg-slate-800 hover:bg-slate-700 text-slate-200 cursor-pointer'
                    }`}
                  >
                    {isActive ? 'CURRENT ROUTE' : 'SET AS ACTIVE'}
                  </button>
                ) : (
                  <span className="text-[10px] text-slate-500 italic">Admin role required to route</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
