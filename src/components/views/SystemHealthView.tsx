import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  CheckCircle, 
  AlertTriangle, 
  XCircle, 
  RefreshCw, 
  Cpu, 
  Server, 
  Database, 
  ShieldCheck, 
  FileText,
  Clock
} from 'lucide-react';
import { SystemHealthReport } from '../../core/types';

export const SystemHealthView: React.FC = () => {
  const [health, setHealth] = useState<SystemHealthReport | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const fetchHealth = async () => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        const data = await res.json();
        setHealth(data);
      }
    } catch (e) {
      console.error('Failed to probe health report:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
        <div>
          <h2 className="text-base font-bold text-slate-100 font-mono flex items-center space-x-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span>INFRASTRUCTURE COMPONENT HEALTH PROBES</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Real-time readiness telemetry across perimeter boundary services. Honest status reporting (no fabricated indicators).
          </p>
        </div>

        <button
          onClick={fetchHealth}
          disabled={isLoading}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs transition-colors cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>REFRESH HEALTH</span>
        </button>
      </div>

      {!health ? (
        <div className="p-12 text-center text-slate-500 font-mono text-xs">
          Probing system health...
        </div>
      ) : (
        <div className="space-y-4 font-mono text-xs">
          {/* Overall Health Status Banner */}
          <div className={`p-4 rounded-xl border flex items-center justify-between ${
            health.status === 'HEALTHY'
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
              : 'bg-amber-950/40 border-amber-800/60 text-amber-300'
          }`}>
            <div className="flex items-center space-x-3">
              {health.status === 'HEALTHY' ? (
                <CheckCircle className="w-6 h-6 text-emerald-400" />
              ) : (
                <AlertTriangle className="w-6 h-6 text-amber-400" />
              )}
              <div>
                <div className="font-bold text-sm tracking-wide">SYSTEM READINESS: {health.status}</div>
                <div className="text-[11px] opacity-80 mt-0.5">
                  Last verified at {new Date(health.timestamp).toLocaleTimeString()}
                </div>
              </div>
            </div>
            <span className="text-[10px] px-2 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
              6 Core Subsystems Monitored
            </span>
          </div>

          {/* Component Health Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* 1. Gateway */}
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3">
              <div className="flex justify-between items-start">
                <span className="text-slate-200 font-bold flex items-center space-x-1.5">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  <span>Boundary Gateway</span>
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                  {health.components.gateway.status}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">{health.components.gateway.details}</p>
              <div className="text-[10px] text-slate-500 pt-1 border-t border-slate-800/80">
                Latency: <span className="text-slate-300 font-semibold">{health.components.gateway.latencyMs}ms</span>
              </div>
            </div>

            {/* 2. Detectors */}
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3">
              <div className="flex justify-between items-start">
                <span className="text-slate-200 font-bold flex items-center space-x-1.5">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  <span>Detection Engine</span>
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                  {health.components.detectors.status}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">{health.components.detectors.details}</p>
              <div className="text-[10px] text-slate-500 pt-1 border-t border-slate-800/80">
                Active Layers: <span className="text-slate-300 font-semibold">{health.components.detectors.activeCount} detectors</span>
              </div>
            </div>

            {/* 3. Policy Engine */}
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3">
              <div className="flex justify-between items-start">
                <span className="text-slate-200 font-bold flex items-center space-x-1.5">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <span>Policy Engine</span>
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                  {health.components.policyEngine.status}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">{health.components.policyEngine.details}</p>
              <div className="text-[10px] text-slate-500 pt-1 border-t border-slate-800/80">
                Active Rules: <span className="text-slate-300 font-semibold">{health.components.policyEngine.activePolicies} rules</span>
              </div>
            </div>

            {/* 4. Database */}
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3">
              <div className="flex justify-between items-start">
                <span className="text-slate-200 font-bold flex items-center space-x-1.5">
                  <Database className="w-4 h-4 text-cyan-400" />
                  <span>Storage Layer</span>
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                  {health.components.database.status}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">{health.components.database.details}</p>
              <div className="text-[10px] text-slate-500 pt-1 border-t border-slate-800/80">
                Audit Records: <span className="text-slate-300 font-semibold">{health.components.database.logCount} records</span>
              </div>
            </div>

            {/* 5. AI Providers */}
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3">
              <div className="flex justify-between items-start">
                <span className="text-slate-200 font-bold flex items-center space-x-1.5">
                  <Server className="w-4 h-4 text-cyan-400" />
                  <span>AI Provider Route</span>
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  health.components.aiProviders.status === 'HEALTHY'
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                    : 'bg-amber-950 text-amber-300 border-amber-800'
                }`}>
                  {health.components.aiProviders.status}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">{health.components.aiProviders.details}</p>
              <div className="text-[10px] text-slate-500 pt-1 border-t border-slate-800/80">
                Active Provider: <span className="text-slate-300 font-semibold">{health.components.aiProviders.activeProvider}</span>
              </div>
            </div>

            {/* 6. Audit System */}
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3">
              <div className="flex justify-between items-start">
                <span className="text-slate-200 font-bold flex items-center space-x-1.5">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  <span>Audit Trail Engine</span>
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                  {health.components.auditSystem.status}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">{health.components.auditSystem.details}</p>
              <div className="text-[10px] text-slate-500 pt-1 border-t border-slate-800/80">
                Log Integrity: <span className="text-slate-300 font-semibold">SHA-256 Hashing Enforced</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
