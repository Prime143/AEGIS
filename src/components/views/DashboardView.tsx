import React from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Activity, 
  Clock, 
  ArrowRight, 
  CheckCircle, 
  XCircle,
  Eye
} from 'lucide-react';
import { LogEvent } from '../../../database';
import { PolicyRule } from '../../core/types';

interface DashboardViewProps {
  events: LogEvent[];
  policies: PolicyRule[];
  activeProviderName: string;
  isProviderMock: boolean;
  onNavigateToConsole: () => void;
  onNavigateToEvents: () => void;
  onSelectEvent: (event: LogEvent) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  events,
  policies,
  activeProviderName,
  isProviderMock,
  onNavigateToConsole,
  onNavigateToEvents,
  onSelectEvent
}) => {
  // Real measured statistics
  const totalInteractions = events.length;
  const totalAllowed = events.filter(e => e.action === 'ALLOW').length;
  const totalMasked = events.filter(e => e.action === 'MODIFIED').length;
  const totalBlocked = events.filter(e => e.action === 'BLOCK').length;
  const totalHighRisk = events.filter(e => e.risk_score >= 70).length;

  const averageLatency = totalInteractions > 0
    ? Math.round(events.reduce((acc, e) => acc + (e.latency_ms || 25), 0) / totalInteractions)
    : 0;

  // Category Distribution
  const categoryCounts: Record<string, number> = {};
  for (const e of events) {
    const cat = e.attack_type || 'General Traffic';
    categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
  }

  // Risk Trend from actual recent events (last 12 events)
  const recentForTrend = [...events].slice(0, 12).reverse();

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner / Quick Action */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900/60 border border-slate-800">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <span>Security Operations Dashboard</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1 leading-relaxed">
            Perimeter boundary telemetry inspecting employee prompts and AI provider responses in real time.
          </p>
        </div>
        <button
          onClick={onNavigateToConsole}
          className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs tracking-wide shadow-sm transition-all cursor-pointer shrink-0"
        >
          <span>OPEN AI CONSOLE</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      {/* Primary KPI Metrics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Scanned</div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-1.5">{totalInteractions}</div>
          <div className="text-[11px] text-slate-500 mt-1">Verified interactions</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="text-xs font-semibold text-emerald-400 uppercase tracking-wider flex items-center space-x-1.5">
            <CheckCircle className="w-3.5 h-3.5" />
            <span>Allowed</span>
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1.5">{totalAllowed}</div>
          <div className="text-[11px] text-slate-500 mt-1">
            {totalInteractions > 0 ? `${Math.round((totalAllowed / totalInteractions) * 100)}% approved` : '0%'}
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="text-xs font-semibold text-amber-400 uppercase tracking-wider flex items-center space-x-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Masked</span>
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1.5">{totalMasked}</div>
          <div className="text-[11px] text-slate-500 mt-1">PII / secrets redacted</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="text-xs font-semibold text-rose-400 uppercase tracking-wider flex items-center space-x-1.5">
            <XCircle className="w-3.5 h-3.5" />
            <span>Blocked</span>
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400 mt-1.5">{totalBlocked}</div>
          <div className="text-[11px] text-slate-500 mt-1">Perimeter intercepted</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="text-xs font-semibold text-rose-300 uppercase tracking-wider flex items-center space-x-1.5">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Critical Risk</span>
          </div>
          <div className="text-2xl font-bold font-mono text-rose-300 mt-1.5">{totalHighRisk}</div>
          <div className="text-[11px] text-slate-500 mt-1">Risk score &ge; 70</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="text-xs font-semibold text-cyan-400 uppercase tracking-wider flex items-center space-x-1.5">
            <Clock className="w-3.5 h-3.5" />
            <span>Avg Latency</span>
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1.5">{averageLatency}ms</div>
          <div className="text-[11px] text-slate-500 mt-1">Measured round-trip</div>
        </div>
      </div>

      {/* Analytics: Risk Trend & Threat Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* SVG Risk Score Trend */}
        <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center justify-between mb-3.5">
            <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Real-Time Risk Trajectory (Recent Interactions)
            </h3>
            <span className="text-xs text-slate-400 font-mono">0 &ndash; 100 Scale</span>
          </div>

          {recentForTrend.length < 2 ? (
            <div className="h-36 flex flex-col items-center justify-center text-slate-500 text-xs">
              <Activity className="w-6 h-6 text-slate-600 mb-2" />
              <span>Awaiting events for trend trajectory...</span>
            </div>
          ) : (
            <div className="w-full">
              <svg viewBox="0 0 500 120" className="w-full h-32 overflow-visible">
                <defs>
                  <linearGradient id="trend-grad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.3" />
                    <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
                  </linearGradient>
                </defs>
                <line x1="20" y1="20" x2="480" y2="20" stroke="#1e293b" strokeWidth="1" strokeDasharray="3,3" />
                <line x1="20" y1="60" x2="480" y2="60" stroke="#1e293b" strokeWidth="1" strokeDasharray="3,3" />
                <line x1="20" y1="100" x2="480" y2="100" stroke="#334155" strokeWidth="1" />
                
                {(() => {
                  const points = recentForTrend.map((evt, idx) => {
                    const x = 20 + idx * (460 / (recentForTrend.length - 1));
                    const y = 20 + (1 - evt.risk_score / 100) * 80;
                    return { x, y, score: evt.risk_score, id: evt.id };
                  });
                  const linePath = points.map((p, idx) => `${idx === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');
                  const areaPath = `${linePath} L ${points[points.length - 1].x} 100 L ${points[0].x} 100 Z`;

                  return (
                    <>
                      <path d={areaPath} fill="url(#trend-grad)" />
                      <path d={linePath} fill="none" stroke="#22d3ee" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                      {points.map((p, i) => (
                        <circle
                          key={i}
                          cx={p.x}
                          cy={p.y}
                          r="4"
                          fill="#0b0f19"
                          stroke={p.score >= 70 ? '#f43f5e' : p.score >= 30 ? '#f59e0b' : '#10b981'}
                          strokeWidth="2.5"
                        />
                      ))}
                    </>
                  );
                })()}
              </svg>
            </div>
          )}
        </div>

        {/* Threat Category Breakdown */}
        <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center justify-between mb-3.5">
            <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Detection Category Distribution
            </h3>
            <span className="text-xs text-slate-400">By Classification</span>
          </div>

          {Object.keys(categoryCounts).length === 0 ? (
            <div className="h-36 flex flex-col items-center justify-center text-slate-500 text-xs">
              <span>No detection events recorded yet</span>
            </div>
          ) : (
            <div className="space-y-2.5 text-xs">
              {Object.entries(categoryCounts).map(([cat, count]) => {
                const pct = totalInteractions > 0 ? Math.round((count / totalInteractions) * 100) : 0;
                let barColor = 'bg-cyan-500';
                if (cat.includes('CREDENTIAL') || cat.includes('Leakage') || cat.includes('High Risk')) barColor = 'bg-rose-500';
                else if (cat.includes('PII') || cat.includes('FINANCIAL') || cat.includes('Suspicious')) barColor = 'bg-amber-500';
                else if (cat.includes('EXPLOIT') || cat.includes('INJECTION')) barColor = 'bg-purple-500';
                else if (cat.includes('None') || cat.includes('BENIGN')) barColor = 'bg-emerald-500';

                return (
                  <div key={cat} className="space-y-1">
                    <div className="flex justify-between items-center text-xs text-slate-300">
                      <span className="truncate">{cat}</span>
                      <span className="text-slate-200 font-semibold font-mono">{count} ({pct}%)</span>
                    </div>
                    <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div className={`h-full ${barColor}`} style={{ width: `${pct}%` }}></div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Recent Security Events Table */}
      <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span>Recent Security Events</span>
          </h3>
          <button
            onClick={onNavigateToEvents}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center space-x-1 cursor-pointer transition-colors"
          >
            <span>View All Events</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {events.length === 0 ? (
          <div className="py-8 text-center text-slate-500 text-xs">
            No security events logged yet. Submit a prompt in the AI Console to view live inspection telemetry.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-xs text-slate-400">
                  <th className="pb-2.5 font-medium">TIMESTAMP</th>
                  <th className="pb-2.5 font-medium">USER</th>
                  <th className="pb-2.5 font-medium">ACTION</th>
                  <th className="pb-2.5 font-medium">RISK</th>
                  <th className="pb-2.5 font-medium">CLASSIFICATION</th>
                  <th className="pb-2.5 font-medium">EXPLANATION</th>
                  <th className="pb-2.5 font-medium text-right">INSPECT</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {events.slice(0, 6).map((evt) => {
                  let actionBadge = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
                  if (evt.action === 'BLOCK') actionBadge = 'bg-rose-500/10 text-rose-400 border-rose-500/30';
                  if (evt.action === 'MODIFIED') actionBadge = 'bg-amber-500/10 text-amber-400 border-amber-500/30';

                  return (
                    <tr key={evt.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 text-slate-400 whitespace-nowrap font-mono text-[11px]">
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-3 text-slate-200 font-medium truncate max-w-[140px]">
                        {evt.user}
                      </td>
                      <td className="py-3">
                        <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${actionBadge}`}>
                          {evt.action === 'MODIFIED' ? 'MASKED' : evt.action}
                        </span>
                      </td>
                      <td className="py-3 font-mono font-bold">
                        <span className={evt.risk_score >= 70 ? 'text-rose-400' : evt.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'}>
                          {evt.risk_score}
                        </span>
                      </td>
                      <td className="py-3 text-slate-300 truncate max-w-[150px]">
                        {evt.attack_type || 'General'}
                      </td>
                      <td className="py-3 text-slate-400 truncate max-w-[280px]">
                        {evt.suggested_safe_prompt || evt.report_summary || 'Approved'}
                      </td>
                      <td className="py-3 text-right">
                        <button
                          onClick={() => onSelectEvent(evt)}
                          className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-300 transition-colors cursor-pointer"
                          title="Inspect Event"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
