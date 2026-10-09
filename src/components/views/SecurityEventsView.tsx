import React, { useState } from 'react';
import { 
  Search, 
  Filter, 
  Eye, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Clock, 
  Server, 
  X, 
  Hash, 
  User, 
  CheckCircle, 
  XCircle,
  Download,
  Check,
  RotateCcw
} from 'lucide-react';
import { LogEvent } from '../../../database';
import { UserRole } from '../../core/types';

interface SecurityEventsViewProps {
  events: LogEvent[];
  selectedEvent: LogEvent | null;
  onSelectEvent: (event: LogEvent | null) => void;
  onExportEvents?: () => void;
  userRole?: UserRole;
  onOverrideEvent?: (logId: string, overrideReason: string, overrideText?: string) => Promise<void>;
}

export const SecurityEventsView: React.FC<SecurityEventsViewProps> = ({
  events,
  selectedEvent,
  onSelectEvent,
  onExportEvents,
  userRole,
  onOverrideEvent
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterAction, setFilterAction] = useState<string>('ALL');
  const [filterRisk, setFilterRisk] = useState<string>('ALL');
  const [overrideReasonInput, setOverrideReasonInput] = useState('');
  const [overrideTextInput, setOverrideTextInput] = useState('');
  const [isSubmittingOverride, setIsSubmittingOverride] = useState(false);

  const filteredEvents = events.filter(e => {
    if (filterAction !== 'ALL' && e.action !== filterAction) return false;
    if (filterRisk === 'HIGH' && e.risk_score < 70) return false;
    if (filterRisk === 'MEDIUM' && (e.risk_score < 30 || e.risk_score >= 70)) return false;
    if (filterRisk === 'LOW' && e.risk_score >= 30) return false;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchUser = e.user.toLowerCase().includes(q);
      const matchThreat = (e.attack_type || '').toLowerCase().includes(q);
      const matchReason = (e.reasons || []).some(r => r.toLowerCase().includes(q));
      const matchId = e.id.toLowerCase().includes(q);
      return matchUser || matchThreat || matchReason || matchId;
    }

    return true;
  });

  return (
    <div className="space-y-4">
      {/* Search & Filter Header Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 font-mono text-xs">
        <div className="flex-1 flex items-center space-x-2 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 focus-within:border-cyan-500/50">
          <Search className="w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by event ID, user identity, threat category, or policy reason..."
            className="w-full bg-transparent text-slate-200 placeholder-slate-500 focus:outline-none"
          />
          {searchQuery && (
            <button onClick={() => setSearchQuery('')} className="text-slate-500 hover:text-slate-300">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <div className="flex items-center space-x-2">
          {/* Action Filter */}
          <select
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            className="bg-slate-950 text-slate-200 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none cursor-pointer"
          >
            <option value="ALL">Action: All</option>
            <option value="ALLOW">Action: ALLOW</option>
            <option value="MODIFIED">Action: MASKED</option>
            <option value="BLOCK">Action: BLOCKED</option>
          </select>

          {/* Risk Level Filter */}
          <select
            value={filterRisk}
            onChange={(e) => setFilterRisk(e.target.value)}
            className="bg-slate-950 text-slate-200 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none cursor-pointer"
          >
            <option value="ALL">Risk: All</option>
            <option value="HIGH">Risk: High (&ge;70)</option>
            <option value="MEDIUM">Risk: Medium (30-69)</option>
            <option value="LOW">Risk: Low (&lt;30)</option>
          </select>

          {onExportEvents && (
            <button
              onClick={onExportEvents}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-slate-100 transition-colors cursor-pointer"
              title="Export DSAR Audit Logs"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden md:inline">Export</span>
            </button>
          )}
        </div>
      </div>

      {/* Events Table Container */}
      <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
        <div className="flex justify-between items-center mb-3 font-mono text-xs">
          <span className="text-slate-400">
            Showing <span className="text-slate-200 font-bold">{filteredEvents.length}</span> of {events.length} audit events
          </span>
          <span className="text-[10px] text-slate-500">Raw secrets excluded per security policy</span>
        </div>

        {filteredEvents.length === 0 ? (
          <div className="py-12 text-center text-slate-500 font-mono text-xs">
            No matching security events found.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] text-slate-400">
                  <th className="pb-2.5 font-medium">TIMESTAMP</th>
                  <th className="pb-2.5 font-medium">USER IDENTIFIER</th>
                  <th className="pb-2.5 font-medium">ACTION</th>
                  <th className="pb-2.5 font-medium">RISK SCORE</th>
                  <th className="pb-2.5 font-medium">CATEGORY</th>
                  <th className="pb-2.5 font-medium">AI PROVIDER</th>
                  <th className="pb-2.5 font-medium">LATENCY</th>
                  <th className="pb-2.5 font-medium text-right">DETAILS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredEvents.map((evt) => {
                  let badge = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
                  if (evt.action === 'BLOCK') badge = 'bg-rose-500/10 text-rose-400 border-rose-500/30';
                  if (evt.action === 'MODIFIED') badge = 'bg-amber-500/10 text-amber-400 border-amber-500/30';

                  const isSelected = selectedEvent?.id === evt.id;

                  return (
                    <tr
                      key={evt.id}
                      onClick={() => onSelectEvent(evt)}
                      className={`hover:bg-slate-800/50 cursor-pointer transition-colors ${
                        isSelected ? 'bg-cyan-950/30 border-l-2 border-cyan-400' : ''
                      }`}
                    >
                      <td className="py-2.5 text-slate-400 whitespace-nowrap text-[11px]">
                        {new Date(evt.timestamp).toLocaleString()}
                      </td>
                      <td className="py-2.5 text-slate-200 font-medium truncate max-w-[140px]">
                        {evt.user}
                      </td>
                      <td className="py-2.5">
                        <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${badge}`}>
                          {evt.action === 'MODIFIED' ? 'MASKED' : evt.action}
                        </span>
                      </td>
                      <td className="py-2.5">
                        <span className={`font-bold ${
                          evt.risk_score >= 70 ? 'text-rose-400' :
                          evt.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {evt.risk_score}
                        </span>
                      </td>
                      <td className="py-2.5 text-slate-300 truncate max-w-[150px]">
                        {evt.attack_type || 'General Traffic'}
                      </td>
                      <td className="py-2.5 text-slate-400 truncate max-w-[120px]">
                        {evt.provider_id || 'Safe Mock'}
                      </td>
                      <td className="py-2.5 text-slate-400">
                        {evt.latency_ms ? `${evt.latency_ms}ms` : '--'}
                      </td>
                      <td className="py-2.5 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectEvent(evt);
                          }}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-300 text-[11px]"
                        >
                          Inspect
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

      {/* Detailed Investigation Modal / Drawer (Section 24 & 25) */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6 font-mono text-xs space-y-4 shadow-2xl">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <span>SECURITY EVENT INVESTIGATION: {selectedEvent.id}</span>
                </h3>
                <span className="text-[10px] text-slate-400">
                  {new Date(selectedEvent.timestamp).toUTCString()}
                </span>
              </div>
              <button
                onClick={() => onSelectEvent(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Decision Summary Card */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <div>
                <div className="text-[10px] text-slate-500 uppercase">Policy Decision</div>
                <div className={`font-bold mt-0.5 text-sm ${
                  selectedEvent.action === 'ALLOW' ? 'text-emerald-400' :
                  selectedEvent.action === 'MODIFIED' ? 'text-amber-400' : 'text-rose-400'
                }`}>
                  {selectedEvent.action === 'MODIFIED' ? 'MASKED' : selectedEvent.action}
                </div>
              </div>
              <div>
                <div className="text-[10px] text-slate-500 uppercase">Risk Score</div>
                <div className="font-bold text-slate-200 mt-0.5 text-sm">{selectedEvent.risk_score} / 100</div>
              </div>
              <div>
                <div className="text-[10px] text-slate-500 uppercase">Alert Status</div>
                <div className={`font-bold mt-0.5 text-sm ${
                  selectedEvent.alert_status === 'TRIGGERED' ? 'text-rose-400' : 'text-slate-400'
                }`}>
                  {selectedEvent.alert_status}
                </div>
              </div>
              <div>
                <div className="text-[10px] text-slate-500 uppercase">AI Provider</div>
                <div className="text-slate-200 mt-0.5 text-xs truncate">{selectedEvent.provider_id || 'Safe Mock'}</div>
              </div>
            </div>

            {/* Request Cryptographic Integrity & Sanitization */}
            <div className="space-y-2">
              <div className="flex items-center space-x-2 text-[11px] font-semibold text-slate-300">
                <Hash className="w-3.5 h-3.5 text-cyan-400" />
                <span>SHA-256 Request Hash (Integrity Verification):</span>
              </div>
              <div className="p-2 rounded bg-slate-950 border border-slate-800 text-[10px] text-cyan-300 break-all">
                {selectedEvent.prompt_hash || 'SHA-256 computed on perimeter ingestion'}
              </div>
            </div>

            {/* Sanitized Outbound Payload */}
            <div className="space-y-1.5">
              <span className="text-[11px] font-semibold text-slate-300">
                Sanitized Request Representation:
              </span>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 break-words max-h-36 overflow-y-auto">
                {selectedEvent.rewritten_prompt || selectedEvent.original_prompt}
              </div>
              <div className="text-[10px] text-slate-500 italic">
                * Note: Plaintext confidential credentials or PII are scrubbed and never stored raw.
              </div>
            </div>

            {/* Decision Explainability (Section 25) */}
            <div className="space-y-2 p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <span className="text-[11px] font-bold text-cyan-400 uppercase tracking-wide">
                Decision Explainability Chain:
              </span>
              <div className="text-slate-200 text-xs">
                {selectedEvent.report_summary || selectedEvent.suggested_safe_prompt}
              </div>
              {selectedEvent.reasons && selectedEvent.reasons.length > 0 && (
                <div className="mt-2 space-y-1">
                  <div className="text-[10px] text-slate-400">Triggered Findings:</div>
                  {selectedEvent.reasons.map((r, i) => (
                    <div key={i} className="text-slate-300 text-[11px] pl-2 border-l border-cyan-500/40">
                      {r}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* SOC Incident Override Section */}
            {selectedEvent.override_status === 'OVERRIDDEN' ? (
              <div className="p-3.5 rounded-xl bg-amber-950/40 border border-amber-800/60 space-y-1.5">
                <div className="flex items-center space-x-2 text-amber-300 font-bold text-xs">
                  <RotateCcw className="w-4 h-4 text-amber-400" />
                  <span>INCIDENT STATUS: APPROVED VIA SOC OVERRIDE</span>
                </div>
                <div className="text-slate-300 text-[11px]">
                  Reason: <span className="text-amber-200">{selectedEvent.override_reason || 'Verified as approved business exception'}</span>
                </div>
                {selectedEvent.override_timestamp && (
                  <div className="text-slate-500 text-[10px]">
                    Overridden at: {new Date(selectedEvent.override_timestamp).toLocaleString()}
                  </div>
                )}
              </div>
            ) : userRole === 'ADMIN' && onOverrideEvent && selectedEvent.action === 'BLOCK' ? (
              <div className="p-3.5 rounded-xl bg-slate-950 border border-amber-500/40 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-amber-400 uppercase tracking-wide flex items-center space-x-1.5">
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>ADMINISTRATIVE SOC OVERRIDE (FALSE POSITIVE REMEDIATION)</span>
                  </span>
                  <span className="text-[10px] text-slate-500">Admin privilege verified</span>
                </div>

                <div className="space-y-2">
                  <input
                    type="text"
                    value={overrideReasonInput}
                    onChange={(e) => setOverrideReasonInput(e.target.value)}
                    placeholder="Enter official SOC justification (e.g. Authorized security drill or approved business exception)..."
                    className="w-full p-2.5 rounded bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-amber-400/50"
                  />
                  <input
                    type="text"
                    value={overrideTextInput}
                    onChange={(e) => setOverrideTextInput(e.target.value)}
                    placeholder="Optional sanitized / rewritten prompt override text..."
                    className="w-full p-2.5 rounded bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-amber-400/50"
                  />
                  <div className="flex justify-end">
                    <button
                      disabled={!overrideReasonInput.trim() || isSubmittingOverride}
                      onClick={async () => {
                        setIsSubmittingOverride(true);
                        try {
                          await onOverrideEvent(selectedEvent.id, overrideReasonInput.trim(), overrideTextInput.trim());
                          setOverrideReasonInput('');
                          setOverrideTextInput('');
                        } finally {
                          setIsSubmittingOverride(false);
                        }
                      }}
                      className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 disabled:opacity-40 text-slate-950 font-bold text-xs transition-colors cursor-pointer"
                    >
                      <Check className="w-3.5 h-3.5" />
                      <span>{isSubmittingOverride ? 'SAVING OVERRIDE...' : 'CONFIRM SOC OVERRIDE'}</span>
                    </button>
                  </div>
                </div>
              </div>
            ) : null}

            {/* Footer */}
            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => onSelectEvent(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold cursor-pointer transition-colors"
              >
                Close Investigation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
