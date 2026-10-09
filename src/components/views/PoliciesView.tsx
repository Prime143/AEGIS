import React, { useState } from 'react';
import { 
  ShieldCheck, 
  PlusCircle, 
  Trash2, 
  Edit3, 
  Check, 
  X, 
  Sliders, 
  Lock, 
  AlertTriangle,
  Info
} from 'lucide-react';
import { PolicyRule, UserRole } from '../../core/types';
import { DlpPolicy } from '../../../database';

interface PoliciesViewProps {
  policies: PolicyRule[];
  onTogglePolicy: (id: string, enabled: boolean) => Promise<void>;
  onAddPolicy: (policy: PolicyRule) => Promise<void>;
  onDeletePolicy: (id: string) => Promise<void>;
  userRole: UserRole;
  dlpPolicy?: DlpPolicy | null;
  onUpdateDlpPolicy?: (updated: DlpPolicy) => Promise<void>;
}

export const PoliciesView: React.FC<PoliciesViewProps> = ({
  policies,
  onTogglePolicy,
  onAddPolicy,
  onDeletePolicy,
  userRole,
  dlpPolicy,
  onUpdateDlpPolicy
}) => {
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newCategory, setNewCategory] = useState<string>('CREDENTIAL');
  const [newAction, setNewAction] = useState<'ALLOW' | 'MASK' | 'BLOCK'>('BLOCK');
  const [newPriority, setNewPriority] = useState<number>(50);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim() || userRole !== 'ADMIN') return;

    const newRule: PolicyRule = {
      id: `POL-${Date.now().toString().slice(-4)}`,
      name: newName.trim(),
      description: newDesc.trim() || 'Custom administrative security rule.',
      enabled: true,
      priority: newPriority,
      condition: {
        categories: [newCategory as any],
        minSeverity: 'MEDIUM'
      },
      action: newAction,
      explanation: `Custom policy enforced by ${userRole}: ${newName}`
    };

    await onAddPolicy(newRule);
    setShowCreateModal(false);
    setNewName('');
    setNewDesc('');
  };

  return (
    <div className="space-y-4 font-sans">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <span>
              {userRole === 'USER' ? 'Acceptable Use & Security Policies' : 'Centralized Policy Governance Engine'}
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            {userRole === 'USER'
              ? 'Active security rules governing AI interactions across the organization. Requests violating these rules are sanitized or blocked.'
              : 'Deterministic rule definitions evaluated against employee prompts and AI provider responses.'}
          </p>
        </div>

        {userRole === 'ADMIN' ? (
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs shadow-sm transition-all cursor-pointer shrink-0"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            <span>CREATE POLICY</span>
          </button>
        ) : (
          <div className="text-xs text-slate-400 bg-slate-950 border border-slate-800 px-2.5 py-1 rounded-lg">
            Read-only mode ({userRole === 'SECURITY_ANALYST' ? 'Security Analyst' : 'Employee'})
          </div>
        )}
      </div>

      {/* DLP Shield Policy Controls */}
      {dlpPolicy && onUpdateDlpPolicy && (
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3 text-xs">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <span className="font-bold text-slate-100 text-xs tracking-wide">Data Loss Prevention (DLP) Categories</span>
            </div>
            <span className="text-[11px] text-slate-400">
              {userRole === 'ADMIN' ? 'Real-time gateway enforcement toggles' : 'Active gateway protection status'}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2.5">
            {[
              { key: 'ssn' as const, label: 'US Social Security Numbers (SSN)' },
              { key: 'creditCard' as const, label: 'Payment Card / Credit Cards' },
              { key: 'apiKeys' as const, label: 'API Keys & Access Tokens' },
              { key: 'dbStrings' as const, label: 'Database Connection URIs' },
              { key: 'medicalPii' as const, label: 'Medical & Healthcare PII' },
              { key: 'appExploits' as const, label: 'AppSec Exploits (SQLi/XSS/RCE)' },
              { key: 'promptInjections' as const, label: 'Adversarial Prompt Injections' }
            ].map(({ key, label }) => {
              const item = dlpPolicy[key];
              if (!item) return null;

              return (
                <div key={key} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 flex flex-col justify-between space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-slate-300 font-semibold truncate pr-1">{label}</span>
                    <button
                      disabled={userRole !== 'ADMIN'}
                      onClick={() => {
                        onUpdateDlpPolicy({
                          ...dlpPolicy,
                          [key]: { ...item, enabled: !item.enabled }
                        });
                      }}
                      className={`px-1.5 py-0.5 rounded text-[9px] font-bold border transition-colors ${
                        userRole !== 'ADMIN' ? 'opacity-60 cursor-default' : 'cursor-pointer'
                      } ${
                        item.enabled
                          ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                          : 'bg-slate-900 text-slate-500 border-slate-800'
                      }`}
                    >
                      {item.enabled ? 'ENABLED' : 'OFF'}
                    </button>
                  </div>

                  <div className="flex items-center justify-between text-[10px] pt-1 border-t border-slate-900">
                    <span className="text-slate-500">Action:</span>
                    <button
                      disabled={userRole !== 'ADMIN'}
                      onClick={() => {
                        onUpdateDlpPolicy({
                          ...dlpPolicy,
                          [key]: { ...item, action: item.action === 'BLOCK' ? 'REDACT' : 'BLOCK' }
                        });
                      }}
                      className={`px-1.5 py-0.5 rounded text-[9px] font-bold border transition-colors ${
                        userRole !== 'ADMIN' ? 'opacity-60 cursor-default' : 'cursor-pointer'
                      } ${
                        item.action === 'BLOCK'
                          ? 'bg-rose-950/70 text-rose-300 border-rose-800/70'
                          : 'bg-amber-950/70 text-amber-300 border-amber-800/70'
                      }`}
                    >
                      {item.action === 'BLOCK' ? 'BLOCK' : 'MASK (REDACT)'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Policies Table */}
      <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
        <div className="overflow-x-auto text-xs">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400">
                <th className="pb-2.5 font-medium">POLICY ID</th>
                <th className="pb-2.5 font-medium">NAME &amp; SCOPE</th>
                <th className="pb-2.5 font-medium">CATEGORY</th>
                <th className="pb-2.5 font-medium">ACTION</th>
                <th className="pb-2.5 font-medium">PRIORITY</th>
                <th className="pb-2.5 font-medium">STATUS</th>
                {userRole === 'ADMIN' && <th className="pb-2.5 font-medium text-right">MANAGE</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {policies.map((policy) => {
                let actionBadge = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
                if (policy.action === 'BLOCK') actionBadge = 'bg-rose-500/10 text-rose-400 border-rose-500/30';
                if (policy.action === 'MASK') actionBadge = 'bg-amber-500/10 text-amber-400 border-amber-500/30';

                return (
                  <tr key={policy.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 text-cyan-400 font-semibold">{policy.id}</td>
                    <td className="py-3 max-w-[280px]">
                      <div className="text-slate-200 font-bold">{policy.name}</div>
                      <div className="text-[11px] text-slate-400 truncate">{policy.description}</div>
                    </td>
                    <td className="py-3 text-slate-300">
                      {policy.condition.categories?.join(', ') || 'Any'}
                    </td>
                    <td className="py-3">
                      <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${actionBadge}`}>
                        {policy.action}
                      </span>
                    </td>
                    <td className="py-3 text-slate-400">
                      P{policy.priority}
                    </td>
                    <td className="py-3">
                      <button
                        disabled={userRole !== 'ADMIN'}
                        onClick={() => onTogglePolicy(policy.id, !policy.enabled)}
                        className={`px-2.5 py-1 rounded text-[10px] font-bold border transition-colors ${
                          userRole !== 'ADMIN' ? 'cursor-default' : 'cursor-pointer'
                        } ${
                          policy.enabled
                            ? 'bg-emerald-950/60 border-emerald-700/60 text-emerald-300'
                            : 'bg-slate-900 border-slate-800 text-slate-500'
                        }`}
                      >
                        {policy.enabled ? 'ACTIVE' : 'DISABLED'}
                      </button>
                    </td>
                    {userRole === 'ADMIN' && (
                      <td className="py-3 text-right">
                        <button
                          onClick={() => onDeletePolicy(policy.id)}
                          className="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors cursor-pointer"
                          title="Delete Policy"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Policy Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <form onSubmit={handleCreate} className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 font-mono text-xs space-y-4 shadow-2xl">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                <span>CREATE GOVERNANCE POLICY</span>
              </h3>
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-[11px] text-slate-400 block mb-1">Policy Name</label>
                <input
                  type="text"
                  required
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="e.g. Block Financial Spreadsheets"
                  className="w-full p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <div>
                <label className="text-[11px] text-slate-400 block mb-1">Description / Rationale</label>
                <input
                  type="text"
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Reason for rule..."
                  className="w-full p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] text-slate-400 block mb-1">Target Category</label>
                  <select
                    value={newCategory}
                    onChange={(e) => setNewCategory(e.target.value)}
                    className="w-full p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none cursor-pointer"
                  >
                    <option value="CREDENTIAL">CREDENTIAL</option>
                    <option value="PII">PII</option>
                    <option value="CONFIDENTIAL_FINANCIAL">CONFIDENTIAL_FINANCIAL</option>
                    <option value="CONFIDENTIAL_TECHNICAL">CONFIDENTIAL_TECHNICAL</option>
                    <option value="APPSEC_EXPLOIT">APPSEC_EXPLOIT</option>
                    <option value="PROMPT_INJECTION">PROMPT_INJECTION</option>
                    <option value="INSIDER_THREAT">INSIDER_THREAT</option>
                  </select>
                </div>

                <div>
                  <label className="text-[11px] text-slate-400 block mb-1">Enforcement Action</label>
                  <select
                    value={newAction}
                    onChange={(e) => setNewAction(e.target.value as any)}
                    className="w-full p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none cursor-pointer"
                  >
                    <option value="BLOCK">BLOCK</option>
                    <option value="MASK">MASK</option>
                    <option value="ALLOW">ALLOW</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-[11px] text-slate-400 block mb-1">Priority (Ascending precedence)</label>
                <input
                  type="number"
                  min="1"
                  max="100"
                  value={newPriority}
                  onChange={(e) => setNewPriority(parseInt(e.target.value, 10))}
                  className="w-full p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none"
                />
              </div>
            </div>

            <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold"
              >
                Save Policy
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
