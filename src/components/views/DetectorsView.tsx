import React, { useState } from 'react';
import { 
  Shield, 
  Cpu, 
  FileCode, 
  BookOpen, 
  PlusCircle, 
  Trash2, 
  CheckCircle, 
  Sliders,
  AlertTriangle,
  Info,
  ShieldCheck,
  Check,
  X,
  Lock,
  Layers,
  Filter
} from 'lucide-react';
import { EnterpriseRule, DlpPolicy } from '../../../database';
import { PolicyRule, UserRole } from '../../core/types';

interface DetectorsViewProps {
  rules: EnterpriseRule[];
  onAddRule: (rule: Omit<EnterpriseRule, 'id'>) => Promise<void>;
  onDeleteRule: (id: string) => Promise<void>;
  userRole: UserRole;
  // Consolidated Policy & DLP Engine
  policies?: PolicyRule[];
  onTogglePolicy?: (id: string, enabled: boolean) => Promise<void>;
  onAddPolicy?: (policy: PolicyRule) => Promise<void>;
  onDeletePolicy?: (id: string) => Promise<void>;
  dlpPolicy?: DlpPolicy | null;
  onUpdateDlpPolicy?: (updated: DlpPolicy) => Promise<void>;
}

export const DetectorsView: React.FC<DetectorsViewProps> = ({
  rules,
  onAddRule,
  onDeleteRule,
  userRole,
  policies = [],
  onTogglePolicy,
  onAddPolicy,
  onDeletePolicy,
  dlpPolicy,
  onUpdateDlpPolicy
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'policies' | 'dlp' | 'custom' | 'scanners'>('policies');

  // Custom Rule Form State
  const [ruleName, setRuleName] = useState('');
  const [rulePattern, setRulePattern] = useState('');
  const [ruleType, setRuleType] = useState<'keyword' | 'regex'>('keyword');
  const [ruleAction, setRuleAction] = useState<'BLOCK' | 'REDACT'>('BLOCK');
  const [rulePlaceholder, setRulePlaceholder] = useState('');
  const [ruleExplanation, setRuleExplanation] = useState('');
  const [showAddRuleForm, setShowAddRuleForm] = useState(false);

  // Policy Create Modal State
  const [showCreatePolicyModal, setShowCreatePolicyModal] = useState(false);
  const [newPolicyName, setNewPolicyName] = useState('');
  const [newPolicyDesc, setNewPolicyDesc] = useState('');
  const [newPolicyCategory, setNewPolicyCategory] = useState<string>('CREDENTIAL');
  const [newPolicyAction, setNewPolicyAction] = useState<'ALLOW' | 'MASK' | 'BLOCK'>('BLOCK');
  const [newPolicyPriority, setNewPolicyPriority] = useState<number>(50);
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  const handleCustomRuleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ruleName.trim() || !rulePattern.trim() || userRole !== 'ADMIN') return;

    await onAddRule({
      name: ruleName.trim(),
      pattern: rulePattern.trim(),
      type: ruleType,
      action: ruleAction,
      redactPlaceholder: ruleAction === 'REDACT' ? (rulePlaceholder || '[REDACTED_CUSTOM]') : undefined,
      explanation: ruleExplanation.trim() || `Custom ${ruleAction} rule for ${ruleName}`
    });

    setRuleName('');
    setRulePattern('');
    setRulePlaceholder('');
    setRuleExplanation('');
    setShowAddRuleForm(false);
  };

  const handleCreatePolicySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPolicyName.trim() || userRole !== 'ADMIN' || !onAddPolicy) return;

    const newRule: PolicyRule = {
      id: `POL-${Date.now().toString().slice(-4)}`,
      name: newPolicyName.trim(),
      description: newPolicyDesc.trim() || 'Custom administrative security rule.',
      enabled: true,
      priority: newPolicyPriority,
      condition: {
        categories: [newPolicyCategory as any],
        minSeverity: 'MEDIUM'
      },
      action: newPolicyAction,
      explanation: `Custom policy enforced by ${userRole}: ${newPolicyName}`
    };

    await onAddPolicy(newRule);
    setShowCreatePolicyModal(false);
    setNewPolicyName('');
    setNewPolicyDesc('');
  };

  const layeredDetectors = [
    {
      id: 'detector-regex',
      name: 'Deterministic Regex Pattern Detector',
      version: '2.1.0',
      type: 'Deterministic',
      status: 'ACTIVE',
      latency: '< 1ms',
      categories: ['CREDENTIAL', 'PII', 'CONFIDENTIAL_FINANCIAL', 'APPSEC_EXPLOIT'],
      description: 'High-precision regular expressions capturing API keys, private keys, JWTs, database connection URIs, SSNs, credit cards, emails, and code injection exploits.'
    },
    {
      id: 'detector-dictionary',
      name: 'Organization Glossary & Entity Detector',
      version: '1.8.0',
      type: 'Deterministic Dictionary',
      status: 'ACTIVE',
      latency: '< 1ms',
      categories: ['CONFIDENTIAL_TECHNICAL', 'INTERNAL_IDENTIFIER', 'RESTRICTED'],
      description: 'Matches prompts against configured enterprise glossary terms, confidential project codenames (e.g. Orion-Core), and internal server FQDNs.'
    },
    {
      id: 'detector-contextual',
      name: 'Contextual Threat & Injection Detector',
      version: '2.0.0',
      type: 'Deterministic Heuristic',
      status: 'ACTIVE',
      latency: '< 2ms',
      categories: ['PROMPT_INJECTION', 'INSIDER_THREAT', 'APPSEC_EXPLOIT'],
      description: 'Inspects intent for adversarial prompt injections, system guardrail jailbreaks, sabotage/logic bombs, and data hostage extortion attempts.'
    }
  ];

  const filteredPolicies = policies.filter(p => {
    if (categoryFilter === 'ALL') return true;
    return p.condition.categories.includes(categoryFilter as any);
  });

  return (
    <div className="space-y-5 font-sans">
      {/* Top Banner */}
      <div className="p-4 sm:p-5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            <span>Detectors &amp; Policy Governance Engine</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
            Unified perimeter defense combining layered scanning detectors, deterministic policy enforcement rules (ALLOW / MASK / BLOCK), DLP data shields, and custom pattern signatures.
          </p>
        </div>

        {/* Quick Role Badge */}
        <div className="text-[11px] font-mono px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 shrink-0">
          Mode: <span className="text-cyan-400 font-bold">{userRole}</span> ({userRole === 'ADMIN' ? 'Full Control' : 'Enforced'})
        </div>
      </div>

      {/* Sub-Navigation Pill Tabs */}
      <div className="flex items-center space-x-2 border-b border-slate-800 pb-2 overflow-x-auto scrollbar-none">
        <button
          onClick={() => setActiveSubTab('policies')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer shrink-0 ${
            activeSubTab === 'policies'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Sliders className="w-3.5 h-3.5" />
          <span>Policy Rules Engine</span>
          <span className="ml-1 text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 font-mono">
            {policies.length}
          </span>
        </button>

        <button
          onClick={() => setActiveSubTab('dlp')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer shrink-0 ${
            activeSubTab === 'dlp'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>DLP Data Shields</span>
        </button>

        <button
          onClick={() => setActiveSubTab('custom')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer shrink-0 ${
            activeSubTab === 'custom'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <FileCode className="w-3.5 h-3.5" />
          <span>Custom Rules &amp; Regex</span>
          <span className="ml-1 text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 font-mono">
            {rules.length}
          </span>
        </button>

        <button
          onClick={() => setActiveSubTab('scanners')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer shrink-0 ${
            activeSubTab === 'scanners'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Layered Scanners</span>
          <span className="ml-1 text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 font-mono">
            {layeredDetectors.length}
          </span>
        </button>
      </div>

      {/* ------------------------------------------------------------- */}
      {/* TAB 1: POLICY RULES ENGINE                                   */}
      {/* ------------------------------------------------------------- */}
      {activeSubTab === 'policies' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div className="flex items-center space-x-2">
              <Filter className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-xs text-slate-400">Filter Category:</span>
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-200 focus:outline-none"
              >
                <option value="ALL">All Categories</option>
                <option value="CREDENTIAL">Credentials &amp; Secrets</option>
                <option value="PII">Personal Data (PII)</option>
                <option value="PROMPT_INJECTION">Prompt Injections</option>
                <option value="APPSEC_EXPLOIT">AppSec Exploits</option>
                <option value="CONFIDENTIAL_TECHNICAL">Internal Confidential</option>
                <option value="CONFIDENTIAL_FINANCIAL">Financial Records</option>
              </select>
            </div>

            {userRole === 'ADMIN' && (
              <button
                onClick={() => setShowCreatePolicyModal(true)}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs shadow-sm transition-all cursor-pointer"
              >
                <PlusCircle className="w-3.5 h-3.5" />
                <span>CREATE POLICY RULE</span>
              </button>
            )}
          </div>

          {/* Policies Table */}
          <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/70 text-[11px] text-slate-400 uppercase font-mono">
                  <th className="p-3">POLICY RULE</th>
                  <th className="p-3">TARGET CATEGORIES</th>
                  <th className="p-3">ACTION</th>
                  <th className="p-3">PRIORITY</th>
                  <th className="p-3">STATUS</th>
                  {userRole === 'ADMIN' && <th className="p-3 text-right">MANAGE</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredPolicies.map((pol) => {
                  const isBlock = pol.action === 'BLOCK';
                  const isMask = pol.action === 'MASK';

                  return (
                    <tr key={pol.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="p-3">
                        <div className="font-semibold text-slate-100 flex items-center space-x-2">
                          <span>{pol.name}</span>
                          <span className="text-[10px] text-slate-500 font-mono">({pol.id})</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed max-w-md">
                          {pol.description}
                        </p>
                      </td>

                      <td className="p-3">
                        <div className="flex flex-wrap gap-1">
                          {pol.condition.categories.map((c) => (
                            <span key={c} className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">
                              {c}
                            </span>
                          ))}
                        </div>
                      </td>

                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border font-mono ${
                          isBlock
                            ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                            : isMask
                            ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                            : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        }`}>
                          {pol.action}
                        </span>
                      </td>

                      <td className="p-3 font-mono text-slate-300 text-xs">
                        {pol.priority}
                      </td>

                      <td className="p-3">
                        {userRole === 'ADMIN' && onTogglePolicy ? (
                          <button
                            onClick={() => onTogglePolicy(pol.id, !pol.enabled)}
                            className={`px-2.5 py-1 rounded-md text-[11px] font-semibold border transition-all cursor-pointer ${
                              pol.enabled
                                ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800 hover:bg-emerald-900/60'
                                : 'bg-slate-800 text-slate-400 border-slate-700 hover:bg-slate-700'
                            }`}
                          >
                            {pol.enabled ? 'ACTIVE' : 'DISABLED'}
                          </button>
                        ) : (
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            pol.enabled ? 'text-emerald-400 bg-emerald-950/60' : 'text-slate-500 bg-slate-900'
                          }`}>
                            {pol.enabled ? 'ACTIVE' : 'DISABLED'}
                          </span>
                        )}
                      </td>

                      {userRole === 'ADMIN' && (
                        <td className="p-3 text-right">
                          {onDeletePolicy && (
                            <button
                              onClick={() => onDeletePolicy(pol.id)}
                              className="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors cursor-pointer"
                              title="Delete policy"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* TAB 2: DLP DATA PROTECTION SHIELDS                            */}
      {/* ------------------------------------------------------------- */}
      {activeSubTab === 'dlp' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <span>DATA LOSS PREVENTION (DLP) SENSITIVE CATEGORIES</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Real-time perimeter boundary scanning toggles. Active categories are automatically intercepted, redacted, or blocked before reaching third-party LLMs.
                </p>
              </div>

              <span className="text-xs text-slate-400 bg-slate-950 border border-slate-800 px-2.5 py-1 rounded-lg">
                {userRole === 'ADMIN' ? 'Editable (Administrator)' : 'Read-Only Mode'}
              </span>
            </div>

            {dlpPolicy && onUpdateDlpPolicy ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {[
                  { key: 'ssn' as const, label: 'US Social Security Numbers (SSN)', desc: 'Validates 9-digit SSN pattern delimiters' },
                  { key: 'creditCard' as const, label: 'Payment Cards / Credit Cards', desc: 'Luhn-verified Visa, MC, Amex numbers' },
                  { key: 'apiKeys' as const, label: 'API Keys & Secrets', desc: 'AWS, Stripe, OpenAI, Slack token patterns' },
                  { key: 'dbStrings' as const, label: 'Database Connection URIs', desc: 'postgres://, mongodb+srv://, mysql://' },
                  { key: 'medicalPii' as const, label: 'Medical & Healthcare PII', desc: 'HIPAA identifier patterns and health records' },
                  { key: 'appExploits' as const, label: 'AppSec Exploits (SQLi/XSS)', desc: 'Command injection, path traversal, script tags' },
                  { key: 'internalCodenames' as const, label: 'Confidential Codenames', desc: 'Project Orion, Hyperion, Apollo specs' },
                  { key: 'promptInjections' as const, label: 'Adversarial Prompt Injections', desc: 'Jailbreaks, system prompt extractions' },
                ].map((item) => {
                  const isChecked = !!dlpPolicy[item.key];
                  return (
                    <label
                      key={item.key}
                      className={`flex flex-col justify-between p-3.5 rounded-xl border transition-all cursor-pointer ${
                        isChecked
                          ? 'bg-cyan-950/30 border-cyan-500/40 text-slate-200 shadow-sm'
                          : 'bg-slate-950/60 border-slate-800/80 text-slate-400 opacity-60'
                      }`}
                    >
                      <div>
                        <div className="flex items-center justify-between mb-1.5">
                          <span className="font-semibold text-xs text-slate-100">{item.label}</span>
                          <input
                            type="checkbox"
                            checked={isChecked}
                            disabled={userRole !== 'ADMIN'}
                            onChange={(e) => {
                              onUpdateDlpPolicy({
                                ...dlpPolicy,
                                [item.key]: e.target.checked
                              });
                            }}
                            className="rounded border-slate-700 text-cyan-500 focus:ring-0 cursor-pointer"
                          />
                        </div>
                        <p className="text-[11px] text-slate-400 leading-relaxed">{item.desc}</p>
                      </div>

                      <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center space-x-1.5">
                        <span className={`w-2 h-2 rounded-full ${isChecked ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                        <span className="text-[10px] font-mono text-slate-400">
                          {isChecked ? 'ENFORCED (FAIL-CLOSED)' : 'BYPASS / DISABLED'}
                        </span>
                      </div>
                    </label>
                  );
                })}
              </div>
            ) : (
              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-slate-400 text-xs">
                DLP policy definitions are currently operating under default gateway security settings.
              </div>
            )}
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* TAB 3: CUSTOM RULES & REGEX PATTERNS                         */}
      {/* ------------------------------------------------------------- */}
      {activeSubTab === 'custom' && (
        <div className="space-y-4 font-mono text-xs">
          <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                  <FileCode className="w-4 h-4 text-cyan-400" />
                  <span>CUSTOM ORGANIZATION SECURITY RULES</span>
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Dynamic keyword substrings and regular expression signatures applied during real-time prompt ingestion.
                </p>
              </div>

              {userRole === 'ADMIN' && (
                <button
                  onClick={() => setShowAddRuleForm(!showAddRuleForm)}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs shadow-sm transition-all cursor-pointer shrink-0"
                >
                  <PlusCircle className="w-3.5 h-3.5" />
                  <span>{showAddRuleForm ? 'CANCEL' : 'ADD CUSTOM RULE'}</span>
                </button>
              )}
            </div>

            {/* Add Custom Rule Form */}
            {showAddRuleForm && userRole === 'ADMIN' && (
              <form onSubmit={handleCustomRuleSubmit} className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
                <h4 className="font-bold text-slate-200 text-xs">Define Custom Enterprise Rule</h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="text-[10px] text-slate-400 block mb-1">Rule Name</label>
                    <input
                      type="text"
                      required
                      value={ruleName}
                      onChange={(e) => setRuleName(e.target.value)}
                      placeholder="e.g. Project Orion Codename"
                      className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] text-slate-400 block mb-1">Matching Pattern</label>
                    <input
                      type="text"
                      required
                      value={rulePattern}
                      onChange={(e) => setRulePattern(e.target.value)}
                      placeholder="e.g. Orion-Core or dev-cluster\\.internal"
                      className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] text-slate-400 block mb-1">Matcher Type</label>
                    <select
                      value={ruleType}
                      onChange={(e) => setRuleType(e.target.value as any)}
                      className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none"
                    >
                      <option value="keyword">Exact Keyword Substring</option>
                      <option value="regex">Regular Expression</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[10px] text-slate-400 block mb-1">Enforcement Action</label>
                    <select
                      value={ruleAction}
                      onChange={(e) => setRuleAction(e.target.value as any)}
                      className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none"
                    >
                      <option value="BLOCK">BLOCK Prompt</option>
                      <option value="REDACT">REDACT / MASK Match</option>
                    </select>
                  </div>

                  {ruleAction === 'REDACT' && (
                    <div>
                      <label className="text-[10px] text-slate-400 block mb-1">Redaction Placeholder</label>
                      <input
                        type="text"
                        value={rulePlaceholder}
                        onChange={(e) => setRulePlaceholder(e.target.value)}
                        placeholder="[REDACTED_CODENAME]"
                        className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none"
                      />
                    </div>
                  )}

                  <div className={ruleAction === 'REDACT' ? '' : 'sm:col-span-2'}>
                    <label className="text-[10px] text-slate-400 block mb-1">Explanation / Impact</label>
                    <input
                      type="text"
                      value={ruleExplanation}
                      onChange={(e) => setRuleExplanation(e.target.value)}
                      placeholder="Protects confidential internal codename from leaking..."
                      className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none"
                    />
                  </div>
                </div>

                <div className="flex justify-end pt-2">
                  <button
                    type="submit"
                    className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold cursor-pointer"
                  >
                    Commit Rule to Gateway
                  </button>
                </div>
              </form>
            )}

            {/* Custom Rules Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-slate-800 text-[11px] text-slate-400">
                    <th className="pb-2 font-medium">RULE NAME</th>
                    <th className="pb-2 font-medium">PATTERN</th>
                    <th className="pb-2 font-medium">TYPE</th>
                    <th className="pb-2 font-medium">ACTION</th>
                    <th className="pb-2 font-medium">EXPLANATION</th>
                    {userRole === 'ADMIN' && <th className="pb-2 font-medium text-right">MANAGE</th>}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {rules.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-6 text-center text-slate-500">
                        No custom rules registered. Standard layered detectors remain active.
                      </td>
                    </tr>
                  ) : (
                    rules.map((rule) => (
                      <tr key={rule.id} className="hover:bg-slate-800/40">
                        <td className="py-2.5 font-bold text-slate-200">{rule.name}</td>
                        <td className="py-2.5 text-cyan-300 font-mono text-[11px]">{rule.pattern}</td>
                        <td className="py-2.5 text-slate-400 uppercase text-[10px]">{rule.type}</td>
                        <td className="py-2.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            rule.action === 'BLOCK'
                              ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                              : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          }`}>
                            {rule.action}
                          </span>
                        </td>
                        <td className="py-2.5 text-slate-400 text-[11px] max-w-[260px] truncate">{rule.explanation}</td>
                        {userRole === 'ADMIN' && (
                          <td className="py-2.5 text-right">
                            <button
                              onClick={() => onDeleteRule(rule.id)}
                              className="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors cursor-pointer"
                              title="Delete Rule"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </td>
                        )}
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* TAB 4: LAYERED SCANNERS ARCHITECTURE                          */}
      {/* ------------------------------------------------------------- */}
      {activeSubTab === 'scanners' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
            {layeredDetectors.map((det) => (
              <div key={det.id} className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 flex flex-col justify-between space-y-3">
                <div>
                  <div className="flex justify-between items-start">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950/60 border border-cyan-800/40 text-cyan-300">
                      {det.type}
                    </span>
                    <span className="text-[10px] text-emerald-400 font-semibold flex items-center space-x-1">
                      <CheckCircle className="w-3 h-3" />
                      <span>{det.status}</span>
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-slate-100 mt-2">{det.name}</h3>
                  <div className="text-[10px] text-slate-500 mt-0.5 font-mono">
                    Version: {det.version} &middot; Latency: {det.latency}
                  </div>
                  <p className="text-[11px] text-slate-400 mt-2 leading-relaxed font-sans">{det.description}</p>
                </div>

                <div className="pt-2 border-t border-slate-800/80">
                  <span className="text-[10px] text-slate-500 block mb-1">Coverage Scope:</span>
                  <div className="flex flex-wrap gap-1">
                    {det.categories.map((c) => (
                      <span key={c} className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[9px]">
                        {c}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Create Policy Modal */}
      {showCreatePolicyModal && userRole === 'ADMIN' && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 text-xs space-y-4 shadow-2xl">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                <span>CREATE NEW POLICY RULE</span>
              </h3>
              <button
                onClick={() => setShowCreatePolicyModal(false)}
                className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreatePolicySubmit} className="space-y-3">
              <div>
                <label className="text-[11px] font-semibold text-slate-300 block mb-1">Policy Name</label>
                <input
                  type="text"
                  required
                  value={newPolicyName}
                  onChange={(e) => setNewPolicyName(e.target.value)}
                  placeholder="e.g. Block Critical Private Keys"
                  className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <div>
                <label className="text-[11px] font-semibold text-slate-300 block mb-1">Description / Rationale</label>
                <textarea
                  rows={2}
                  value={newPolicyDesc}
                  onChange={(e) => setNewPolicyDesc(e.target.value)}
                  placeholder="Explains why this policy rule is enforced..."
                  className="w-full p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-semibold text-slate-300 block mb-1">Target Category</label>
                  <select
                    value={newPolicyCategory}
                    onChange={(e) => setNewPolicyCategory(e.target.value)}
                    className="w-full p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none"
                  >
                    <option value="CREDENTIAL">CREDENTIAL</option>
                    <option value="PII">PII</option>
                    <option value="PROMPT_INJECTION">PROMPT_INJECTION</option>
                    <option value="APPSEC_EXPLOIT">APPSEC_EXPLOIT</option>
                    <option value="CONFIDENTIAL_TECHNICAL">CONFIDENTIAL_TECHNICAL</option>
                    <option value="CONFIDENTIAL_FINANCIAL">CONFIDENTIAL_FINANCIAL</option>
                  </select>
                </div>

                <div>
                  <label className="text-[11px] font-semibold text-slate-300 block mb-1">Enforcement Action</label>
                  <select
                    value={newPolicyAction}
                    onChange={(e) => setNewPolicyAction(e.target.value as any)}
                    className="w-full p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none"
                  >
                    <option value="BLOCK">BLOCK</option>
                    <option value="MASK">MASK</option>
                    <option value="ALLOW">ALLOW</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-[11px] font-semibold text-slate-300 block mb-1">Priority (1 - 100)</label>
                <input
                  type="number"
                  min={1}
                  max={100}
                  value={newPolicyPriority}
                  onChange={(e) => setNewPolicyPriority(parseInt(e.target.value, 10) || 50)}
                  className="w-full p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreatePolicyModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold cursor-pointer"
                >
                  Create Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
