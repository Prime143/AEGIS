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
  Info
} from 'lucide-react';
import { EnterpriseRule } from '../../../database';
import { UserRole } from '../../core/types';

interface DetectorsViewProps {
  rules: EnterpriseRule[];
  onAddRule: (rule: Omit<EnterpriseRule, 'id'>) => Promise<void>;
  onDeleteRule: (id: string) => Promise<void>;
  userRole: UserRole;
}

export const DetectorsView: React.FC<DetectorsViewProps> = ({
  rules,
  onAddRule,
  onDeleteRule,
  userRole
}) => {
  const [name, setName] = useState('');
  const [pattern, setPattern] = useState('');
  const [type, setType] = useState<'keyword' | 'regex'>('keyword');
  const [action, setAction] = useState<'BLOCK' | 'REDACT'>('BLOCK');
  const [placeholder, setPlaceholder] = useState('');
  const [explanation, setExplanation] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !pattern.trim() || userRole !== 'ADMIN') return;

    await onAddRule({
      name: name.trim(),
      pattern: pattern.trim(),
      type,
      action,
      redactPlaceholder: action === 'REDACT' ? (placeholder || '[REDACTED_CUSTOM]') : undefined,
      explanation: explanation.trim() || `Custom ${action} rule for ${name}`
    });

    setName('');
    setPattern('');
    setPlaceholder('');
    setExplanation('');
    setShowAddForm(false);
  };

  const layeredDetectors = [
    {
      id: 'detector-regex',
      name: 'Deterministic Regex Pattern Detector',
      version: '2.1.0',
      type: 'Deterministic',
      status: 'ACTIVE',
      categories: ['CREDENTIAL', 'PII', 'CONFIDENTIAL_FINANCIAL', 'APPSEC_EXPLOIT'],
      description: 'High-precision regular expressions capturing API keys, private keys, JWTs, database connection URIs, SSNs, credit cards, emails, and code injection exploits.'
    },
    {
      id: 'detector-dictionary',
      name: 'Organization Glossary & Entity Detector',
      version: '1.8.0',
      type: 'Deterministic Dictionary',
      status: 'ACTIVE',
      categories: ['CONFIDENTIAL_TECHNICAL', 'INTERNAL_IDENTIFIER', 'RESTRICTED'],
      description: 'Matches prompts against configured enterprise glossary terms, confidential project codenames (e.g. Orion-Core), and internal server FQDNs.'
    },
    {
      id: 'detector-contextual',
      name: 'Contextual Threat & Injection Detector',
      version: '2.0.0',
      type: 'Deterministic Heuristic',
      status: 'ACTIVE',
      categories: ['PROMPT_INJECTION', 'INSIDER_THREAT', 'APPSEC_EXPLOIT'],
      description: 'Inspects intent for adversarial prompt injections, system guardrail jailbreaks, sabotage/logic bombs, and data hostage extortion attempts.'
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
        <h2 className="text-base font-bold text-slate-100 font-mono flex items-center space-x-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span>LAYERED DETECTION ENGINE ARCHITECTURE</span>
        </h2>
        <p className="text-xs text-slate-400 font-mono mt-0.5">
          Multi-stage perimeter inspection pipeline. Modular detectors execute in parallel, resolving overlapping spans by confidence and severity.
        </p>
      </div>

      {/* Layered Detectors Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {layeredDetectors.map((det) => (
          <div key={det.id} className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 flex flex-col justify-between font-mono text-xs space-y-3">
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
              <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{det.description}</p>
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

      {/* Custom Organization Rules Management */}
      <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 font-mono text-xs space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <BookOpen className="w-4 h-4 text-cyan-400" />
              <span>CUSTOM ORGANIZATION SECURITY RULES</span>
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Organization-specific keywords and regex patterns applied dynamically during prompt ingestion.
            </p>
          </div>

          {userRole === 'ADMIN' && (
            <button
              onClick={() => setShowAddForm(!showAddForm)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs shadow-[0_0_10px_rgba(6,182,212,0.25)] transition-all cursor-pointer"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>{showAddForm ? 'CANCEL' : 'ADD CUSTOM RULE'}</span>
            </button>
          )}
        </div>

        {/* Add Rule Form */}
        {showAddForm && userRole === 'ADMIN' && (
          <form onSubmit={handleSubmit} className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
            <h4 className="font-bold text-slate-200 text-xs">Define Custom Enterprise Rule</h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] text-slate-400 block mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Project Orion Codename"
                  className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <div>
                <label className="text-[10px] text-slate-400 block mb-1">Matching Pattern</label>
                <input
                  type="text"
                  required
                  value={pattern}
                  onChange={(e) => setPattern(e.target.value)}
                  placeholder="e.g. Orion-Core or dev-cluster\\.internal"
                  className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <div>
                <label className="text-[10px] text-slate-400 block mb-1">Matcher Type</label>
                <select
                  value={type}
                  onChange={(e) => setType(e.target.value as any)}
                  className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none"
                >
                  <option value="keyword">Exact Keyword Substring</option>
                  <option value="regex">Regular Expression</option>
                </select>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 block mb-1">Enforcement Action</label>
                <select
                  value={action}
                  onChange={(e) => setAction(e.target.value as any)}
                  className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none"
                >
                  <option value="BLOCK">BLOCK Prompt</option>
                  <option value="REDACT">REDACT / MASK Match</option>
                </select>
              </div>

              {action === 'REDACT' && (
                <div>
                  <label className="text-[10px] text-slate-400 block mb-1">Redaction Placeholder</label>
                  <input
                    type="text"
                    value={placeholder}
                    onChange={(e) => setPlaceholder(e.target.value)}
                    placeholder="[REDACTED_CODENAME]"
                    className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none"
                  />
                </div>
              )}

              <div className={action === 'REDACT' ? '' : 'sm:col-span-2'}>
                <label className="text-[10px] text-slate-400 block mb-1">Explanation / Impact</label>
                <input
                  type="text"
                  value={explanation}
                  onChange={(e) => setExplanation(e.target.value)}
                  placeholder="Protects confidential internal codename from leaking..."
                  className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none"
                />
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="submit"
                className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold"
              >
                Commit Rule to Gateway
              </button>
            </div>
          </form>
        )}

        {/* Existing Rules Table */}
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
              {rules.map((rule) => (
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
                        className="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors"
                        title="Delete Rule"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
