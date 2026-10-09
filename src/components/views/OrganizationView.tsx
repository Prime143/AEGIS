import React, { useState } from 'react';
import { 
  Building2, 
  Tag, 
  FileText, 
  Shield, 
  Save, 
  PlusCircle, 
  Trash2,
  Lock,
  Info,
  Key,
  Copy,
  Check
} from 'lucide-react';
import { OrganizationContext, UserRole } from '../../core/types';
import { ApiKey } from '../../../database';

interface OrganizationViewProps {
  organization: OrganizationContext;
  onUpdateOrganization: (updated: Partial<OrganizationContext>) => Promise<void>;
  userRole: UserRole;
  apiKeys?: ApiKey[];
  onCreateApiKey?: (name: string, role: UserRole) => Promise<void>;
  onRevokeApiKey?: (id: string) => Promise<void>;
}

export const OrganizationView: React.FC<OrganizationViewProps> = ({
  organization,
  onUpdateOrganization,
  userRole,
  apiKeys = [],
  onCreateApiKey,
  onRevokeApiKey
}) => {
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyRole, setNewKeyRole] = useState<UserRole>('USER');
  const [copiedKeyId, setCopiedKeyId] = useState<string | null>(null);
  const [orgName, setOrgName] = useState(organization.organizationName);
  const [retentionDays, setRetentionDays] = useState(organization.retentionDays || 90);
  const [newTerm, setNewTerm] = useState('');
  const [newClassification, setNewClassification] = useState<'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED'>('CONFIDENTIAL');
  const [newPlaceholder, setNewPlaceholder] = useState('');
  const [savedSuccess, setSavedSuccess] = useState(false);

  const handleSaveGeneral = async (e: React.FormEvent) => {
    e.preventDefault();
    if (userRole !== 'ADMIN') return;

    await onUpdateOrganization({
      organizationName: orgName,
      retentionDays
    });
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2000);
  };

  const handleAddGlossaryTerm = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTerm.trim() || userRole !== 'ADMIN') return;

    const newEntry = {
      id: `gls-${Date.now()}`,
      term: newTerm.trim(),
      category: 'CONFIDENTIAL_TECHNICAL' as const,
      classification: newClassification,
      placeholder: newPlaceholder.trim() || `[REDACTED_${newClassification}]`
    };

    const updatedGlossary = [...organization.glossary, newEntry];
    await onUpdateOrganization({ glossary: updatedGlossary });
    setNewTerm('');
    setNewPlaceholder('');
  };

  const handleDeleteGlossaryTerm = async (id: string) => {
    if (userRole !== 'ADMIN') return;
    const updated = organization.glossary.filter(g => g.id !== id);
    await onUpdateOrganization({ glossary: updated });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
        <h2 className="text-base font-bold text-slate-100 font-mono flex items-center space-x-2">
          <Building2 className="w-4 h-4 text-cyan-400" />
          <span>ORGANIZATION SECURITY CONTEXT &amp; DATA CLASSIFICATIONS</span>
        </h2>
        <p className="text-xs text-slate-400 font-mono mt-0.5">
          Configurable enterprise boundary definitions. Decoupled from hardcoded values, supporting dynamic tenant policies.
        </p>
      </div>

      {/* General Organization Settings */}
      <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 font-mono text-xs">
        <h3 className="text-sm font-bold text-slate-100 mb-3 flex items-center space-x-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span>Enterprise Entity &amp; Audit Retention</span>
        </h3>

        <form onSubmit={handleSaveGeneral} className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="text-[11px] text-slate-400 block mb-1">Organization Name</label>
            <input
              type="text"
              disabled={userRole !== 'ADMIN'}
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              className="w-full p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none focus:border-cyan-500/50 disabled:opacity-50"
            />
          </div>

          <div>
            <label className="text-[11px] text-slate-400 block mb-1">Audit Log Retention (Days)</label>
            <input
              type="number"
              min="7"
              max="365"
              disabled={userRole !== 'ADMIN'}
              value={retentionDays}
              onChange={(e) => setRetentionDays(parseInt(e.target.value, 10))}
              className="w-full p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none focus:border-cyan-500/50 disabled:opacity-50"
            />
          </div>

          {userRole === 'ADMIN' && (
            <div className="sm:col-span-2 flex justify-end">
              <button
                type="submit"
                className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold transition-all cursor-pointer"
              >
                <Save className="w-3.5 h-3.5" />
                <span>{savedSuccess ? 'SAVED TO GATEWAY' : 'SAVE GENERAL SETTINGS'}</span>
              </button>
            </div>
          )}
        </form>
      </div>

      {/* Data Classifications Grid */}
      <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 font-mono text-xs space-y-3">
        <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
          <Tag className="w-4 h-4 text-cyan-400" />
          <span>DATA CLASSIFICATION TIERS</span>
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {organization.dataClassifications.map((cls) => {
            let badge = 'bg-emerald-950 text-emerald-300 border-emerald-800';
            if (cls.level === 'INTERNAL') badge = 'bg-blue-950 text-blue-300 border-blue-800';
            if (cls.level === 'CONFIDENTIAL') badge = 'bg-amber-950 text-amber-300 border-amber-800';
            if (cls.level === 'RESTRICTED') badge = 'bg-rose-950 text-rose-300 border-rose-800';

            return (
              <div key={cls.id} className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${badge}`}>
                  {cls.name}
                </span>
                <p className="text-[11px] text-slate-400 leading-relaxed">{cls.description}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Protected Organization Glossary Terms */}
      <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 font-mono text-xs space-y-4">
        <div className="flex justify-between items-center border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              <span>PROTECTED GLOSSARY TERMS &amp; CODENAMES</span>
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Identified terms will be intercepted by the DictionaryDetector and masked according to organizational classification.
            </p>
          </div>
        </div>

        {/* Add Glossary Term Form */}
        {userRole === 'ADMIN' && (
          <form onSubmit={handleAddGlossaryTerm} className="grid grid-cols-1 sm:grid-cols-4 gap-2.5 p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div>
              <label className="text-[10px] text-slate-400 block mb-1">Protected Term</label>
              <input
                type="text"
                required
                value={newTerm}
                onChange={(e) => setNewTerm(e.target.value)}
                placeholder="e.g. Project Chimera"
                className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none"
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-400 block mb-1">Classification Tier</label>
              <select
                value={newClassification}
                onChange={(e) => setNewClassification(e.target.value as any)}
                className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none"
              >
                <option value="INTERNAL">INTERNAL (Mask)</option>
                <option value="CONFIDENTIAL">CONFIDENTIAL (Mask)</option>
                <option value="RESTRICTED">RESTRICTED (Block)</option>
              </select>
            </div>

            <div>
              <label className="text-[10px] text-slate-400 block mb-1">Redaction Placeholder</label>
              <input
                type="text"
                value={newPlaceholder}
                onChange={(e) => setNewPlaceholder(e.target.value)}
                placeholder="[REDACTED_CODENAME]"
                className="w-full p-2 rounded bg-slate-900 border border-slate-800 text-slate-100 focus:outline-none"
              />
            </div>

            <div className="flex items-end">
              <button
                type="submit"
                className="w-full p-2 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold flex items-center justify-center space-x-1 cursor-pointer"
              >
                <PlusCircle className="w-3.5 h-3.5" />
                <span>ADD TERM</span>
              </button>
            </div>
          </form>
        )}

        {/* Existing Glossary Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400">
                <th className="pb-2 font-medium">PROTECTED TERM</th>
                <th className="pb-2 font-medium">CLASSIFICATION</th>
                <th className="pb-2 font-medium">MASKING PLACEHOLDER</th>
                {userRole === 'ADMIN' && <th className="pb-2 font-medium text-right">MANAGE</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {organization.glossary.map((g) => (
                <tr key={g.id} className="hover:bg-slate-800/40">
                  <td className="py-2.5 text-slate-200 font-bold">{g.term}</td>
                  <td className="py-2.5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      g.classification === 'RESTRICTED' ? 'bg-rose-950 text-rose-300 border-rose-800' :
                      g.classification === 'CONFIDENTIAL' ? 'bg-amber-950 text-amber-300 border-amber-800' :
                      'bg-blue-950 text-blue-300 border-blue-800'
                    }`}>
                      {g.classification}
                    </span>
                  </td>
                  <td className="py-2.5 text-cyan-300 text-[11px]">{g.placeholder || `[REDACTED_${g.classification}]`}</td>
                  {userRole === 'ADMIN' && (
                    <td className="py-2.5 text-right">
                      <button
                        onClick={() => handleDeleteGlossaryTerm(g.id)}
                        className="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors"
                        title="Remove Term"
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

      {/* Developer API Keys Management */}
      <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 font-mono text-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <Key className="w-4 h-4 text-cyan-400" />
              <span>DEVELOPER SERVICE-TO-SERVICE API KEYS</span>
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Service credentials for programmatic AI Gateway integration. Grants bypass of interactive user consent.
            </p>
          </div>
          {userRole !== 'ADMIN' && (
            <span className="text-[10px] text-slate-500 italic">Admin role required to generate or revoke API keys</span>
          )}
        </div>

        {userRole === 'ADMIN' && onCreateApiKey && (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              if (!newKeyName.trim()) return;
              await onCreateApiKey(newKeyName.trim(), newKeyRole);
              setNewKeyName('');
            }}
            className="flex flex-wrap items-center gap-2 p-3 rounded-lg bg-slate-950 border border-slate-800"
          >
            <input
              type="text"
              placeholder="Application / Service Name (e.g. CI-Pipeline-Bot)..."
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              className="flex-1 min-w-[200px] p-2 rounded bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-cyan-500/50"
            />
            <select
              value={newKeyRole}
              onChange={(e) => setNewKeyRole(e.target.value as UserRole)}
              className="p-2 rounded bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none cursor-pointer"
            >
              <option value="USER">Role: USER</option>
              <option value="SECURITY_ANALYST">Role: ANALYST</option>
              <option value="ADMIN">Role: ADMIN</option>
            </select>
            <button
              type="submit"
              disabled={!newKeyName.trim()}
              className="flex items-center space-x-1.5 px-3 py-2 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-slate-950 font-bold text-xs transition-colors cursor-pointer"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>GENERATE KEY</span>
            </button>
          </form>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400">
                <th className="pb-2.5 font-medium">SERVICE NAME</th>
                <th className="pb-2.5 font-medium">TOKEN (SECRET)</th>
                <th className="pb-2.5 font-medium">ROLE</th>
                <th className="pb-2.5 font-medium">STATUS</th>
                <th className="pb-2.5 font-medium">REQUESTS</th>
                {userRole === 'ADMIN' && <th className="pb-2.5 font-medium text-right">MANAGE</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {apiKeys.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-6 text-center text-slate-500">
                    No developer API keys created.
                  </td>
                </tr>
              ) : (
                apiKeys.map((k) => (
                  <tr key={k.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 text-slate-200 font-bold">{k.name}</td>
                    <td className="py-2.5">
                      <div className="flex items-center space-x-2">
                        <code className="text-[11px] text-cyan-300 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                          {k.key ? `${k.key.substring(0, 14)}...${k.key.slice(-4)}` : '••••••••'}
                        </code>
                        <button
                          onClick={() => {
                            navigator.clipboard.writeText(k.key);
                            setCopiedKeyId(k.id);
                            setTimeout(() => setCopiedKeyId(null), 2000);
                          }}
                          className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
                          title="Copy API key to clipboard"
                        >
                          {copiedKeyId === k.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </td>
                    <td className="py-2.5 text-slate-300 text-[11px]">{k.role}</td>
                    <td className="py-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        k.status === 'active'
                          ? 'bg-emerald-950/70 text-emerald-300 border-emerald-800'
                          : 'bg-rose-950/70 text-rose-400 border-rose-800'
                      }`}>
                        {k.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-2.5 text-slate-400">{k.totalRequests || 0}</td>
                    {userRole === 'ADMIN' && (
                      <td className="py-2.5 text-right">
                        {k.status === 'active' && onRevokeApiKey && (
                          <button
                            onClick={() => onRevokeApiKey(k.id)}
                            className="px-2 py-1 rounded bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-rose-300 text-[10px] font-bold cursor-pointer"
                          >
                            REVOKE
                          </button>
                        )}
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
  );
};
