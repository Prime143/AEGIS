import React, { useState } from 'react';
import { 
  GraduationCap, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  User, 
  Search, 
  Filter, 
  Clock, 
  BookOpen, 
  PlusCircle, 
  Check, 
  Download, 
  X, 
  ArrowRight,
  TrendingUp,
  Sparkles
} from 'lucide-react';
import { UserAwarenessProfile, TrainingModule, UserRole } from '../../core/types';

interface AwarenessAdminViewProps {
  profiles: UserAwarenessProfile[];
  modules: TrainingModule[];
  onAssignTraining: (email: string, moduleId: string) => Promise<void>;
  onCompleteTraining: (email: string, moduleId: string) => Promise<void>;
  userRole: UserRole;
  authToken?: string;
  onRefresh?: () => void;
}

export const AwarenessAdminView: React.FC<AwarenessAdminViewProps> = ({
  profiles,
  modules,
  onAssignTraining,
  onCompleteTraining,
  userRole,
  onRefresh
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterTier, setFilterTier] = useState<string>('ALL');
  const [filterType, setFilterType] = useState<'HUMAN_EMPLOYEE' | 'SECURITY_ADMIN' | 'SERVICE_PRINCIPAL' | 'ALL'>('HUMAN_EMPLOYEE');
  const [selectedProfile, setSelectedProfile] = useState<UserAwarenessProfile | null>(null);
  const [isActionPending, setIsActionPending] = useState(false);

  // Human Employees baseline for realistic organizational statistics
  const humanProfiles = profiles.filter(p => p.accountType === 'HUMAN_EMPLOYEE');
  const totalEmployees = humanProfiles.length;
  const avgAwareness = totalEmployees > 0
    ? Math.round(humanProfiles.reduce((acc, p) => acc + p.awarenessScore, 0) / totalEmployees)
    : 100;
  const highRiskCount = humanProfiles.filter(p => p.postureTier === 'HIGH_RISK').length;
  const needsCoachingCount = humanProfiles.filter(p => p.postureTier === 'NEEDS_COACHING').length;
  const remediationRequiredCount = highRiskCount + needsCoachingCount;
  const totalCompletedTrainings = humanProfiles.reduce(
    (acc, p) => acc + p.assignedModules.filter(m => m.status === 'COMPLETED').length,
    0
  );

  // Segment Counts
  const humanCount = humanProfiles.length;
  const adminCount = profiles.filter(p => p.accountType === 'SECURITY_ADMIN').length;
  const serviceCount = profiles.filter(p => p.accountType === 'SERVICE_PRINCIPAL').length;

  // Filtered List
  const filteredProfiles = profiles.filter(p => {
    if (filterType !== 'ALL' && p.accountType !== filterType) return false;
    if (filterTier !== 'ALL' && p.postureTier !== filterTier) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchEmail = p.userEmail.toLowerCase().includes(q);
      const matchName = p.name.toLowerCase().includes(q);
      const matchDept = p.department.toLowerCase().includes(q);
      const matchGaps = p.primaryGaps.some(g => g.category.toLowerCase().includes(q));
      return matchEmail || matchName || matchDept || matchGaps;
    }
    return true;
  });

  const handleExportDossier = (profile: UserAwarenessProfile) => {
    const jsonStr = JSON.stringify(profile, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-security-awareness-${profile.userEmail.replace(/[@.]/g, '_')}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900/60 border border-slate-800">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
            <GraduationCap className="w-5 h-5 text-cyan-400" />
            <span>Human Risk Management &amp; Security Awareness</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1 leading-relaxed">
            Continuous behavioral posture assessment identifying recurring blind spots and prescribing just-in-time micro-training for enterprise personnel.
          </p>
        </div>

        {onRefresh && (
          <button
            onClick={onRefresh}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors cursor-pointer shrink-0"
          >
            <span>Refresh Telemetry</span>
          </button>
        )}
      </div>

      {/* KPI Stats Bar (Based on Active Human Workforce) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Average Awareness</div>
          <div className={`text-2xl font-bold font-mono mt-1.5 ${
            avgAwareness >= 80 ? 'text-emerald-400' :
            avgAwareness >= 60 ? 'text-amber-400' : 'text-rose-400'
          }`}>
            {avgAwareness} / 100
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Human workforce index</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Employees</div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-1.5">{totalEmployees}</div>
          <div className="text-[11px] text-slate-500 mt-1">Monitored corporate personnel</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="text-xs font-semibold text-amber-400 uppercase tracking-wider flex items-center space-x-1">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Requires Remediation</span>
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1.5">{remediationRequiredCount}</div>
          <div className="text-[11px] text-slate-500 mt-1">
            {highRiskCount} high risk &middot; {needsCoachingCount} coaching
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="text-xs font-semibold text-emerald-400 uppercase tracking-wider flex items-center space-x-1">
            <CheckCircle className="w-3.5 h-3.5" />
            <span>Remediated Modules</span>
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1.5">{totalCompletedTrainings}</div>
          <div className="text-[11px] text-slate-500 mt-1">Micro-courses completed</div>
        </div>
      </div>

      {/* Account Type Directory Segment Pills */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3 text-xs">
        <span className="text-slate-400 mr-2 font-medium">Directory Scope:</span>
        <button
          onClick={() => setFilterType('HUMAN_EMPLOYEE')}
          className={`px-3 py-1.5 rounded-lg font-medium transition-all cursor-pointer ${
            filterType === 'HUMAN_EMPLOYEE'
              ? 'bg-cyan-600 text-slate-950 font-semibold shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          Human Employees ({humanCount})
        </button>
        <button
          onClick={() => setFilterType('SECURITY_ADMIN')}
          className={`px-3 py-1.5 rounded-lg font-medium transition-all cursor-pointer ${
            filterType === 'SECURITY_ADMIN'
              ? 'bg-cyan-600 text-slate-950 font-semibold shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          SecOps Operators ({adminCount})
        </button>
        <button
          onClick={() => setFilterType('SERVICE_PRINCIPAL')}
          className={`px-3 py-1.5 rounded-lg font-medium transition-all cursor-pointer ${
            filterType === 'SERVICE_PRINCIPAL'
              ? 'bg-cyan-600 text-slate-950 font-semibold shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          Service Principals &amp; Bots ({serviceCount})
        </button>
        <button
          onClick={() => setFilterType('ALL')}
          className={`px-3 py-1.5 rounded-lg font-medium transition-all cursor-pointer ${
            filterType === 'ALL'
              ? 'bg-cyan-600 text-slate-950 font-semibold shadow-sm'
              : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
          }`}
        >
          All Directory Accounts ({profiles.length})
        </button>
      </div>

      {/* Search & Filter Header */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 text-xs">
        <div className="flex-1 flex items-center space-x-2 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 focus-within:border-cyan-500/50">
          <Search className="w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by employee name, email, department, or blind spot category..."
            className="w-full bg-transparent text-slate-200 placeholder-slate-500 focus:outline-none"
          />
          {searchQuery && (
            <button onClick={() => setSearchQuery('')} className="text-slate-500 hover:text-slate-300">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <div className="flex items-center space-x-2">
          <select
            value={filterTier}
            onChange={(e) => setFilterTier(e.target.value)}
            className="bg-slate-950 text-slate-200 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Posture Tiers</option>
            <option value="HIGH_RISK">High Risk (&lt;50)</option>
            <option value="NEEDS_COACHING">Needs Coaching (50-74)</option>
            <option value="GOOD">Good Posture (75-89)</option>
            <option value="EXEMPLARY">Exemplary (&ge;90)</option>
          </select>
        </div>
      </div>

      {/* Employee Awareness Directory Table */}
      <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
        <div className="flex justify-between items-center mb-3 text-xs">
          <span className="text-slate-400">
            Showing <span className="text-slate-200 font-bold">{filteredProfiles.length}</span> of {profiles.length} profiles
            {filterType === 'HUMAN_EMPLOYEE' && <span className="text-cyan-400 font-medium ml-1.5">&middot; Human Workforce Focus</span>}
          </span>
          <span className="text-[11px] text-slate-500">Continuous behavioral risk monitoring</span>
        </div>

        {filteredProfiles.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-xs">
            No profiles match the selected scope and filters.
          </div>
        ) : (
          <div className="overflow-x-auto text-xs">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] text-slate-400">
                  <th className="pb-2.5 font-medium">PERSONNEL &amp; DEPARTMENT</th>
                  <th className="pb-2.5 font-medium">CLASSIFICATION</th>
                  <th className="pb-2.5 font-medium">AWARENESS SCORE</th>
                  <th className="pb-2.5 font-medium">POSTURE TIER</th>
                  <th className="pb-2.5 font-medium">INTERCEPTIONS</th>
                  <th className="pb-2.5 font-medium">PRIMARY BLIND SPOT</th>
                  <th className="pb-2.5 font-medium text-right">DOSSIER</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredProfiles.map((p) => {
                  let badge = 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30';
                  if (p.postureTier === 'HIGH_RISK') badge = 'bg-rose-500/15 text-rose-300 border-rose-500/30';
                  if (p.postureTier === 'NEEDS_COACHING') badge = 'bg-amber-500/15 text-amber-300 border-amber-500/30';
                  if (p.postureTier === 'GOOD') badge = 'bg-blue-500/15 text-blue-300 border-blue-500/30';

                  const primaryGapName = p.primaryGaps.length > 0
                    ? p.primaryGaps[0].category
                    : p.accountType === 'SECURITY_ADMIN'
                    ? 'Authorized Drill Testing'
                    : 'None (Clean Usage)';

                  return (
                    <tr
                      key={p.userEmail}
                      onClick={() => setSelectedProfile(p)}
                      className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                    >
                      <td className="py-3 text-slate-200 font-medium">
                        <div className="flex items-center space-x-2.5">
                          <div className={`w-7 h-7 rounded-full flex items-center justify-center text-[11px] font-bold shrink-0 ${
                            p.accountType === 'SECURITY_ADMIN' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' :
                            p.accountType === 'SERVICE_PRINCIPAL' ? 'bg-slate-900 text-slate-400 border border-slate-800' :
                            'bg-slate-800 text-slate-200 border border-slate-700'
                          }`}>
                            {p.name.charAt(0)}
                          </div>
                          <div>
                            <div className="font-semibold text-slate-100 flex items-center space-x-1.5">
                              <span>{p.name}</span>
                              {p.isExemptFromMandatoryTraining && (
                                <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-950/70 border border-cyan-800/60 text-cyan-300 uppercase font-mono">
                                  Exempt
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-slate-400">{p.department} &middot; <span className="font-mono text-slate-500">{p.userEmail}</span></div>
                          </div>
                        </div>
                      </td>
                      <td className="py-3 text-slate-400">
                        <span className="text-[10px] px-2 py-0.5 rounded bg-slate-950 border border-slate-800">
                          {p.accountType === 'HUMAN_EMPLOYEE' ? 'Human Personnel' :
                           p.accountType === 'SECURITY_ADMIN' ? 'SecOps Lead' : 'Service Principal'}
                        </span>
                      </td>
                      <td className="py-3">
                        <div className="flex items-center space-x-2">
                          <span className={`font-mono font-bold ${
                            p.awarenessScore >= 80 ? 'text-emerald-400' :
                            p.awarenessScore >= 50 ? 'text-amber-400' : 'text-rose-400'
                          }`}>
                            {p.awarenessScore}
                          </span>
                          <div className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden hidden sm:block">
                            <div
                              className={`h-full ${
                                p.awarenessScore >= 80 ? 'bg-emerald-500' :
                                p.awarenessScore >= 50 ? 'bg-amber-500' : 'bg-rose-500'
                              }`}
                              style={{ width: `${p.awarenessScore}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="py-3">
                        <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${badge}`}>
                          {p.postureTier.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="py-3 text-slate-300">
                        {p.violationsCount > 0 ? (
                          <span className="text-amber-300 font-medium">
                            {p.violationsCount} ({p.blockedCount} blk / {p.maskedCount} mask)
                          </span>
                        ) : (
                          <span className="text-slate-500">0 violations</span>
                        )}
                      </td>
                      <td className="py-3 text-slate-300">
                        <span className="truncate max-w-[170px] block font-medium">
                          {primaryGapName}
                        </span>
                      </td>
                      <td className="py-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedProfile(p);
                          }}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-300 text-[11px] font-medium transition-colors"
                        >
                          View Report
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

      {/* Detailed Individual Employee Awareness Dossier Modal */}
      {selectedProfile && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6 text-xs space-y-5 shadow-2xl">
            {/* Modal Header */}
            <div className="flex justify-between items-start border-b border-slate-800 pb-3">
              <div>
                <div className="flex items-center space-x-2">
                  <GraduationCap className="w-5 h-5 text-cyan-400" />
                  <h3 className="text-sm font-bold text-slate-100">
                    EMPLOYEE SECURITY AWARENESS DOSSIER
                  </h3>
                </div>
                <div className="text-slate-400 mt-1 flex items-center space-x-2">
                  <span className="font-semibold text-slate-200">{selectedProfile.userEmail}</span>
                  <span>&middot;</span>
                  <span>Role: {selectedProfile.userRole}</span>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handleExportDossier(selectedProfile)}
                  className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-slate-100"
                  title="Export Dossier (JSON)"
                >
                  <Download className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setSelectedProfile(null)}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* AI Executive Posture Assessment Summary */}
            <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/30 space-y-2">
              <div className="flex items-center space-x-2 text-cyan-300 font-semibold text-xs uppercase tracking-wide">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <span>Automated Posture Assessment &amp; Coaching Diagnosis</span>
              </div>
              <p className="text-slate-200 leading-relaxed text-xs">
                {selectedProfile.aiExecutiveSummary}
              </p>
            </div>

            {/* Score & Metrics Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <div>
                <div className="text-[10px] text-slate-500 uppercase">Awareness Score</div>
                <div className={`font-mono font-bold text-base mt-0.5 ${
                  selectedProfile.awarenessScore >= 80 ? 'text-emerald-400' :
                  selectedProfile.awarenessScore >= 50 ? 'text-amber-400' : 'text-rose-400'
                }`}>
                  {selectedProfile.awarenessScore} / 100
                </div>
              </div>
              <div>
                <div className="text-[10px] text-slate-500 uppercase">Posture Tier</div>
                <div className="font-semibold text-slate-200 mt-0.5 text-xs">
                  {selectedProfile.postureTier.replace('_', ' ')}
                </div>
              </div>
              <div>
                <div className="text-[10px] text-slate-500 uppercase">Total Interactions</div>
                <div className="font-mono text-slate-200 mt-0.5 text-xs">
                  {selectedProfile.totalInteractions} ({selectedProfile.cleanInteractions} clean)
                </div>
              </div>
              <div>
                <div className="text-[10px] text-slate-500 uppercase">Policy Stops</div>
                <div className="font-mono text-amber-300 mt-0.5 text-xs">
                  {selectedProfile.violationsCount} ({selectedProfile.blockedCount} blk / {selectedProfile.maskedCount} mask)
                </div>
              </div>
            </div>

            {/* Identified Primary Blind Spots / Knowledge Gaps */}
            <div className="space-y-2.5">
              <h4 className="font-semibold text-slate-200 text-xs flex items-center space-x-1.5 uppercase tracking-wide">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>Identified Knowledge Gaps &amp; Recurring Exposures</span>
              </h4>

              {selectedProfile.primaryGaps.length === 0 ? (
                <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-800/40 text-emerald-300 text-xs">
                  No recurrent security gaps detected. User demonstrates consistent compliance with enterprise perimeter policies.
                </div>
              ) : (
                <div className="space-y-2">
                  {selectedProfile.primaryGaps.map((gap, i) => (
                    <div key={i} className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-start justify-between gap-3">
                      <div>
                        <div className="font-semibold text-slate-200 text-xs">
                          {gap.category} Exposure
                        </div>
                        <div className="text-slate-400 text-[11px] mt-0.5 leading-relaxed">
                          {gap.description}
                        </div>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-amber-950/80 border border-amber-800 text-amber-300 text-[10px] font-mono shrink-0">
                        {gap.incidentCount} hit{gap.incidentCount > 1 ? 's' : ''}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Prescribed Training Curriculum */}
            <div className="space-y-2.5">
              <h4 className="font-semibold text-slate-200 text-xs flex items-center space-x-1.5 uppercase tracking-wide">
                <BookOpen className="w-4 h-4 text-cyan-400" />
                <span>Prescribed Micro-Learning Modules</span>
              </h4>

              <div className="space-y-2">
                {selectedProfile.recommendedModules.map((mod) => {
                  const assignment = selectedProfile.assignedModules.find(a => a.moduleId === mod.id);
                  const isAssigned = !!assignment;
                  const isCompleted = assignment?.status === 'COMPLETED';

                  return (
                    <div key={mod.id} className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-mono text-cyan-400 font-semibold text-[11px]">{mod.id}</span>
                          <span className="font-semibold text-slate-200 text-xs">{mod.title}</span>
                          <span className="text-[10px] text-slate-500 font-mono">({mod.durationMinutes} min)</span>
                        </div>
                        <p className="text-slate-400 text-[11px] leading-relaxed max-w-md">
                          {mod.description}
                        </p>
                      </div>

                      <div className="shrink-0 flex items-center space-x-2">
                        {isCompleted ? (
                          <span className="px-2.5 py-1 rounded-lg bg-emerald-950 text-emerald-300 border border-emerald-800 text-[11px] font-semibold flex items-center space-x-1">
                            <Check className="w-3.5 h-3.5" />
                            <span>Completed</span>
                          </span>
                        ) : isAssigned ? (
                          <div className="flex items-center space-x-2">
                            <span className="px-2.5 py-1 rounded-lg bg-amber-950 text-amber-300 border border-amber-800 text-[11px] font-semibold">
                              Assigned
                            </span>
                            <button
                              disabled={isActionPending}
                              onClick={async () => {
                                setIsActionPending(true);
                                try {
                                  await onCompleteTraining(selectedProfile.userEmail, mod.id);
                                } finally {
                                  setIsActionPending(false);
                                }
                              }}
                              className="px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 text-[11px] font-semibold transition-colors cursor-pointer"
                            >
                              Mark Completed
                            </button>
                          </div>
                        ) : (
                          <button
                            disabled={isActionPending}
                            onClick={async () => {
                              setIsActionPending(true);
                              try {
                                await onAssignTraining(selectedProfile.userEmail, mod.id);
                              } finally {
                                setIsActionPending(false);
                              }
                            }}
                            className="px-2.5 py-1 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-[11px] font-semibold transition-colors cursor-pointer flex items-center space-x-1"
                          >
                            <PlusCircle className="w-3.5 h-3.5" />
                            <span>Assign Module</span>
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Footer */}
            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedProfile(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs cursor-pointer transition-colors"
              >
                Close Dossier
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
