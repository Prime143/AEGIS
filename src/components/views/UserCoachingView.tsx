import React, { useState } from 'react';
import { 
  GraduationCap, 
  ShieldCheck, 
  Award, 
  CheckCircle, 
  Clock, 
  BookOpen, 
  Check, 
  Sparkles, 
  ArrowRight,
  Lightbulb,
  FileText,
  Shield
} from 'lucide-react';
import { UserAwarenessProfile, TrainingModule } from '../../core/types';

interface UserCoachingViewProps {
  profile: UserAwarenessProfile | null;
  onCompleteModule: (email: string, moduleId: string) => Promise<void>;
  userEmail: string;
}

export const UserCoachingView: React.FC<UserCoachingViewProps> = ({
  profile,
  onCompleteModule,
  userEmail
}) => {
  const [activeModuleModal, setActiveModuleModal] = useState<TrainingModule | null>(null);
  const [isCompleting, setIsCompleting] = useState(false);

  if (!profile) {
    return (
      <div className="p-12 text-center text-slate-500 font-sans text-xs">
        Loading personalized security awareness profile...
      </div>
    );
  }

  const completedModuleIds = new Set(
    profile.assignedModules.filter(m => m.status === 'COMPLETED').map(m => m.moduleId)
  );

  return (
    <div className="space-y-6 font-sans">
      {/* Header Banner */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
            <GraduationCap className="w-5 h-5 text-cyan-400" />
            <span>My Security Awareness &amp; AI Coaching</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1 leading-relaxed">
            Personalized safety rating and just-in-time micro-learning to help you prompt productively while protecting company data.
          </p>
        </div>

        <div className="flex items-center space-x-2 bg-slate-950 border border-slate-800 px-3 py-1.5 rounded-lg text-xs">
          <span className="text-slate-400">Account:</span>
          <span className="font-semibold text-slate-200">{userEmail}</span>
        </div>
      </div>

      {/* Hero Posture Score & Diagnosis */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Awareness Score Card */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between space-y-4">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center space-x-1.5">
              <Award className="w-4 h-4 text-cyan-400" />
              <span>Security Posture Rating</span>
            </div>
            <div className="flex items-baseline space-x-2 mt-2">
              <span className={`text-4xl font-bold font-mono ${
                profile.awarenessScore >= 80 ? 'text-emerald-400' :
                profile.awarenessScore >= 50 ? 'text-amber-400' : 'text-rose-400'
              }`}>
                {profile.awarenessScore}
              </span>
              <span className="text-slate-500 text-sm font-mono">/ 100</span>
            </div>
          </div>

          <div>
            <div className="w-full h-2 rounded-full bg-slate-950 border border-slate-800 overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${
                  profile.awarenessScore >= 80 ? 'bg-emerald-500' :
                  profile.awarenessScore >= 50 ? 'bg-amber-500' : 'bg-rose-500'
                }`}
                style={{ width: `${profile.awarenessScore}%` }}
              />
            </div>
            <div className="flex justify-between items-center text-[11px] text-slate-400 mt-2">
              <span>Tier: <strong className="text-slate-200">{profile.postureTier.replace('_', ' ')}</strong></span>
              <span>{profile.cleanInteractions} clean prompt{profile.cleanInteractions !== 1 ? 's' : ''}</span>
            </div>
          </div>
        </div>

        {/* AI Personalized Guidance Summary */}
        <div className="md:col-span-2 p-5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between space-y-3">
          <div>
            <div className="text-xs font-semibold text-cyan-300 uppercase tracking-wider flex items-center space-x-1.5 mb-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <span>Personalized Security Insights</span>
            </div>
            <p className="text-slate-200 text-xs sm:text-sm leading-relaxed">
              {profile.aiExecutiveSummary}
            </p>
          </div>

          <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
            <span>Continuous coaching based on recent gateway prompts</span>
            <span className="text-cyan-400 font-medium">Safe Prompting Verified</span>
          </div>
        </div>
      </div>

      {/* Recommended & Assigned Micro-Learning Modules */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <BookOpen className="w-4 h-4 text-cyan-400" />
              <span>Your Recommended Micro-Learning Modules</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Short, high-impact guides (5–8 minutes) designed to keep customer data and company secrets safe.
            </p>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            {profile.recommendedModules.length} module{profile.recommendedModules.length > 1 ? 's' : ''} available
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {profile.recommendedModules.map((mod) => {
            const isCompleted = completedModuleIds.has(mod.id);

            return (
              <div
                key={mod.id}
                className={`p-5 rounded-xl border transition-all flex flex-col justify-between space-y-4 ${
                  isCompleted
                    ? 'bg-slate-900/40 border-slate-800/80 opacity-90'
                    : 'bg-slate-900/70 border-slate-800 hover:border-cyan-500/40'
                }`}
              >
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 border border-cyan-800 text-cyan-300">
                        {mod.id}
                      </span>
                      <span className="text-slate-400 text-[11px] flex items-center space-x-1 font-mono">
                        <Clock className="w-3 h-3" />
                        <span>{mod.durationMinutes} min</span>
                      </span>
                    </div>

                    {isCompleted ? (
                      <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-semibold flex items-center space-x-1">
                        <Check className="w-3 h-3" />
                        <span>Completed</span>
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800 text-[10px]">
                        {mod.level}
                      </span>
                    )}
                  </div>

                  <h4 className="text-sm font-bold text-slate-100">
                    {mod.title}
                  </h4>

                  <p className="text-xs text-slate-400 leading-relaxed">
                    {mod.description}
                  </p>

                  {/* Key Takeaways Preview */}
                  <div className="pt-2 border-t border-slate-800/60 space-y-1">
                    <div className="text-[11px] font-semibold text-slate-300">Key Takeaways:</div>
                    <ul className="list-disc list-inside space-y-0.5 text-[11px] text-slate-400">
                      {mod.keyTakeaways.slice(0, 2).map((k, i) => (
                        <li key={i} className="truncate">{k}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                  <span className="text-[11px] text-slate-500 italic">
                    Action: {mod.actionItem.substring(0, 38)}...
                  </span>

                  <button
                    onClick={() => setActiveModuleModal(mod)}
                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors cursor-pointer flex items-center space-x-1"
                  >
                    <span>{isCompleted ? 'Review Module' : 'Start Module'}</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Safe Prompting Best Practices Quick Reference */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
        <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
          <Lightbulb className="w-4 h-4 text-amber-400" />
          <span>Enterprise AI Prompting Golden Rules</span>
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="font-semibold text-cyan-300 block">1. Use Placeholders</span>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Replace customer names, emails, and phone numbers with generic labels (e.g. <code>Client-A</code>) before submitting.
            </p>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="font-semibold text-cyan-300 block">2. Zero Credentials</span>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Never paste active API tokens, passwords, or database URIs into AI assistants; use mock tokens like <code>YOUR_API_KEY</code>.
            </p>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="font-semibold text-cyan-300 block">3. Protect Codenames</span>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Keep unreleased product codenames (e.g. Orion-Core) and internal hostnames generic when asking for coding assistance.
            </p>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="font-semibold text-cyan-300 block">4. Verify Outputs</span>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Always double-check generated code and factual statements for hallucinations before incorporating into business workflows.
            </p>
          </div>
        </div>
      </div>

      {/* Interactive Micro-Module Modal */}
      {activeModuleModal && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 text-xs space-y-4 shadow-2xl">
            <div className="flex justify-between items-start border-b border-slate-800 pb-3">
              <div>
                <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wide">
                  AEGIS SECURITY MICRO-MODULE &middot; {activeModuleModal.id}
                </span>
                <h3 className="text-sm font-bold text-slate-100 mt-0.5">
                  {activeModuleModal.title}
                </h3>
              </div>
              <button
                onClick={() => setActiveModuleModal(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                &times;
              </button>
            </div>

            <div className="space-y-3">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 leading-relaxed">
                {activeModuleModal.description}
              </div>

              <div className="space-y-2">
                <span className="font-semibold text-slate-200 block">Key Takeaways for Daily Work:</span>
                <div className="space-y-1.5">
                  {activeModuleModal.keyTakeaways.map((takeaway, i) => (
                    <div key={i} className="flex items-start space-x-2 text-slate-300">
                      <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                      <span>{takeaway}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-cyan-950/40 border border-cyan-800/40 space-y-1">
                <span className="font-semibold text-cyan-300 text-xs block">Immediate Action Item:</span>
                <p className="text-slate-200 text-xs leading-relaxed">
                  {activeModuleModal.actionItem}
                </p>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-between items-center">
              <button
                onClick={() => setActiveModuleModal(null)}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs cursor-pointer"
              >
                Close
              </button>

              <button
                disabled={isCompleting || completedModuleIds.has(activeModuleModal.id)}
                onClick={async () => {
                  setIsCompleting(true);
                  try {
                    await onCompleteModule(userEmail, activeModuleModal.id);
                    setActiveModuleModal(null);
                  } finally {
                    setIsCompleting(false);
                  }
                }}
                className={`px-4 py-1.5 rounded-lg font-semibold text-xs transition-colors ${
                  completedModuleIds.has(activeModuleModal.id)
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-800 cursor-default'
                    : 'bg-emerald-600 hover:bg-emerald-500 text-slate-950 cursor-pointer'
                }`}
              >
                {completedModuleIds.has(activeModuleModal.id) ? (
                  'Completed'
                ) : isCompleting ? (
                  'Marking Completed...'
                ) : (
                  'Complete & Apply Learning (+10 Pts)'
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
