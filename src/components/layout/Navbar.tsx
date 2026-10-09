import React from 'react';
import { Shield, ShieldAlert, Cpu, Activity, User, Lock, Unlock, Server } from 'lucide-react';
import { UserRole } from '../../core/types';

interface NavbarProps {
  currentRole: UserRole;
  userEmail: string;
  onRoleChange: (newRole: UserRole) => void;
  systemStatus: 'active' | 'lockdown';
  onToggleLockdown: () => void;
  activeProviderName: string;
  isProviderMock: boolean;
  activeTab: string;
  onSelectTab: (tab: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentRole,
  userEmail,
  onRoleChange,
  systemStatus,
  onToggleLockdown,
  activeProviderName,
  isProviderMock,
  activeTab,
  onSelectTab
}) => {
  // Role-aware navigation tabs
  const getTabsForRole = (role: UserRole) => {
    if (role === 'USER') {
      return [
        { id: 'console', label: 'AI Prompt Console' },
        { id: 'coaching', label: 'My Security Coaching' },
        { id: 'events', label: 'My Activity & DSAR' },
        { id: 'detectors', label: 'Security Rules & Policies (Read-Only)' }
      ];
    }
    if (role === 'SECURITY_ANALYST') {
      return [
        { id: 'dashboard', label: 'SOC Dashboard' },
        { id: 'console', label: 'AI Boundary Console' },
        { id: 'events', label: 'Security Events' },
        { id: 'awareness', label: 'Awareness & Training' },
        { id: 'detectors', label: 'Detectors & Policies' },
        { id: 'experiments', label: 'Experiments' },
        { id: 'health', label: 'System Health' }
      ];
    }
    // ADMIN has full platform access
    return [
      { id: 'dashboard', label: 'SOC Dashboard' },
      { id: 'console', label: 'AI Console' },
      { id: 'events', label: 'Security Events' },
      { id: 'awareness', label: 'Awareness & Training' },
      { id: 'detectors', label: 'Detectors & Policies' },
      { id: 'organization', label: 'Organization' },
      { id: 'experiments', label: 'Experiments' },
      { id: 'health', label: 'System Health' }
    ];
  };

  const tabs = getTabsForRole(currentRole);

  return (
    <header className="bg-slate-950 border-b border-slate-800 sticky top-0 z-40 select-none font-sans">
      {/* Top Banner: Project Name, Status & Controls */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-2.5 flex items-center justify-between gap-4 border-b border-slate-900">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 flex items-center justify-center shadow-sm">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-base tracking-wider text-slate-100">AEGIS</span>
              <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/60 text-cyan-300 font-semibold tracking-wide">
                Security Gateway
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              AI-Enabled Governance &amp; Information Security &middot; <span className="text-cyan-400 font-medium">Perimeter Defense &amp; Privacy Boundary</span>
            </p>
          </div>
        </div>

        {/* Status Indicators & Role Switcher */}
        <div className="flex items-center space-x-3 text-xs">
          {/* Active Provider Pill */}
          <div className="hidden md:flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">Route:</span>
            <span className="text-slate-200 font-medium">{activeProviderName}</span>
            {isProviderMock && (
              <span className="text-[9px] bg-amber-950/80 text-amber-300 border border-amber-800/60 px-1 py-0.2 rounded uppercase font-mono">
                Simulated
              </span>
            )}
          </div>

          {/* Lockdown Button (Admin only) */}
          {currentRole === 'ADMIN' && (
            <button
              onClick={onToggleLockdown}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all cursor-pointer ${
                systemStatus === 'lockdown'
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/50 shadow-[0_0_10px_rgba(244,63,94,0.3)] animate-pulse'
                  : 'bg-slate-900 hover:bg-slate-800 text-slate-400 border border-slate-800'
              }`}
              title={systemStatus === 'lockdown' ? 'Click to deactivate emergency lockdown' : 'Click to trigger emergency lockdown'}
            >
              {systemStatus === 'lockdown' ? <Lock className="w-3.5 h-3.5 text-rose-400" /> : <Unlock className="w-3.5 h-3.5 text-slate-400" />}
              <span>{systemStatus === 'lockdown' ? 'LOCKDOWN ACTIVE' : 'GATEWAY ACTIVE'}</span>
            </button>
          )}

          {/* Role Switcher */}
          <div className="flex items-center space-x-1.5 bg-slate-900 border border-slate-800 rounded-lg p-1">
            <User className="w-3.5 h-3.5 text-slate-400 ml-1.5" />
            <select
              value={currentRole}
              onChange={(e) => onRoleChange(e.target.value as UserRole)}
              className="bg-transparent text-slate-200 font-medium text-xs focus:outline-none cursor-pointer pr-1 py-0.5"
            >
              <option value="ADMIN" className="bg-slate-900 text-slate-100">Role: ADMIN</option>
              <option value="SECURITY_ANALYST" className="bg-slate-900 text-slate-100">Role: ANALYST</option>
              <option value="USER" className="bg-slate-900 text-slate-100">Role: USER</option>
            </select>
          </div>
        </div>
      </div>

      {/* Navigation Tabs Bar */}
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 flex space-x-1.5 overflow-x-auto scrollbar-none py-2">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onSelectTab(tab.id)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg whitespace-nowrap transition-all flex items-center space-x-1.5 cursor-pointer ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
              }`}
            >
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>
    </header>
  );
};
