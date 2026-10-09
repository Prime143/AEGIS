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
  const tabs = [
    { id: 'dashboard', label: 'SOC Dashboard' },
    { id: 'console', label: 'AI Console' },
    { id: 'events', label: 'Security Events' },
    { id: 'policies', label: 'Policies' },
    { id: 'detectors', label: 'Detectors' },
    { id: 'providers', label: 'AI Providers' },
    { id: 'organization', label: 'Organization' },
    { id: 'experiments', label: 'Experiments' },
    { id: 'health', label: 'System Health' }
  ];

  return (
    <header className="bg-slate-950 border-b border-slate-800 sticky top-0 z-40 select-none">
      {/* Top Banner: Project Name, Tagline & Controls */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-2.5 flex items-center justify-between gap-4 border-b border-slate-900">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.2)]">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-extrabold text-base tracking-wider text-slate-100 font-mono">AEGIS</span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/60 text-cyan-300 font-semibold tracking-wide">
                PROTOTYPE GATEWAY
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono tracking-tight hidden sm:block">
              AI-Enabled Governance & Information Security &middot; <span className="text-cyan-400 font-medium">SECURE THE BOUNDARY. GOVERN THE INTELLIGENCE.</span>
            </p>
          </div>
        </div>

        {/* Status Indicators & Role Switcher */}
        <div className="flex items-center space-x-3 text-xs font-mono">
          {/* Active Provider Pill */}
          <div className="hidden md:flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">Provider:</span>
            <span className="text-slate-200 font-medium">{activeProviderName}</span>
            {isProviderMock && (
              <span className="text-[9px] bg-amber-950/80 text-amber-300 border border-amber-800/60 px-1 rounded uppercase">
                Simulated
              </span>
            )}
          </div>

          {/* Lockdown Button (Admin only) */}
          {currentRole === 'ADMIN' && (
            <button
              onClick={onToggleLockdown}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded font-semibold transition-all ${
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
          <div className="flex items-center space-x-1.5 bg-slate-900/90 border border-slate-800 rounded-lg p-1">
            <User className="w-3.5 h-3.5 text-slate-400 ml-1" />
            <select
              value={currentRole}
              onChange={(e) => onRoleChange(e.target.value as UserRole)}
              className="bg-transparent text-slate-200 font-medium text-xs focus:outline-none cursor-pointer pr-1"
            >
              <option value="ADMIN" className="bg-slate-900 text-slate-100">Role: ADMIN</option>
              <option value="SECURITY_ANALYST" className="bg-slate-900 text-slate-100">Role: ANALYST</option>
              <option value="USER" className="bg-slate-900 text-slate-100">Role: USER</option>
            </select>
          </div>
        </div>
      </div>

      {/* Navigation Tabs Bar */}
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 flex space-x-1 overflow-x-auto scrollbar-none py-1.5">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onSelectTab(tab.id)}
              className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md whitespace-nowrap transition-all flex items-center space-x-1.5 ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-[0_0_10px_rgba(6,182,212,0.15)] font-semibold'
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
