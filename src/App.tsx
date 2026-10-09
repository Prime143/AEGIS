import React, { useState, useEffect } from 'react';
import { Navbar } from './components/layout/Navbar';
import { DashboardView } from './components/views/DashboardView';
import { AIConsoleView } from './components/views/AIConsoleView';
import { SecurityEventsView } from './components/views/SecurityEventsView';
import { PoliciesView } from './components/views/PoliciesView';
import { DetectorsView } from './components/views/DetectorsView';
import { ProvidersView } from './components/views/ProvidersView';
import { OrganizationView } from './components/views/OrganizationView';
import { ExperimentsView } from './components/views/ExperimentsView';
import { SystemHealthView } from './components/views/SystemHealthView';
import { AwarenessAdminView } from './components/views/AwarenessAdminView';
import { UserCoachingView } from './components/views/UserCoachingView';

import { LogEvent, EnterpriseRule, DlpPolicy, ApiKey } from '../database';
import { PolicyRule, OrganizationContext, AIProviderMetadata, UserRole, UserAwarenessProfile, TrainingModule } from './core/types';
import { GatewayInteractionResponse } from './core/gateway/GatewayPipeline';

export default function App() {
  const [currentRole, setCurrentRole] = useState<UserRole>('ADMIN');
  const [userEmail, setUserEmail] = useState('admin.soc@nexus-corp.com');
  const [authToken, setAuthToken] = useState('aegis_admin_session_4f9a0c2e');
  const [activeTab, setActiveTab] = useState<string>('dashboard');

  const [systemStatus, setSystemStatus] = useState<'active' | 'lockdown'>('active');
  const [activeProviderId, setActiveProviderId] = useState('provider-safe-mock');
  const [activeProviderName, setActiveProviderName] = useState('Safe Mock Provider (Simulated)');
  const [isProviderMock, setIsProviderMock] = useState(true);

  const [events, setEvents] = useState<LogEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<LogEvent | null>(null);
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [rules, setRules] = useState<EnterpriseRule[]>([]);
  const [providers, setProviders] = useState<AIProviderMetadata[]>([]);
  const [dlpPolicy, setDlpPolicy] = useState<DlpPolicy | null>(null);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [hasUserConsent, setHasUserConsent] = useState(true);
  const [showConsentModal, setShowConsentModal] = useState(false);
  const [organization, setOrganization] = useState<OrganizationContext>({
    organizationName: 'Nexus Defense Systems',
    dataClassifications: [],
    glossary: [],
    sensitiveEntities: [],
    allowedProviders: [],
    retentionDays: 90
  });

  // Human Risk Management & Security Awareness States
  const [awarenessProfiles, setAwarenessProfiles] = useState<UserAwarenessProfile[]>([]);
  const [trainingModules, setTrainingModules] = useState<TrainingModule[]>([]);
  const [currentUserProfile, setCurrentUserProfile] = useState<UserAwarenessProfile | null>(null);

  const [isProcessingPrompt, setIsProcessingPrompt] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 3000);
  };

  const getHeaders = () => ({
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${authToken}`
  });

  // Synchronize state with gateway backend
  const fetchGatewayState = async (tokenOverride?: string, emailOverride?: string, roleOverride?: UserRole) => {
    const effectiveToken = tokenOverride || authToken;
    const effectiveEmail = emailOverride || userEmail;
    const effectiveRole = roleOverride || currentRole;

    try {
      const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${effectiveToken}`
      };

      // 1. Settings
      const settingsRes = await fetch('/api/settings', { headers });
      if (settingsRes.ok) {
        const s = await settingsRes.json();
        setSystemStatus(s.systemStatus || 'active');
      }

      // 2. Providers
      const provRes = await fetch('/api/providers', { headers });
      if (provRes.ok) {
        const pData = await provRes.json();
        setProviders(pData.providers || []);
        setActiveProviderId(pData.activeProviderId || 'provider-safe-mock');
        const activeObj = (pData.providers || []).find((p: any) => p.id === pData.activeProviderId);
        if (activeObj) {
          setActiveProviderName(activeObj.name);
          setIsProviderMock(activeObj.type === 'mock');
        }
      }

      // 3. Policies
      const polRes = await fetch('/api/policies', { headers });
      if (polRes.ok) {
        const polData = await polRes.json();
        setPolicies(polData);
      }

      // 4. Custom Rules
      const rulesRes = await fetch('/api/rules', { headers });
      if (rulesRes.ok) {
        const rData = await rulesRes.json();
        setRules(rData);
      }

      // 5. Organization
      const orgRes = await fetch('/api/organization', { headers });
      if (orgRes.ok) {
        const oData = await orgRes.json();
        setOrganization(oData);
      }

      // 6. DLP Policy Toggles
      const dlpRes = await fetch('/api/dlp', { headers });
      if (dlpRes.ok) {
        const dData = await dlpRes.json();
        setDlpPolicy(dData);
      }

      // 7. Developer API Keys (Admin only)
      if (effectiveRole === 'ADMIN') {
        const keysRes = await fetch('/api/keys', { headers });
        if (keysRes.ok) {
          const kData = await keysRes.json();
          setApiKeys(kData);
        }
      } else {
        setApiKeys([]);
      }

      // 8. User Consent Verification
      const conRes = await fetch(`/api/consent/${encodeURIComponent(effectiveEmail)}`, { headers });
      if (conRes.ok) {
        const cData = await conRes.json();
        setHasUserConsent(!!cData.consented);
      }

      // 9. Security Events / Logs (Protected RBAC)
      if (effectiveRole !== 'USER') {
        const logsRes = await fetch('/api/logs', { headers });
        if (logsRes.ok) {
          const lData = await logsRes.json();
          setEvents(lData);
        }
      } else {
        // Safe DSAR export for standard user role
        const dsarRes = await fetch(`/api/dsar/export?email=${encodeURIComponent(effectiveEmail)}`, { headers });
        if (dsarRes.ok) {
          const dData = await dsarRes.json();
          setEvents(dData.interactions || []);
        }
      }

      // 10. Human Risk Management & Security Awareness Profiles
      try {
        const modRes = await fetch('/api/awareness/modules', { headers });
        if (modRes.ok) {
          const mData = await modRes.json();
          setTrainingModules(mData);
        }

        const profRes = await fetch('/api/awareness/profiles', { headers });
        if (profRes.ok) {
          const pData: UserAwarenessProfile[] = await profRes.json();
          setAwarenessProfiles(pData);
          const myProfile = pData.find(p => p.userEmail === effectiveEmail) || pData[0] || null;
          setCurrentUserProfile(myProfile);
        }
      } catch (awarenessErr) {
        console.error('Awareness sync error:', awarenessErr);
      }
    } catch (e) {
      console.error('Failed to sync gateway state:', e);
    }
  };

  useEffect(() => {
    fetchGatewayState();
    const interval = setInterval(() => fetchGatewayState(), 12000);
    return () => clearInterval(interval);
  }, [authToken, userEmail, currentRole]);

  // Role Switcher & Login
  const handleRoleChange = async (newRole: UserRole) => {
    setCurrentRole(newRole);
    const targetEmail =
      newRole === 'ADMIN' ? 'admin.soc@nexus-corp.com' :
      newRole === 'SECURITY_ANALYST' ? 'analyst@nexus-corp.com' :
      'current.user@nexus-corp.com';
    setUserEmail(targetEmail);

    // Adjust activeTab logically to match role workspace permissions
    const userAllowedTabs = ['console', 'coaching', 'events', 'policies'];
    const analystAllowedTabs = ['dashboard', 'console', 'events', 'awareness', 'policies', 'detectors', 'providers', 'experiments', 'health'];

    if (newRole === 'USER' && !userAllowedTabs.includes(activeTab)) {
      setActiveTab('console');
    } else if (newRole === 'SECURITY_ANALYST' && !analystAllowedTabs.includes(activeTab)) {
      setActiveTab('dashboard');
    }

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: targetEmail, role: newRole })
      });
      if (res.ok) {
        const data = await res.json();
        setAuthToken(data.token);
        showNotification(`Switched role to ${newRole} (${targetEmail})`);
        await fetchGatewayState(data.token, targetEmail, newRole);
      }
    } catch (e) {
      console.error('Role authentication failed:', e);
    }
  };

  // Record Data Privacy Consent
  const handleRecordConsent = async (granted: boolean) => {
    try {
      const res = await fetch('/api/consent', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ email: userEmail, granted })
      });
      if (res.ok) {
        setHasUserConsent(granted);
        setShowConsentModal(false);
        showNotification(granted ? 'Data Privacy & Monitoring Consent Granted' : 'Data Privacy Consent Revoked');
        await fetchGatewayState();
      }
    } catch (e) {
      console.error('Consent recording failed:', e);
    }
  };

  // Update DLP Policy
  const handleUpdateDlpPolicy = async (updated: DlpPolicy) => {
    try {
      const res = await fetch('/api/dlp', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(updated)
      });
      if (res.ok) {
        const data = await res.json();
        setDlpPolicy(data);
        showNotification('DLP Shield policy settings updated');
      }
    } catch (e) {
      console.error('Update DLP failed:', e);
    }
  };

  // Create Developer API Key
  const handleCreateApiKey = async (name: string, role: UserRole) => {
    try {
      const res = await fetch('/api/keys', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ name, role, createdBy: userEmail })
      });
      if (res.ok) {
        showNotification(`Developer API Key generated for ${name}`);
        await fetchGatewayState();
      }
    } catch (e) {
      console.error('Create API Key failed:', e);
    }
  };

  // Revoke Developer API Key
  const handleRevokeApiKey = async (id: string) => {
    if (!window.confirm('Revoke this developer API key immediately?')) return;
    try {
      const res = await fetch(`/api/keys/${id}`, {
        method: 'DELETE',
        headers: getHeaders()
      });
      if (res.ok) {
        showNotification('API key revoked');
        await fetchGatewayState();
      }
    } catch (e) {
      console.error('Revoke API Key failed:', e);
    }
  };

  // Assign Security Training Module
  const handleAssignTraining = async (email: string, moduleId: string) => {
    try {
      const res = await fetch('/api/awareness/assign', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ email, moduleId })
      });
      if (res.ok) {
        showNotification(`Assigned training module ${moduleId} to ${email}`);
        await fetchGatewayState();
      }
    } catch (e) {
      console.error('Assign training failed:', e);
    }
  };

  // Complete Security Training Module
  const handleCompleteTraining = async (email: string, moduleId: string) => {
    try {
      const res = await fetch('/api/awareness/complete', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ email, moduleId })
      });
      if (res.ok) {
        showNotification(`Module ${moduleId} completed! Posture score updated.`);
        await fetchGatewayState();
      }
    } catch (e) {
      console.error('Complete training failed:', e);
    }
  };

  // SOC Incident Override
  const handleOverrideEvent = async (logId: string, overrideReason: string, overrideText?: string) => {
    try {
      const res = await fetch('/api/override', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ logId, overrideReason, overrideText })
      });
      if (res.ok) {
        showNotification(`Incident ${logId} overridden by Administrator`);
        await fetchGatewayState();
        if (selectedEvent && selectedEvent.id === logId) {
          setSelectedEvent({
            ...selectedEvent,
            action: 'MODIFIED',
            override_status: 'OVERRIDDEN',
            override_reason: overrideReason,
            override_timestamp: new Date().toISOString()
          });
        }
      }
    } catch (e) {
      console.error('Override event failed:', e);
    }
  };

  // Toggle Global Lockdown
  const handleToggleLockdown = async () => {
    if (currentRole !== 'ADMIN') return;
    const newStatus = systemStatus === 'lockdown' ? 'active' : 'lockdown';
    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ systemStatus: newStatus })
      });
      if (res.ok) {
        setSystemStatus(newStatus);
        showNotification(newStatus === 'lockdown' ? 'Perimeter Lockdown ACTIVATED' : 'Perimeter Gateway set to ACTIVE');
        await fetchGatewayState();
      }
    } catch (e) {
      console.error('Lockdown update failed:', e);
    }
  };

  // Gateway Prompt Interaction
  const handleSendPrompt = async (prompt: string, providerId?: string): Promise<GatewayInteractionResponse | null> => {
    setIsProcessingPrompt(true);
    try {
      const res = await fetch('/api/gateway/interact', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          prompt,
          providerId: providerId || activeProviderId
        })
      });

      if (res.ok) {
        const result: GatewayInteractionResponse = await res.json();
        await fetchGatewayState();
        return result;
      } else {
        const err = await res.json();
        alert(`Gateway rejected interaction: ${err.error || err.message}`);
        return null;
      }
    } catch (e: any) {
      console.error('Gateway interaction call failed:', e);
      alert(`Network error connecting to Gateway: ${e.message}`);
      return null;
    } finally {
      setIsProcessingPrompt(false);
    }
  };

  // Policy CRUD
  const handleTogglePolicy = async (id: string, enabled: boolean) => {
    try {
      const res = await fetch(`/api/policies/${id}`, {
        method: 'PUT',
        headers: getHeaders(),
        body: JSON.stringify({ enabled })
      });
      if (res.ok) {
        setPolicies(prev => prev.map(p => p.id === id ? { ...p, enabled } : p));
        showNotification(`Policy ${id} ${enabled ? 'activated' : 'disabled'}`);
      }
    } catch (e) {
      console.error('Toggle policy failed:', e);
    }
  };

  const handleAddPolicy = async (newPolicy: PolicyRule) => {
    try {
      const res = await fetch('/api/policies', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(newPolicy)
      });
      if (res.ok) {
        await fetchGatewayState();
        showNotification(`Created policy ${newPolicy.id}`);
      }
    } catch (e) {
      console.error('Create policy failed:', e);
    }
  };

  const handleDeletePolicy = async (id: string) => {
    if (!window.confirm(`Delete policy ${id}?`)) return;
    try {
      const res = await fetch(`/api/policies/${id}`, {
        method: 'DELETE',
        headers: getHeaders()
      });
      if (res.ok) {
        setPolicies(prev => prev.filter(p => p.id !== id));
        showNotification(`Policy ${id} deleted`);
      }
    } catch (e) {
      console.error('Delete policy failed:', e);
    }
  };

  // Custom Rules CRUD
  const handleAddRule = async (newRule: Omit<EnterpriseRule, 'id'>) => {
    try {
      const res = await fetch('/api/rules', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(newRule)
      });
      if (res.ok) {
        await fetchGatewayState();
        showNotification(`Added custom enterprise rule`);
      }
    } catch (e) {
      console.error('Add rule failed:', e);
    }
  };

  const handleDeleteRule = async (id: string) => {
    if (!window.confirm('Delete custom rule?')) return;
    try {
      const res = await fetch(`/api/rules/${id}`, {
        method: 'DELETE',
        headers: getHeaders()
      });
      if (res.ok) {
        setRules(prev => prev.filter(r => r.id !== id));
        showNotification('Rule deleted');
      }
    } catch (e) {
      console.error('Delete rule failed:', e);
    }
  };

  // Provider Activation
  const handleSelectActiveProvider = async (providerId: string) => {
    try {
      const res = await fetch('/api/providers/active', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ providerId })
      });
      if (res.ok) {
        await fetchGatewayState();
        showNotification(`Active route switched to ${providerId}`);
      }
    } catch (e) {
      console.error('Select active provider failed:', e);
    }
  };

  // Update Organization Context
  const handleUpdateOrganization = async (updated: Partial<OrganizationContext>) => {
    try {
      const res = await fetch('/api/organization', {
        method: 'PUT',
        headers: getHeaders(),
        body: JSON.stringify(updated)
      });
      if (res.ok) {
        const data = await res.json();
        setOrganization(data);
        showNotification('Organization security context updated');
      }
    } catch (e) {
      console.error('Update organization context failed:', e);
    }
  };

  // Export Audit Logs (DSAR)
  const handleExportEvents = () => {
    const jsonStr = JSON.stringify(events, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-audit-events-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Toast Notification */}
      {notification && (
        <div className="fixed bottom-4 right-4 z-50 px-4 py-2 rounded-lg bg-cyan-950 border border-cyan-500/50 text-cyan-200 font-mono text-xs shadow-2xl animate-fade-in flex items-center space-x-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          <span>{notification}</span>
        </div>
      )}

      {/* Navigation Header */}
      <Navbar
        currentRole={currentRole}
        userEmail={userEmail}
        onRoleChange={handleRoleChange}
        systemStatus={systemStatus}
        onToggleLockdown={handleToggleLockdown}
        activeProviderName={activeProviderName}
        isProviderMock={isProviderMock}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
      />

      {/* Main Content View Switcher */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        {activeTab === 'dashboard' && (
          <DashboardView
            events={events}
            policies={policies}
            activeProviderName={activeProviderName}
            isProviderMock={isProviderMock}
            onNavigateToConsole={() => setActiveTab('console')}
            onNavigateToEvents={() => setActiveTab('events')}
            onSelectEvent={(evt) => {
              setSelectedEvent(evt);
              setActiveTab('events');
            }}
          />
        )}

        {activeTab === 'console' && (
          <AIConsoleView
            onSendPrompt={handleSendPrompt}
            isProcessing={isProcessingPrompt}
            activeProviderId={activeProviderId}
            activeProviderName={activeProviderName}
            isProviderMock={isProviderMock}
            userEmail={userEmail}
            hasConsent={hasUserConsent}
            onRequestConsent={() => setShowConsentModal(true)}
          />
        )}

        {activeTab === 'events' && (
          <SecurityEventsView
            events={events}
            selectedEvent={selectedEvent}
            onSelectEvent={setSelectedEvent}
            onExportEvents={handleExportEvents}
            userRole={currentRole}
            onOverrideEvent={handleOverrideEvent}
          />
        )}

        {activeTab === 'policies' && (
          <PoliciesView
            policies={policies}
            onTogglePolicy={handleTogglePolicy}
            onAddPolicy={handleAddPolicy}
            onDeletePolicy={handleDeletePolicy}
            userRole={currentRole}
            dlpPolicy={dlpPolicy}
            onUpdateDlpPolicy={handleUpdateDlpPolicy}
          />
        )}

        {activeTab === 'detectors' && (
          <DetectorsView
            rules={rules}
            onAddRule={handleAddRule}
            onDeleteRule={handleDeleteRule}
            userRole={currentRole}
          />
        )}

        {activeTab === 'providers' && (
          <ProvidersView
            providers={providers}
            activeProviderId={activeProviderId}
            onSelectActiveProvider={handleSelectActiveProvider}
            userRole={currentRole}
            authToken={authToken}
          />
        )}

        {activeTab === 'organization' && (
          <OrganizationView
            organization={organization}
            onUpdateOrganization={handleUpdateOrganization}
            userRole={currentRole}
            apiKeys={apiKeys}
            onCreateApiKey={handleCreateApiKey}
            onRevokeApiKey={handleRevokeApiKey}
          />
        )}

        {activeTab === 'experiments' && (
          <ExperimentsView
            authToken={authToken}
            userRole={currentRole}
          />
        )}

        {activeTab === 'health' && (
          <SystemHealthView />
        )}

        {activeTab === 'awareness' && (
          <AwarenessAdminView
            profiles={awarenessProfiles}
            modules={trainingModules}
            onAssignTraining={handleAssignTraining}
            onCompleteTraining={handleCompleteTraining}
            userRole={currentRole}
            authToken={authToken}
            onRefresh={() => fetchGatewayState()}
          />
        )}

        {activeTab === 'coaching' && (
          <UserCoachingView
            profile={currentUserProfile}
            onCompleteModule={handleCompleteTraining}
            userEmail={userEmail}
            allProfiles={awarenessProfiles.filter(p => p.accountType === 'HUMAN_EMPLOYEE')}
            onSelectProfile={(p) => setCurrentUserProfile(p)}
          />
        )}
      </main>

      {/* GDPR / DPDP Privacy & Monitoring Consent Modal */}
      {showConsentModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 font-mono text-xs space-y-4 shadow-2xl">
            <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
              <h3 className="text-sm font-bold text-slate-100">
                DATA PRIVACY &amp; SECURITY MONITORING CONSENT (GDPR / DPDP)
              </h3>
            </div>

            <div className="space-y-2 text-slate-300 leading-relaxed text-[11px]">
              <p>
                In compliance with the corporate security standard and international data protection regulations (GDPR / DPDP):
              </p>
              <ul className="list-disc pl-5 space-y-1 text-slate-400">
                <li>Prompts submitted to external AI models are inspected for sensitive data, credentials, and PII.</li>
                <li>Raw plaintext secrets are never stored. Only sanitized representations and cryptographic SHA-256 hashes are recorded for audit compliance.</li>
                <li>You may grant or revoke your consent at any time. Revoking consent will suspend outbound AI gateway transmission for your account.</li>
              </ul>
              <div className="p-2 rounded bg-slate-950 border border-slate-800 text-[10px] text-cyan-300">
                Identity Target: <strong>{userEmail}</strong> &middot; Role: <strong>{currentRole}</strong>
              </div>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-slate-800">
              <button
                onClick={() => handleRecordConsent(false)}
                className="px-3 py-1.5 rounded-lg bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-rose-300 font-bold transition-colors cursor-pointer"
              >
                Withdraw / Decline
              </button>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setShowConsentModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  onClick={() => handleRecordConsent(true)}
                  className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold shadow-[0_0_12px_rgba(6,182,212,0.3)] transition-colors cursor-pointer"
                >
                  Review &amp; Accept Consent
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Persistent Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-3 text-center text-[11px] font-mono text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row justify-between items-center gap-2">
          <span>AEGIS Gateway Engine &middot; Active Perimeter Boundary Firewall</span>
          <span>SHA-256 Hashing Enforced &middot; Zero Plaintext Secret Retention</span>
        </div>
      </footer>
    </div>
  );
}
