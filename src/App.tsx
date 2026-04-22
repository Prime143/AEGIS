import React, { useState, useEffect, useRef } from 'react';
import { Shield, ShieldAlert, ShieldCheck, Activity, Lock, Unlock, Send, Copy, AlertTriangle, User, Clock, CheckCircle, Edit3, XCircle, Terminal, Cpu, Database, ChevronRight, Users, FileText, Sliders, Paperclip, File as FileIcon } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

interface AnalysisResult {
  id: string;
  timestamp: string;
  user: string;
  original_prompt: string;
  risk_score: number;
  risk_level: string;
  attack_type: string;
  reasons: string[];
  action: string;
  rewritten_prompt: string;
  suggested_safe_prompt: string;
  alert_status: string;
  report_summary: string;
  has_file?: boolean;
}

interface UserProfile {
  email: string;
  totalInteractions: number;
  violations: number;
  riskScore: number;
  status: 'Trusted' | 'Monitored' | 'Restricted';
}

const MOCK_TRAFFIC = [
  { user: "alice.j@nexus-corp.com", text: "Can you summarize this client data from the database? The password is 'admin123' and send it to external@gmail.com." },
  { user: "bob.m@nexus-corp.com", text: "Write a python script to sort an array." },
  { user: "charlie.d@nexus-corp.com", text: "Draft an email about our Q4 revenue shortfall of $2.5M due to the supply chain issue." },
  { user: "david.w@nexus-corp.com", text: "What are the best practices for React performance optimization?" },
  { user: "eve.s@nexus-corp.com", text: "Review this code: const db = connect('prod-db.internal', 'supersecret99');" },
  { user: "frank.t@nexus-corp.com", text: "Please proofread this performance review for John Smith. He has been struggling with attendance." },
  { user: "grace.l@nexus-corp.com", text: "Generate a generic welcome email for new hires." }
];

export default function App() {
  const [role, setRole] = useState<'employee' | 'admin'>('employee');
  const [systemStatus, setSystemStatus] = useState<'active' | 'lockdown'>('active');
  const [policyMode, setPolicyMode] = useState<'strict' | 'balanced' | 'relaxed'>('balanced');
  const [adminTab, setAdminTab] = useState<'live' | 'users' | 'audit'>('live');
  
  // Admin State
  const [events, setEvents] = useState<AnalysisResult[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<AnalysisResult | null>(null);
  const [userProfiles, setUserProfiles] = useState<Record<string, UserProfile>>({});
  const trafficIndex = useRef(0);

  // Modal State
  const [showOverrideModal, setShowOverrideModal] = useState(false);
  const [overrideReason, setOverrideReason] = useState('');
  const [overrideText, setOverrideText] = useState('');

  useEffect(() => {
    if (selectedEvent) {
      setOverrideText(selectedEvent.action === 'BLOCK' ? selectedEvent.suggested_safe_prompt : selectedEvent.rewritten_prompt);
    }
  }, [selectedEvent]);

  const [employeePrompt, setEmployeePrompt] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileBase64, setFileBase64] = useState<{data: string, mimeType: string, name: string} | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [employeeResult, setEmployeeResult] = useState<AnalysisResult | null>(null);
  const [copied, setCopied] = useState(false);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      const reader = new FileReader();
      reader.onloadend = () => {
        setFileBase64({
          data: reader.result as string,
          mimeType: file.type,
          name: file.name
        });
      };
      reader.readAsDataURL(file);
    }
  };

  const removeFile = () => {
    setSelectedFile(null);
    setFileBase64(null);
  };

  // Simulate live traffic for Admin
  useEffect(() => {
    if (systemStatus === 'lockdown') return;

    const interval = setInterval(() => {
      const traffic = MOCK_TRAFFIC[trafficIndex.current % MOCK_TRAFFIC.length];
      trafficIndex.current += 1;
      analyzeTraffic(traffic.text, traffic.user, true);
    }, 8000);

    if (events.length === 0) {
      analyzeTraffic(MOCK_TRAFFIC[0].text, MOCK_TRAFFIC[0].user, true);
      trafficIndex.current += 1;
    }

    return () => clearInterval(interval);
  }, [systemStatus, events.length, policyMode]);

  const analyzeTraffic = async (text: string, user: string, isBackground = false, fileData: any = null) => {
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, user, policyMode, file: fileData }),
      });
      
      if (response.ok) {
        const data = await response.json();
        const newEvent = { ...data, id: Date.now().toString(), timestamp: new Date().toISOString(), has_file: !!fileData };
        
        setEvents(prev => [newEvent, ...prev].slice(0, 500)); // Keep up to 500 for audit log
        
        // Update User Profiles
        setUserProfiles(prev => {
          const profile = prev[user] || { email: user, totalInteractions: 0, violations: 0, riskScore: 0, status: 'Trusted' };
          const newInteractions = profile.totalInteractions + 1;
          const newViolations = profile.violations + (newEvent.action !== 'ALLOW' ? 1 : 0);
          const newRiskScore = Math.round(((profile.riskScore * profile.totalInteractions) + newEvent.risk_score) / newInteractions);
          
          let status: 'Trusted' | 'Monitored' | 'Restricted' = 'Trusted';
          if (newRiskScore >= 50 || newViolations >= 3) status = 'Restricted';
          else if (newRiskScore >= 20 || newViolations >= 1) status = 'Monitored';

          return { ...prev, [user]: { ...profile, totalInteractions: newInteractions, violations: newViolations, riskScore: newRiskScore, status } };
        });

        if (!isBackground) {
          setEmployeeResult(newEvent);
        } else if (!selectedEvent && role === 'admin' && adminTab === 'live') {
          setSelectedEvent(newEvent);
        }
      }
    } catch (error) {
      console.error('Error analyzing traffic:', error);
    }
  };

  const handleEmployeeSubmit = async () => {
    if ((!employeePrompt.trim() && !fileBase64) || systemStatus === 'lockdown') return;
    setIsAnalyzing(true);
    await analyzeTraffic(employeePrompt || "Please analyze the attached document.", 'current.user@nexus-corp.com', false, fileBase64);
    setIsAnalyzing(false);
  };
  
  const renderHighlightedText = (text: string) => {
    if (!text) return null;
    const parts = text.split(/(\[REDACTED_[^\]]+\])/g);
    return parts.map((part, idx) => {
      if (part.startsWith('[REDACTED_')) {
        return (
          <span key={idx} className="inline-block bg-amber-500/20 text-amber-300 font-bold px-1.5 py-0.5 rounded border border-amber-500/40 shadow-[0_0_10px_rgba(245,158,11,0.2)] mx-1">
            {part}
          </span>
        );
      }
      return <span key={idx}>{part}</span>;
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getActionColor = (action: string) => {
    switch (action) {
      case 'BLOCK': return 'text-rose-400 border-rose-500/30 bg-rose-500/10';
      case 'MODIFIED': return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
      case 'ALLOW': return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
      default: return 'text-slate-400 border-slate-500/30 bg-slate-500/10';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Restricted': return 'text-rose-400 border-rose-500/30 bg-rose-500/10';
      case 'Monitored': return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
      case 'Trusted': return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
      default: return 'text-slate-400 border-slate-500/30 bg-slate-500/10';
    }
  };

  return (
    <div className="min-h-screen text-slate-300 font-sans selection:bg-cyan-500/30 relative overflow-hidden flex flex-col">
      {/* Background Effects */}
      <div className="absolute inset-0 bg-grid-pattern opacity-30 pointer-events-none" />
      <div className="absolute top-[-10%] left-1/2 -translate-x-1/2 w-[1200px] h-[600px] bg-gradient-to-r from-cyan-500/15 via-blue-600/15 to-purple-600/15 blur-[120px] rounded-full pointer-events-none" />
      
      {/* Global Header */}
      <header className="relative z-10 glass-panel mx-4 md:mx-6 mt-4 rounded-2xl border-white/5 px-4 md:px-6 py-4 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center space-x-4">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-400 to-blue-600 shadow-[0_0_20px_rgba(6,182,212,0.5)] shrink-0 border border-white/10">
            <Shield className="w-5 h-5 text-white drop-shadow-md" />
          </div>
          <div className="text-center sm:text-left">
            <h1 className="text-base md:text-lg font-bold text-white tracking-wide flex items-center justify-center sm:justify-start">
              AEGIS <span className="text-cyan-400 mx-2">|</span> AI Governance
            </h1>
            <p className="text-[10px] md:text-xs text-slate-400 uppercase tracking-widest font-semibold">Enterprise Security Hub</p>
          </div>
        </div>

        <div className="flex items-center space-x-4 md:space-x-6 w-full sm:w-auto justify-center">
          {/* Role Switcher */}
          <div className="flex bg-slate-900/80 p-1 rounded-lg border border-slate-700/50 w-full sm:w-auto">
            <button
              onClick={() => setRole('employee')}
              className={`flex-1 sm:flex-none px-3 md:px-4 py-1.5 text-[10px] md:text-xs font-bold uppercase tracking-wider rounded-md transition-all ${role === 'employee' ? 'bg-cyan-500/20 text-cyan-300 shadow-[0_0_10px_rgba(6,182,212,0.2)]' : 'text-slate-500 hover:text-slate-300'}`}
            >
              Workspace
            </button>
            <button
              onClick={() => setRole('admin')}
              className={`flex-1 sm:flex-none px-3 md:px-4 py-1.5 text-[10px] md:text-xs font-bold uppercase tracking-wider rounded-md transition-all ${role === 'admin' ? 'bg-rose-500/20 text-rose-300 shadow-[0_0_10px_rgba(244,63,94,0.2)]' : 'text-slate-500 hover:text-slate-300'}`}
            >
              SOC Admin
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 relative z-10 flex overflow-hidden">
        <AnimatePresence mode="wait">
          {role === 'employee' ? (
            <motion.div 
              key="employee"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="flex-1 overflow-y-auto custom-scrollbar p-6 md:p-12"
            >
              <div className="max-w-5xl mx-auto space-y-8">
                <div className="text-center space-y-4 mb-12 relative">
                  <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[300px] h-[100px] bg-cyan-500/20 blur-[60px] rounded-full pointer-events-none" />
                  <h2 className="text-4xl md:text-5xl font-black text-white tracking-tight leading-tight relative z-10">
                    Proactive Prompt <br className="md:hidden" /><span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-400 to-indigo-400 drop-shadow-[0_0_15px_rgba(56,189,248,0.4)]">Sanitization</span>
                  </h2>
                  <p className="text-slate-400 max-w-2xl mx-auto text-sm md:text-base relative z-10 font-medium leading-relaxed">
                    Before sending sensitive queries to external AI tools, use Aegis to automatically redact PII, financial data, and internal secrets while preserving your intent.
                  </p>
                </div>

                {systemStatus === 'lockdown' && (
                  <div className="bg-rose-500/10 border border-rose-500/50 rounded-2xl p-6 flex items-center justify-center text-rose-400 shadow-[0_0_30px_rgba(244,63,94,0.15)]">
                    <Lock className="w-8 h-8 mr-4 animate-pulse" />
                    <div>
                      <h3 className="text-lg font-bold uppercase tracking-wider">Global AI Gateway Lockdown</h3>
                      <p className="text-sm opacity-80">Security Operations has temporarily suspended all external AI interactions.</p>
                    </div>
                  </div>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                  {/* Input Area */}
                  <div className="glass-panel rounded-2xl p-4 md:p-6 flex flex-col h-[400px] md:h-[500px]">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-sm font-bold uppercase tracking-wider text-cyan-400 flex items-center">
                        <Terminal className="w-4 h-4 mr-2" /> Draft Prompt
                      </h3>
                    </div>
                    <div className="relative flex-1 flex flex-col">
                      <textarea
                        className="flex-1 w-full bg-slate-900/50 border border-slate-700/50 rounded-xl p-4 text-slate-200 font-mono text-sm focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500/50 resize-none custom-scrollbar transition-all"
                        placeholder="Enter your draft prompt here. Aegis will analyze it for risks..."
                        value={employeePrompt}
                        onChange={(e) => setEmployeePrompt(e.target.value)}
                        disabled={systemStatus === 'lockdown'}
                      />
                      
                      {/* Attachment Bar */}
                      <div className="absolute bottom-4 left-4 right-4 flex items-center justify-between">
                        {selectedFile ? (
                          <div className="flex items-center space-x-2 bg-slate-800/80 p-2 rounded-lg border border-slate-700/50 max-w-[80%]">
                            <FileIcon className="w-4 h-4 text-cyan-400 shrink-0" />
                            <span className="text-xs text-slate-300 truncate">{selectedFile.name}</span>
                            <button onClick={removeFile} className="text-slate-400 hover:text-rose-400 ml-2">
                              <XCircle className="w-4 h-4" />
                            </button>
                          </div>
                        ) : (
                          <div />
                        )}
                        <button
                          onClick={() => document.getElementById('file-upload')?.click()}
                          className="p-2.5 bg-slate-800/80 hover:bg-slate-700 hover:text-cyan-400 rounded-lg text-slate-400 border border-slate-700/50 transition-all ml-auto focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
                          title="Attach Document for Redaction"
                          disabled={systemStatus === 'lockdown'}
                        >
                          <Paperclip className="w-5 h-5" />
                        </button>
                        <input id="file-upload" type="file" className="hidden" accept="image/*,application/pdf" onChange={handleFileChange} />
                      </div>
                    </div>
                    <button
                      onClick={handleEmployeeSubmit}
                      disabled={isAnalyzing || !employeePrompt.trim() || systemStatus === 'lockdown'}
                      className="mt-6 w-full glass-button text-cyan-50 font-bold py-4 px-6 rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center relative overflow-hidden group"
                    >
                      <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/20 to-blue-500/20 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />
                      {isAnalyzing ? (
                        <><Activity className="w-5 h-5 mr-2 animate-spin" /> Analyzing Context...</>
                      ) : (
                        <><ShieldCheck className="w-5 h-5 mr-2" /> Sanitize & Validate</>
                      )}
                    </button>
                  </div>

                  {/* Output Area */}
                  <div className="glass-panel rounded-2xl p-4 md:p-6 flex flex-col h-[400px] md:h-[500px]">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-sm font-bold uppercase tracking-wider text-emerald-400 flex items-center">
                        <Cpu className="w-4 h-4 mr-2" /> Safe Payload
                      </h3>
                      {employeeResult && (
                        <span className={`text-xs font-bold px-3 py-1 rounded-full border ${getActionColor(employeeResult.action)}`}>
                          {employeeResult.action}
                        </span>
                      )}
                    </div>

                    {employeeResult ? (
                      <div className="flex flex-col h-full space-y-4">
                        {employeeResult.action === 'BLOCK' ? (
                          <div className="flex-1 flex flex-col items-center justify-center bg-rose-500/5 border border-rose-500/20 rounded-xl p-6 text-center">
                            <ShieldAlert className="w-12 h-12 text-rose-500 mb-4 opacity-80" />
                            <h4 className="text-lg font-bold text-rose-400 mb-2">Request Blocked</h4>
                            <p className="text-sm text-rose-300/80">{employeeResult.suggested_safe_prompt}</p>
                          </div>
                        ) : (
                          <>
                            <div className="flex-1 relative group">
                              <div className="absolute inset-0 bg-slate-900/50 border border-emerald-500/30 rounded-xl p-4 overflow-y-auto custom-scrollbar font-mono text-sm text-emerald-300/90 shadow-[inset_0_0_20px_rgba(16,185,129,0.05)] whitespace-pre-wrap leading-relaxed">
                                {renderHighlightedText(employeeResult.rewritten_prompt)}
                              </div>
                              <button
                                onClick={() => copyToClipboard(employeeResult.rewritten_prompt)}
                                className="absolute top-3 right-3 p-2 bg-slate-800/80 hover:bg-slate-700 rounded-lg border border-slate-600 text-slate-300 transition-colors backdrop-blur-sm opacity-0 group-hover:opacity-100"
                                title="Copy Safe Prompt"
                              >
                                {copied ? <CheckCircle className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                              </button>
                            </div>
                            
                            {employeeResult.action === 'MODIFIED' && (
                              <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 shrink-0">
                                <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400 mb-2 flex items-center">
                                  <AlertTriangle className="w-4 h-4 mr-1.5" /> Aegis Intervention
                                </h4>
                                <p className="text-sm text-amber-200/80">{employeeResult.suggested_safe_prompt}</p>
                              </div>
                            )}
                          </>
                        )}
                      </div>
                    ) : (
                      <div className="flex-1 flex flex-col items-center justify-center text-slate-600 border-2 border-dashed border-slate-800 rounded-xl">
                        <Database className="w-12 h-12 mb-4 opacity-20" />
                        <p className="text-sm font-medium">Awaiting Input</p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </motion.div>
          ) : (
            <motion.div 
              key="admin"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="flex-1 flex flex-col md:flex-row overflow-hidden"
            >
              {/* Admin Slim Sidebar */}
              <div className="w-full md:w-20 h-16 md:h-auto glass-panel border-y border-x-0 md:border-y-0 md:border-l-0 md:border-r border-slate-800/50 flex flex-row md:flex-col items-center justify-center md:justify-start md:pt-8 md:pb-6 space-x-6 md:space-x-0 md:space-y-6 z-30 order-last md:order-first shrink-0">
                <button 
                  onClick={() => setAdminTab('live')} 
                  className={`p-3 rounded-xl transition-all ${adminTab === 'live' ? 'bg-cyan-500/20 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.3)]' : 'text-slate-500 hover:text-slate-300'}`} 
                  title="Live Feed"
                >
                  <Activity className="w-5 h-5 md:w-6 md:h-6" />
                </button>
                <button 
                  onClick={() => setAdminTab('users')} 
                  className={`p-3 rounded-xl transition-all ${adminTab === 'users' ? 'bg-cyan-500/20 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.3)]' : 'text-slate-500 hover:text-slate-300'}`} 
                  title="User Risk Profiles"
                >
                  <Users className="w-5 h-5 md:w-6 md:h-6" />
                </button>
                <button 
                  onClick={() => setAdminTab('audit')} 
                  className={`p-3 rounded-xl transition-all ${adminTab === 'audit' ? 'bg-cyan-500/20 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.3)]' : 'text-slate-500 hover:text-slate-300'}`} 
                  title="Audit Logs"
                >
                  <FileText className="w-5 h-5 md:w-6 md:h-6" />
                </button>
              </div>

              {/* Admin Main Area */}
              <div className="flex-1 flex flex-col overflow-hidden relative">
                
                {/* Global Controls Bar */}
                <div className="sticky top-0 z-30 glass-panel border-x-0 border-t-0 border-b border-slate-800/50 p-4 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-950/80">
                  <div className="flex items-center text-sm font-bold text-slate-300 uppercase tracking-wider">
                    {adminTab === 'live' && <><Activity className="w-4 h-4 mr-2 text-cyan-400 shrink-0" /> SOC Command Center</>}
                    {adminTab === 'users' && <><Users className="w-4 h-4 mr-2 text-cyan-400 shrink-0" /> User Risk Directory</>}
                    {adminTab === 'audit' && <><FileText className="w-4 h-4 mr-2 text-cyan-400 shrink-0" /> Historical Audit Trails</>}
                  </div>
                  
                  <div className="flex flex-col sm:flex-row items-stretch sm:items-center space-y-3 sm:space-y-0 sm:space-x-4 w-full md:w-auto">
                    {/* Policy Mode Selector */}
                    <div className="flex items-center justify-center bg-slate-900/80 p-1 rounded-lg border border-slate-700/50">
                      <Sliders className="w-4 h-4 text-slate-500 ml-2 mr-2 shrink-0" />
                      {(['strict', 'balanced', 'relaxed'] as const).map(mode => (
                        <button
                          key={mode}
                          onClick={() => setPolicyMode(mode)}
                          className={`flex-1 sm:flex-none px-2 md:px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider rounded-md transition-all ${policyMode === mode ? 'bg-indigo-500/20 text-indigo-300 shadow-[0_0_10px_rgba(99,102,241,0.2)]' : 'text-slate-500 hover:text-slate-300'}`}
                        >
                          {mode}
                        </button>
                      ))}
                    </div>

                    <button
                      onClick={() => setSystemStatus(prev => prev === 'active' ? 'lockdown' : 'active')}
                      className={`px-4 md:px-6 py-2 rounded-lg font-bold text-[10px] md:text-xs uppercase tracking-widest transition-all flex items-center justify-center shadow-lg ${
                        systemStatus === 'active' 
                          ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-500/20' 
                          : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-500/20'
                      }`}
                    >
                      {systemStatus === 'active' ? (
                        <><Lock className="w-4 h-4 mr-2 shrink-0" /> Initiate Global Lockdown</>
                      ) : (
                        <><Unlock className="w-4 h-4 mr-2 shrink-0" /> Restore Gateway Access</>
                      )}
                    </button>
                  </div>
                </div>

                {/* Tab Contents */}
                <div className="flex-1 overflow-y-auto custom-scrollbar flex flex-col md:flex-row">
                  {adminTab === 'live' && (
                    <>
                      {/* Live Feed List */}
                      <div className="w-full md:w-[400px] h-64 md:h-auto shrink-0 border-b md:border-b-0 md:border-r border-slate-800/50 flex flex-col bg-slate-900/20">
                        <div className="p-4 border-b border-slate-800/50 flex items-center justify-between bg-slate-900/30">
                          <div>
                            <h2 className="text-sm font-bold text-white uppercase tracking-wider">Live Intercepts</h2>
                            <div className="flex items-center text-xs text-slate-400 mt-1">
                              <span className={`w-2 h-2 rounded-full mr-2 ${systemStatus === 'active' ? 'bg-emerald-500 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.6)]' : 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]'}`}></span>
                              {systemStatus === 'active' ? 'Monitoring Active' : 'System Locked Down'}
                            </div>
                          </div>
                        </div>
                        <div className="flex-1 overflow-y-auto p-3 space-y-3 custom-scrollbar">
                          {/* Demo Injector */}
                          <div className="p-3 mb-2 rounded-xl bg-slate-900/40 border border-slate-800 flex items-center gap-2">
                            <form 
                              className="w-full flex gap-2"
                              onSubmit={(e) => {
                                e.preventDefault();
                                const form = e.target as HTMLFormElement;
                                const input = form.elements.namedItem('demoPrompt') as HTMLInputElement;
                                if (input.value.trim()) {
                                  analyzeTraffic(input.value.trim(), 'demo.user@nexus-corp.com', true);
                                  input.value = '';
                                }
                              }}
                            >
                              <input 
                                name="demoPrompt" 
                                type="text" 
                                placeholder="Inject custom prompt for demo..." 
                                className="flex-1 bg-slate-950 border border-slate-700/50 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50" 
                              />
                              <button type="submit" className="bg-slate-800 hover:bg-slate-700 text-cyan-400 px-3 py-2 rounded-lg border border-slate-700/50 transition-colors">
                                <Send className="w-4 h-4" />
                              </button>
                            </form>
                          </div>
                          {events.slice(0, 8).map((event) => (
                            <div 
                              key={event.id}
                              onClick={() => setSelectedEvent(event)}
                              className={`p-4 rounded-xl border cursor-pointer transition-all duration-300 ${
                                selectedEvent?.id === event.id 
                                  ? 'bg-slate-800/80 border-cyan-500/50 shadow-[0_0_20px_rgba(6,182,212,0.15)]' 
                                  : 'bg-slate-900/40 border-slate-800 hover:border-slate-700 hover:bg-slate-800/40'
                              }`}
                            >
                              <div className="flex justify-between items-start mb-3">
                                <div className="flex items-center text-xs font-medium text-slate-300">
                                  <User className="w-3.5 h-3.5 mr-1.5 text-slate-500" />
                                  <span className="truncate max-w-[140px]">{event.user.split('@')[0]}</span>
                                </div>
                                <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border flex items-center ${getActionColor(event.action)}`}>
                                  {event.action}
                                </span>
                              </div>
                              <p className="text-sm text-slate-400 line-clamp-2 font-mono bg-slate-950/50 p-2.5 rounded-lg border border-slate-800/50">
                                {event.original_prompt}
                              </p>
                              <div className="flex justify-between items-center mt-3 text-[10px] text-slate-500 font-medium">
                                <span className="flex items-center">
                                  <Clock className="w-3 h-3 mr-1" />
                                  {new Date(event.timestamp).toLocaleTimeString()}
                                  {event.has_file && <Paperclip className="w-3 h-3 ml-2 text-cyan-500" title="Contained Document Attachment" />}
                                </span>
                                {event.risk_score > 0 && (
                                  <span className={`font-mono px-2 py-0.5 rounded bg-slate-900 border ${event.risk_score >= 71 ? 'text-rose-400 border-rose-500/20' : 'text-amber-400 border-amber-500/20'}`}>
                                    Risk: {event.risk_score}
                                  </span>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                        <div className="p-3 border-t border-slate-800/50 bg-slate-900/50 text-center shrink-0">
                          <button onClick={() => setAdminTab('audit')} className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center justify-center w-full">
                            View Full History ({events.length} records) <ChevronRight className="w-3 h-3 ml-1" />
                          </button>
                        </div>
                      </div>

                      {/* Live Feed Details */}
                      <div className="flex-1 overflow-y-auto custom-scrollbar">
                        {selectedEvent ? (
                          <div className="p-8 space-y-8 max-w-5xl mx-auto w-full">
                            {/* Header Metrics */}
                            <div className="grid grid-cols-3 gap-6">
                              <div className="glass-panel p-6 rounded-2xl flex flex-col justify-center relative overflow-hidden">
                                <div className={`absolute top-0 left-0 w-1 h-full ${selectedEvent.risk_score >= 71 ? 'bg-rose-500' : selectedEvent.risk_score >= 21 ? 'bg-amber-500' : 'bg-emerald-500'}`} />
                                <span className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">Risk Score</span>
                                <div className={`text-5xl font-black font-mono tracking-tighter ${
                                  selectedEvent.risk_score >= 71 ? 'text-rose-500' : 
                                  selectedEvent.risk_score >= 21 ? 'text-amber-500' : 'text-emerald-500'
                                }`}>
                                  {selectedEvent.risk_score}
                                </div>
                              </div>
                              
                              <div className="glass-panel p-6 rounded-2xl flex flex-col justify-center">
                                <span className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">Action Executed</span>
                                <div className="mt-1">
                                  <span className={`inline-flex items-center px-4 py-1.5 rounded-lg text-sm font-bold tracking-wide border ${getActionColor(selectedEvent.action)}`}>
                                    {selectedEvent.action}
                                  </span>
                                </div>
                              </div>

                              <div className="glass-panel p-6 rounded-2xl flex flex-col justify-center">
                                <span className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">User Identity</span>
                                <div className="text-lg font-medium text-slate-200 flex items-center">
                                  <User className="w-5 h-5 mr-2 text-cyan-500" />
                                  {selectedEvent.user}
                                </div>
                              </div>
                            </div>

                            {/* Deep Analysis */}
                            <div className="glass-panel rounded-2xl p-6">
                              <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-6 flex items-center">
                                <Activity className="w-4 h-4 mr-2" /> Contextual Analysis Engine
                              </h3>
                              <div className="grid grid-cols-2 gap-8">
                                <div>
                                  <div className="text-sm text-slate-400 mb-1">Detected Threat Vector</div>
                                  <div className="text-lg font-medium text-slate-200 mb-4">{selectedEvent.attack_type}</div>
                                  
                                  {selectedEvent.reasons.length > 0 && (
                                    <div className="space-y-2">
                                      {selectedEvent.reasons.map((reason, idx) => (
                                        <div key={idx} className="flex items-start text-sm text-slate-300 bg-slate-900/50 p-3 rounded-lg border border-slate-800">
                                          <AlertTriangle className="w-4 h-4 text-amber-500 mr-3 mt-0.5 shrink-0" />
                                          {reason}
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                </div>
                                <div>
                                  <div className="text-sm text-slate-400 mb-1">Business Impact Assessment</div>
                                  <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4 text-sm text-slate-300 leading-relaxed h-full">
                                    {selectedEvent.business_impact}
                                  </div>
                                </div>
                              </div>
                            </div>

                            {/* Payload Comparison */}
                            <div className="glass-panel rounded-2xl overflow-hidden">
                              <div className="grid grid-cols-2 divide-x divide-slate-800/50">
                                <div className="p-6">
                                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-4">Original Intercepted Payload</h3>
                                  <div className="font-mono text-sm text-slate-300 whitespace-pre-wrap bg-slate-950 p-4 rounded-xl border border-slate-800/50 min-h-[150px]">
                                    {selectedEvent.original_prompt}
                                  </div>
                                </div>
                                <div className="p-6 bg-slate-900/30">
                                  <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-4 flex items-center">
                                    Sanitized Output <ChevronRight className="w-4 h-4 ml-1" /> External AI
                                  </h3>
                                  {selectedEvent.action === 'BLOCK' ? (
                                    <div className="flex flex-col items-center justify-center h-full min-h-[150px] text-rose-400/80 bg-rose-500/5 border border-rose-500/20 rounded-xl p-4 text-center">
                                      <ShieldAlert className="w-8 h-8 mb-3 opacity-50" />
                                      <span className="text-sm font-bold uppercase tracking-wider">Payload Terminated</span>
                                    </div>
                                  ) : (
                                    <div className="font-mono text-sm text-emerald-400/90 whitespace-pre-wrap bg-slate-950 p-4 rounded-xl border border-emerald-500/20 min-h-[150px] shadow-[inset_0_0_20px_rgba(16,185,129,0.05)] leading-relaxed">
                                      {renderHighlightedText(selectedEvent.rewritten_prompt)}
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>

                            {/* Admin Intervention */}
                            <div className="glass-panel rounded-2xl p-6 border-indigo-500/30">
                              <h3 className="text-xs font-bold uppercase tracking-wider text-indigo-400 mb-4 flex items-center">
                                <Edit3 className="w-4 h-4 mr-2" /> Admin Intervention & Override
                              </h3>
                              <p className="text-sm text-slate-400 mb-4">
                                Review the AI's sanitization. If the prompt is fundamentally unsafe, warn the employee and provide an alternative approach, or manually override the sanitized prompt.
                              </p>
                              <textarea
                                className="w-full bg-slate-900/50 border border-slate-700/50 rounded-xl p-4 text-slate-200 font-mono text-sm focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 resize-none custom-scrollbar transition-all mb-4"
                                rows={3}
                                value={overrideText}
                                onChange={(e) => setOverrideText(e.target.value)}
                              />
                              <div className="flex justify-end space-x-4">
                                <button 
                                  onClick={() => setShowOverrideModal(true)}
                                  className="bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-2 rounded-lg text-sm font-bold tracking-wide transition-all flex items-center shadow-[0_0_15px_rgba(79,70,229,0.3)]"
                                >
                                  <Send className="w-4 h-4 mr-2" /> Dispatch Override & Warning
                                </button>
                              </div>
                            </div>
                          </div>
                        ) : (
                          <div className="flex-1 h-full flex flex-col items-center justify-center text-slate-600">
                            <Activity className="w-16 h-16 mb-6 opacity-20" />
                            <p className="text-xl font-medium text-slate-400">SOC Dashboard Ready</p>
                            <p className="text-sm mt-2">Select an intercepted event from the live feed to view details.</p>
                          </div>
                        )}
                      </div>
                    </>
                  )}

                  {adminTab === 'users' && (
                    <div className="p-8 max-w-7xl mx-auto w-full space-y-6">
                      <div className="mb-6">
                        <h2 className="text-xl font-bold text-white flex items-center">
                          <AlertTriangle className="w-5 h-5 mr-2 text-amber-500" /> Employee Risk Scoring
                        </h2>
                        <p className="text-sm text-slate-400 mt-1">
                          Identify high-risk employees based on repeated policy violations and dangerous prompts.
                        </p>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {Object.values(userProfiles).map((profile: UserProfile) => (
                          <div key={profile.email} className="glass-panel p-6 rounded-2xl border border-slate-800/50 relative overflow-hidden flex flex-col">
                            <div className="flex justify-between items-start mb-6">
                              <div className="flex items-center">
                                <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center mr-3">
                                  <User className="w-5 h-5 text-slate-400" />
                                </div>
                                <div>
                                  <div className="text-sm font-bold text-slate-200">{profile.email.split('@')[0]}</div>
                                  <div className="text-xs text-slate-500">{profile.email}</div>
                                </div>
                              </div>
                              <span className={`text-[10px] font-bold px-2.5 py-1 rounded-full border ${getStatusColor(profile.status)}`}>
                                {profile.status}
                              </span>
                            </div>
                            
                            <div className="grid grid-cols-2 gap-4 mt-auto">
                              <div className="bg-slate-900/50 p-3 rounded-xl border border-slate-800/50">
                                <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Avg Risk</div>
                                <div className={`text-2xl font-mono font-bold ${profile.riskScore >= 50 ? 'text-rose-400' : profile.riskScore >= 20 ? 'text-amber-400' : 'text-emerald-400'}`}>
                                  {profile.riskScore}
                                </div>
                              </div>
                              <div className="bg-slate-900/50 p-3 rounded-xl border border-slate-800/50">
                                <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Violations</div>
                                <div className="text-2xl font-mono font-bold text-slate-300">
                                  {profile.violations} <span className="text-sm text-slate-600">/ {profile.totalInteractions}</span>
                                </div>
                              </div>
                            </div>
                          </div>
                        ))}
                        {Object.keys(userProfiles).length === 0 && (
                          <div className="col-span-full text-center p-12 text-slate-500">
                            No user data collected yet. Waiting for traffic...
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {adminTab === 'audit' && (
                    <div className="p-8 max-w-7xl mx-auto w-full space-y-6">
                      <div className="glass-panel rounded-2xl overflow-hidden border border-slate-800/50">
                        <div className="overflow-x-auto">
                          <table className="w-full text-left text-sm text-slate-300">
                            <thead className="bg-slate-900/80 border-b border-slate-800/50 text-xs uppercase tracking-wider text-slate-500">
                              <tr>
                                <th className="p-4 font-semibold">Timestamp</th>
                                <th className="p-4 font-semibold">User</th>
                                <th className="p-4 font-semibold">Risk Score</th>
                                <th className="p-4 font-semibold">Action</th>
                                <th className="p-4 font-semibold">Threat Vector</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/30">
                              {events.map(event => (
                                <tr key={event.id} className="hover:bg-slate-800/20 transition-colors">
                                  <td className="p-4 font-mono text-xs text-slate-400">{new Date(event.timestamp).toLocaleString()}</td>
                                  <td className="p-4">{event.user}</td>
                                  <td className="p-4">
                                    <span className={`font-mono px-2 py-1 rounded bg-slate-900 border ${event.risk_score >= 71 ? 'text-rose-400 border-rose-500/20' : event.risk_score >= 21 ? 'text-amber-400 border-amber-500/20' : 'text-emerald-400 border-emerald-500/20'}`}>
                                      {event.risk_score}
                                    </span>
                                  </td>
                                  <td className="p-4">
                                    <span className={`text-[10px] font-bold px-2 py-1 rounded-full border ${getActionColor(event.action)}`}>
                                      {event.action}
                                    </span>
                                  </td>
                                  <td className="p-4 text-slate-400 truncate max-w-xs">{event.attack_type}</td>
                                </tr>
                              ))}
                              {events.length === 0 && (
                                <tr>
                                  <td colSpan={5} className="p-8 text-center text-slate-500">No audit logs available.</td>
                                </tr>
                              )}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* Admin Override Confirmation Modal */}
      <AnimatePresence>
        {showOverrideModal && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4"
          >
            <motion.div 
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="glass-panel p-6 rounded-2xl max-w-md w-full mx-4 border-indigo-500/50 shadow-[0_0_40px_rgba(79,70,229,0.2)]"
            >
              <div className="flex items-center mb-4">
                <div className="w-10 h-10 rounded-full bg-indigo-500/20 flex items-center justify-center mr-3">
                  <ShieldAlert className="w-5 h-5 text-indigo-400" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">Confirm Override</h3>
                  <p className="text-xs text-slate-400">Dispatching to {selectedEvent?.user}</p>
                </div>
              </div>
              
              <p className="text-sm text-slate-300 mb-4">
                Please provide a brief reason for this manual override. This will be logged in the employee's risk profile and the historical audit trail.
              </p>
              
              <textarea
                className="w-full bg-slate-900/80 border border-slate-700/50 rounded-xl p-3 text-slate-200 text-sm focus:ring-2 focus:ring-indigo-500/50 resize-none mb-6 custom-scrollbar"
                rows={3}
                placeholder="e.g., 'Prompt still contained obfuscated client ID. Manually redacted.'"
                value={overrideReason}
                onChange={(e) => setOverrideReason(e.target.value)}
              />
              
              <div className="flex justify-end space-x-3">
                <button 
                  onClick={() => setShowOverrideModal(false)} 
                  className="px-4 py-2 rounded-lg text-sm font-bold text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                >
                  Cancel
                </button>
                <button 
                  onClick={() => {
                    alert(`Override dispatched to ${selectedEvent?.user}!\nReason: ${overrideReason}`);
                    setShowOverrideModal(false);
                    setOverrideReason('');
                  }}
                  disabled={!overrideReason.trim()}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-2 rounded-lg text-sm font-bold transition-all disabled:opacity-50 shadow-[0_0_15px_rgba(79,70,229,0.4)]"
                >
                  Confirm & Dispatch
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
