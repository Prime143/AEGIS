import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
export type { PolicyRule, OrganizationContext, UserRole } from './src/core/types';
import { PolicyRule, OrganizationContext, UserRole } from './src/core/types';
import { DEFAULT_POLICIES } from './src/core/policy/PolicyEngine';
import { DEFAULT_ORGANIZATION_CONTEXT } from './src/core/organization/OrganizationService';

export interface LogEvent {
  id: string;
  timestamp: string;
  user: string;
  user_role?: UserRole;
  prompt_hash?: string;
  original_prompt: string; // Redacted representation if sensitive, NEVER raw secrets
  sanitized_prompt?: string;
  risk_score: number;
  risk_level: string;
  attack_type: string;
  reasons: string[];
  action: 'ALLOW' | 'MODIFIED' | 'BLOCK';
  rewritten_prompt: string;
  suggested_safe_prompt: string;
  business_impact: string;
  alert_status: 'TRIGGERED' | 'NOT TRIGGERED';
  report_summary: string;
  provider_id?: string;
  latency_ms?: number;
  has_file?: boolean;
  override_reason?: string;
  override_status?: 'NONE' | 'OVERRIDDEN';
  override_timestamp?: string;
}

export interface GlobalSettings {
  policyMode: 'strict' | 'balanced' | 'relaxed';
  systemStatus: 'active' | 'lockdown';
  activeProviderId?: string;
}

export interface EnterpriseRule {
  id: string;
  name: string;
  pattern: string;
  type: 'keyword' | 'regex';
  action: 'BLOCK' | 'REDACT';
  redactPlaceholder?: string;
  explanation: string;
}

export interface UserConsent {
  email: string;
  granted: boolean;
  timestamp: string;
  version: string;
  ipAddress: string;
  userAgent: string;
}

export interface ApiKey {
  id: string;
  name: string;
  key: string;
  role: UserRole;
  createdBy: string;
  createdAt: string;
  status: 'active' | 'revoked';
  totalRequests: number;
}

export interface DlpPolicyItem {
  enabled: boolean;
  action: 'BLOCK' | 'REDACT';
}

export interface DlpPolicy {
  ssn: DlpPolicyItem;
  creditCard: DlpPolicyItem;
  apiKeys: DlpPolicyItem;
  dbStrings: DlpPolicyItem;
  medicalPii: DlpPolicyItem;
  appExploits: DlpPolicyItem;
  promptInjections: DlpPolicyItem;
}

export interface DatabaseSchema {
  logs: LogEvent[];
  settings: GlobalSettings;
  rules: EnterpriseRule[];
  consents: UserConsent[];
  apiKeys: ApiKey[];
  dlpPolicy: DlpPolicy;
  policies: PolicyRule[];
  organization: OrganizationContext;
}

const DB_PATH = path.resolve('database.json');
const TEMP_PATH = path.resolve('database.json.tmp');

const DEFAULT_DB: DatabaseSchema = {
  logs: [],
  settings: {
    policyMode: 'balanced',
    systemStatus: 'active',
    activeProviderId: 'provider-safe-mock'
  },
  rules: [
    {
      id: 'rule-1',
      name: 'Project Orion Codename',
      pattern: 'Orion-Core',
      type: 'keyword',
      action: 'REDACT',
      redactPlaceholder: '[REDACTED_PROJECT_CODENAME]',
      explanation: 'Protects references to confidential R&D project (Project Orion).'
    },
    {
      id: 'rule-2',
      name: 'Internal Dev Server Host',
      pattern: 'dev-cluster\\.internal\\.nexus-corp\\.com',
      type: 'regex',
      action: 'BLOCK',
      explanation: 'Prevents leakage of internal infrastructure hostnames.'
    },
    {
      id: 'rule-3',
      name: 'Financial Ledger Access',
      pattern: 'Q[1-4]-financial-report\\.xlsx',
      type: 'regex',
      action: 'BLOCK',
      explanation: 'Blocks queries targeting raw corporate financial spreadsheets.'
    }
  ],
  consents: [
    {
      email: 'admin.soc@nexus-corp.com',
      granted: true,
      timestamp: new Date().toISOString(),
      version: 'v1.0-GDPR-DPDP',
      ipAddress: '127.0.0.1',
      userAgent: 'AEGIS SOC Console'
    },
    {
      email: 'analyst@nexus-corp.com',
      granted: true,
      timestamp: new Date().toISOString(),
      version: 'v1.0-GDPR-DPDP',
      ipAddress: '127.0.0.1',
      userAgent: 'AEGIS Analyst Console'
    },
    {
      email: 'current.user@nexus-corp.com',
      granted: true,
      timestamp: new Date().toISOString(),
      version: 'v1.0-GDPR-DPDP',
      ipAddress: '127.0.0.1',
      userAgent: 'AEGIS Employee Portal'
    },
    {
      email: 'test-user',
      granted: true,
      timestamp: new Date().toISOString(),
      version: 'v1.0-GDPR-DPDP',
      ipAddress: '127.0.0.1',
      userAgent: 'Automated Test Runner'
    }
  ],
  apiKeys: [
    {
      id: 'key-default-admin',
      name: 'Default Admin CI/CD Key',
      key: process.env.ADMIN_API_KEY || `aegis_adm_${crypto.randomBytes(16).toString('hex')}`,
      role: 'ADMIN',
      createdBy: 'System Provisioning',
      createdAt: new Date().toISOString(),
      status: 'active',
      totalRequests: 0
    }
  ],
  dlpPolicy: {
    ssn: { enabled: true, action: 'BLOCK' },
    creditCard: { enabled: true, action: 'BLOCK' },
    apiKeys: { enabled: true, action: 'REDACT' },
    dbStrings: { enabled: true, action: 'BLOCK' },
    medicalPii: { enabled: true, action: 'REDACT' },
    appExploits: { enabled: true, action: 'BLOCK' },
    promptInjections: { enabled: true, action: 'BLOCK' }
  },
  policies: DEFAULT_POLICIES,
  organization: DEFAULT_ORGANIZATION_CONTEXT
};

let dbCache: DatabaseSchema | null = null;
let writeQueue: Promise<void> = Promise.resolve();

async function saveToDisk(): Promise<void> {
  if (!dbCache) return;
  const dataString = JSON.stringify(dbCache, null, 2);
  
  writeQueue = writeQueue.then(async () => {
    try {
      await fs.writeFile(TEMP_PATH, dataString, 'utf8');
      try {
        await fs.rename(TEMP_PATH, DB_PATH);
      } catch (renameErr: any) {
        if (renameErr.code === 'EPERM' || renameErr.code === 'EBUSY') {
          await fs.copyFile(TEMP_PATH, DB_PATH);
          await fs.unlink(TEMP_PATH).catch(() => {});
        } else {
          throw renameErr;
        }
      }
    } catch (err) {
      console.error('Database write error:', err);
    }
  });
  
  return writeQueue;
}

/**
 * Sanitizes existing logs on disk to remove raw credentials or unredacted passwords.
 */
function sanitizeExistingLogs(logs: LogEvent[]): LogEvent[] {
  return logs.map(l => {
    let sanitizedOriginal = l.original_prompt || '';
    // Scrub private keys
    sanitizedOriginal = sanitizedOriginal.replace(/-----BEGIN[^-]+-----[\s\S]*?-----END[^-]+-----/g, '[REDACTED_PRIVATE_KEY]');
    // Scrub passwords
    sanitizedOriginal = sanitizedOriginal.replace(/(password|passwd|pwd)\s*(?:is|:|=)\s*['"]?[^'"\s]+['"]?/gi, '$1 [REDACTED_SECRET]');
    // Scrub db URIs
    sanitizedOriginal = sanitizedOriginal.replace(/[a-zA-Z0-9]+:\/\/[^:@\s]+:[^:@\s]+@[^\s]+/g, '[REDACTED_DB_URI]');
    // Scrub credit cards
    sanitizedOriginal = sanitizedOriginal.replace(/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, '[REDACTED_CREDIT_CARD]');
    // Scrub SSNs
    sanitizedOriginal = sanitizedOriginal.replace(/\b\d{3}[-\s]\d{2}[-\s]\d{4}\b/g, '[REDACTED_SSN]');

    return {
      ...l,
      original_prompt: sanitizedOriginal,
      prompt_hash: l.prompt_hash || crypto.createHash('sha256').update(l.original_prompt || '').digest('hex')
    };
  });
}

export async function initDatabase(): Promise<DatabaseSchema> {
  if (dbCache) return dbCache;
  
  try {
    const raw = await fs.readFile(DB_PATH, 'utf8');
    dbCache = JSON.parse(raw);
    
    // Auto-migrate if any main keys are missing
    let modified = false;
    if (!dbCache || !dbCache.logs || !dbCache.settings || !dbCache.rules || !dbCache.consents) {
      dbCache = { ...DEFAULT_DB, ...dbCache };
      modified = true;
    }
    if (!dbCache.policies) {
      dbCache.policies = DEFAULT_POLICIES;
      modified = true;
    }
    if (!dbCache.organization) {
      dbCache.organization = DEFAULT_ORGANIZATION_CONTEXT;
      modified = true;
    }

    // Sanitize any historical logs to protect secrets
    if (dbCache.logs && dbCache.logs.length > 0) {
      const sanitized = sanitizeExistingLogs(dbCache.logs);
      dbCache.logs = sanitized;
      modified = true;
    }

    if (modified) {
      await saveToDisk();
    }
    return dbCache!;
  } catch (e) {
    dbCache = JSON.parse(JSON.stringify(DEFAULT_DB));
    await saveToDisk();
    return dbCache!;
  }
}

export async function getLogs(): Promise<LogEvent[]> {
  const db = await initDatabase();
  return db.logs;
}

export async function addLog(log: LogEvent): Promise<void> {
  const db = await initDatabase();
  
  // Ensure prompt_hash is computed
  if (!log.prompt_hash) {
    log.prompt_hash = crypto.createHash('sha256').update(log.original_prompt || '').digest('hex');
  }

  // If action is BLOCK, ensure raw confidential prompt is never stored directly
  if (log.action === 'BLOCK' && log.risk_score >= 70) {
    log.original_prompt = log.rewritten_prompt || '[REDACTED_BLOCKED_CONTENT]';
  }

  db.logs.unshift(log);
  if (db.logs.length > 1000) {
    db.logs = db.logs.slice(0, 1000);
  }
  await saveToDisk();
}

export async function updateLog(logId: string, updates: Partial<LogEvent>): Promise<boolean> {
  const db = await initDatabase();
  const index = db.logs.findIndex(l => l.id === logId);
  if (index === -1) return false;
  
  db.logs[index] = { ...db.logs[index], ...updates };
  await saveToDisk();
  return true;
}

export async function getSettings(): Promise<GlobalSettings> {
  const db = await initDatabase();
  return db.settings;
}

export async function updateSettings(settings: Partial<GlobalSettings>): Promise<GlobalSettings> {
  const db = await initDatabase();
  db.settings = { ...db.settings, ...settings };
  await saveToDisk();
  return db.settings;
}

export async function getRules(): Promise<EnterpriseRule[]> {
  const db = await initDatabase();
  return db.rules;
}

export async function addRule(rule: Omit<EnterpriseRule, 'id'>): Promise<EnterpriseRule> {
  const db = await initDatabase();
  const newRule: EnterpriseRule = {
    ...rule,
    id: `rule-${Date.now()}`
  };
  db.rules.push(newRule);
  await saveToDisk();
  return newRule;
}

export async function deleteRule(ruleId: string): Promise<boolean> {
  const db = await initDatabase();
  const index = db.rules.findIndex(r => r.id === ruleId);
  if (index === -1) return false;
  db.rules.splice(index, 1);
  await saveToDisk();
  return true;
}

// PRIVACY SYSTEM: Consent & Log Erasure
export async function getConsents(): Promise<UserConsent[]> {
  const db = await initDatabase();
  return db.consents || [];
}

export async function recordConsent(
  email: string,
  granted: boolean,
  ipAddress: string,
  userAgent: string
): Promise<UserConsent> {
  const db = await initDatabase();
  if (!db.consents) db.consents = [];
  
  const index = db.consents.findIndex(c => c.email === email);
  const consent: UserConsent = {
    email,
    granted,
    timestamp: new Date().toISOString(),
    version: 'v1.0-GDPR-DPDP',
    ipAddress,
    userAgent
  };
  
  if (index !== -1) {
    db.consents[index] = consent;
  } else {
    db.consents.push(consent);
  }
  await saveToDisk();
  return consent;
}

export async function hasConsent(email: string): Promise<boolean> {
  const db = await initDatabase();
  if (!db.consents) return false;
  const record = db.consents.find(c => c.email.toLowerCase() === email.toLowerCase());
  return record ? record.granted : false;
}

export async function eraseUserLogs(email: string): Promise<number> {
  const db = await initDatabase();
  const originalLength = db.logs.length;
  
  db.logs = db.logs.filter(l => l.user.toLowerCase() !== email.toLowerCase());
  
  if (db.consents) {
    const index = db.consents.findIndex(c => c.email.toLowerCase() === email.toLowerCase());
    if (index !== -1) {
      db.consents[index].granted = false;
      db.consents[index].timestamp = new Date().toISOString();
    }
  }
  
  await saveToDisk();
  return originalLength - db.logs.length;
}

// DEVELOPER & API KEYS
export async function getApiKeys(): Promise<ApiKey[]> {
  const db = await initDatabase();
  return db.apiKeys || [];
}

export async function createApiKey(name: string, createdBy: string, role: UserRole = 'USER'): Promise<ApiKey> {
  const db = await initDatabase();
  if (!db.apiKeys) db.apiKeys = [];
  
  const randomSegment = crypto.randomBytes(12).toString('hex');
  const key = `aegis_${role.toLowerCase()}_${randomSegment}`;
  
  const newKey: ApiKey = {
    id: `key-${Date.now()}`,
    name,
    key,
    role,
    createdBy,
    createdAt: new Date().toISOString(),
    status: 'active',
    totalRequests: 0
  };
  
  db.apiKeys.push(newKey);
  await saveToDisk();
  return newKey;
}

export async function revokeApiKey(id: string): Promise<boolean> {
  const db = await initDatabase();
  if (!db.apiKeys) return false;
  const index = db.apiKeys.findIndex(k => k.id === id);
  if (index === -1) return false;
  db.apiKeys[index].status = 'revoked';
  await saveToDisk();
  return true;
}

export async function validateApiKey(key: string): Promise<ApiKey | null> {
  const db = await initDatabase();
  if (!db.apiKeys) return null;
  const record = db.apiKeys.find(k => k.key === key && k.status === 'active');
  if (!record) return null;
  record.totalRequests++;
  await saveToDisk();
  return record;
}

export async function getDlpPolicy(): Promise<DlpPolicy> {
  const db = await initDatabase();
  return db.dlpPolicy;
}

export async function updateDlpPolicy(policy: Partial<DlpPolicy>): Promise<DlpPolicy> {
  const db = await initDatabase();
  db.dlpPolicy = { ...db.dlpPolicy, ...policy };
  await saveToDisk();
  return db.dlpPolicy;
}

export async function getPolicies(): Promise<PolicyRule[]> {
  const db = await initDatabase();
  return db.policies || DEFAULT_POLICIES;
}

export async function savePolicies(policies: PolicyRule[]): Promise<PolicyRule[]> {
  const db = await initDatabase();
  db.policies = [...policies];
  await saveToDisk();
  return db.policies;
}

export async function getOrganization(): Promise<OrganizationContext> {
  const db = await initDatabase();
  return db.organization || DEFAULT_ORGANIZATION_CONTEXT;
}

export async function updateOrganization(org: Partial<OrganizationContext>): Promise<OrganizationContext> {
  const db = await initDatabase();
  db.organization = { ...db.organization, ...org };
  await saveToDisk();
  return db.organization;
}
