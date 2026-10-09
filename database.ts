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

export interface TrainingRecord {
  id: string;
  userEmail: string;
  moduleId: string;
  status: 'ASSIGNED' | 'COMPLETED';
  assignedBy: string;
  assignedAt: string;
  completedAt?: string;
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
  trainings: TrainingRecord[];
}

const DB_PATH = path.resolve('database.json');
const TEMP_PATH = path.resolve('database.json.tmp');

const DEFAULT_DB: DatabaseSchema = {
  logs: [],
  trainings: [],
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
    },
    {
      email: 'jordan.hayes@nexus-corp.com',
      granted: true,
      timestamp: new Date().toISOString(),
      version: 'v1.0-GDPR-DPDP',
      ipAddress: '127.0.0.1',
      userAgent: 'AEGIS Enterprise Portal - DevOps'
    },
    {
      email: 'claire.dupont@nexus-corp.com',
      granted: true,
      timestamp: new Date().toISOString(),
      version: 'v1.0-GDPR-DPDP',
      ipAddress: '127.0.0.1',
      userAgent: 'AEGIS Enterprise Portal - Support'
    },
    {
      email: 'tariq.mansoor@nexus-corp.com',
      granted: true,
      timestamp: new Date().toISOString(),
      version: 'v1.0-GDPR-DPDP',
      ipAddress: '127.0.0.1',
      userAgent: 'AEGIS Enterprise Portal - AI Research'
    },
    {
      email: 'kavita.sharma@nexus-corp.com',
      granted: true,
      timestamp: new Date().toISOString(),
      version: 'v1.0-GDPR-DPDP',
      ipAddress: '127.0.0.1',
      userAgent: 'AEGIS Enterprise Portal - Product'
    },
    {
      email: 'vikram.patel@nexus-corp.com',
      granted: true,
      timestamp: new Date().toISOString(),
      version: 'v1.0-GDPR-DPDP',
      ipAddress: '127.0.0.1',
      userAgent: 'AEGIS Enterprise Portal - AppSec QA'
    },
    {
      email: 'hr@nexus-corp.com',
      granted: true,
      timestamp: new Date().toISOString(),
      version: 'v1.0-GDPR-DPDP',
      ipAddress: '127.0.0.1',
      userAgent: 'AEGIS Enterprise Portal - People Ops'
    },
    {
      email: 'finance@nexus-corp.com',
      granted: true,
      timestamp: new Date().toISOString(),
      version: 'v1.0-GDPR-DPDP',
      ipAddress: '127.0.0.1',
      userAgent: 'AEGIS Enterprise Portal - Finance'
    },
    {
      email: 'marketing@nexus-corp.com',
      granted: true,
      timestamp: new Date().toISOString(),
      version: 'v1.0-GDPR-DPDP',
      ipAddress: '127.0.0.1',
      userAgent: 'AEGIS Enterprise Portal - Marketing'
    },
    {
      email: 'legal@nexus-corp.com',
      granted: true,
      timestamp: new Date().toISOString(),
      version: 'v1.0-GDPR-DPDP',
      ipAddress: '127.0.0.1',
      userAgent: 'AEGIS Enterprise Portal - Legal'
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
      await fs.writeFile(DB_PATH, dataString, 'utf8');
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
    if (!dbCache.trainings) {
      dbCache.trainings = [];
      modified = true;
    }

    // Sanitize any historical logs to protect secrets
    if (dbCache.logs && dbCache.logs.length > 0) {
      const sanitized = sanitizeExistingLogs(dbCache.logs);
      dbCache.logs = sanitized;
      modified = true;
    }

    // Seed realistic sample interactions for enterprise workforce if missing
    if (!dbCache.logs || !dbCache.logs.some(l => l.user === 'jordan.hayes@nexus-corp.com')) {
      const demoUserSeeds: LogEvent[] = [
        // Jordan Hayes (Cloud DevOps & SRE) - Credential Violations -> SEC-101
        {
          id: `aegis-evt-jordan-01`,
          timestamp: new Date(Date.now() - 7200000 * 6).toISOString(),
          user: 'jordan.hayes@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Generate Terraform module for AWS VPC with private subnets').digest('hex'),
          original_prompt: 'Generate Terraform module for AWS VPC with private subnets across 3 AZs',
          sanitized_prompt: 'Generate Terraform module for AWS VPC with private subnets across 3 AZs',
          risk_score: 0,
          risk_level: 'LOW',
          attack_type: 'None',
          reasons: [],
          action: 'ALLOW',
          rewritten_prompt: 'Generate Terraform module for AWS VPC with private subnets across 3 AZs',
          suggested_safe_prompt: 'Prompt verified and approved for transmission.',
          business_impact: 'Safe compliant infrastructure query.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'Prompt verified clean and approved for transmission.',
          provider_id: 'provider-safe-mock',
          latency_ms: 19,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-jordan-02`,
          timestamp: new Date(Date.now() - 7200000 * 5).toISOString(),
          user: 'jordan.hayes@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('AWS provider credentials debug').digest('hex'),
          original_prompt: '[REDACTED_BLOCKED_CONTENT]',
          sanitized_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          risk_score: 98,
          risk_level: 'CRITICAL',
          attack_type: 'CREDENTIAL',
          reasons: ['Detected explicit third-party API key, access token, or incoming webhook.'],
          action: 'BLOCK',
          rewritten_prompt: '',
          suggested_safe_prompt: 'Request blocked by security policy: Strict prohibition against forwarding cryptographic keys or cloud provider secrets.',
          business_impact: 'Critical perimeter block: Cloud provider access keys intercepted.',
          alert_status: 'TRIGGERED',
          report_summary: 'Request blocked by security policy: Block Credentials & Private Keys.',
          provider_id: 'provider-safe-mock',
          latency_ms: 2,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-jordan-03`,
          timestamp: new Date(Date.now() - 7200000 * 4).toISOString(),
          user: 'jordan.hayes@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('PostgreSQL connection debug').digest('hex'),
          original_prompt: '[REDACTED_BLOCKED_CONTENT]',
          sanitized_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          risk_score: 95,
          risk_level: 'CRITICAL',
          attack_type: 'CREDENTIAL',
          reasons: ['Detected database connection string containing embedded cleartext credentials.'],
          action: 'BLOCK',
          rewritten_prompt: '',
          suggested_safe_prompt: 'Request blocked: Production database connection strings must not be forwarded to external AI models.',
          business_impact: 'High-risk perimeter stop: Database credentials intercepted.',
          alert_status: 'TRIGGERED',
          report_summary: 'Request blocked by security policy: Database Connection Strings & Secrets.',
          provider_id: 'provider-safe-mock',
          latency_ms: 2,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-jordan-04`,
          timestamp: new Date(Date.now() - 7200000 * 3).toISOString(),
          user: 'jordan.hayes@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Private certificate key validation').digest('hex'),
          original_prompt: '[REDACTED_BLOCKED_CONTENT]',
          sanitized_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          risk_score: 99,
          risk_level: 'CRITICAL',
          attack_type: 'CREDENTIAL',
          reasons: ['Detected cryptographic private key payload.'],
          action: 'BLOCK',
          rewritten_prompt: '',
          suggested_safe_prompt: 'Request blocked: Cryptographic private keys must never be transmitted outside the enterprise boundary.',
          business_impact: 'Critical perimeter stop: Cryptographic private key intercepted.',
          alert_status: 'TRIGGERED',
          report_summary: 'Request blocked by security policy: Block Credentials & Private Keys.',
          provider_id: 'provider-safe-mock',
          latency_ms: 3,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-jordan-05`,
          timestamp: new Date(Date.now() - 7200000 * 2).toISOString(),
          user: 'jordan.hayes@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('GitLab CI deployment webhook token').digest('hex'),
          original_prompt: '[REDACTED_BLOCKED_CONTENT]',
          sanitized_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          risk_score: 92,
          risk_level: 'CRITICAL',
          attack_type: 'CREDENTIAL',
          reasons: ['Detected explicit third-party API key, access token, or incoming webhook.'],
          action: 'BLOCK',
          rewritten_prompt: '',
          suggested_safe_prompt: 'Request blocked: Third-party deployment tokens must be managed using vault secrets.',
          business_impact: 'Critical perimeter block: Deployment webhook token intercepted.',
          alert_status: 'TRIGGERED',
          report_summary: 'Request blocked by security policy: Block Credentials & Private Keys.',
          provider_id: 'provider-safe-mock',
          latency_ms: 2,
          has_file: false,
          override_status: 'NONE'
        },
        // Claire Dupont (Customer Support) - PII Violations -> PRIV-201
        {
          id: `aegis-evt-claire-01`,
          timestamp: new Date(Date.now() - 86400000).toISOString(),
          user: 'claire.dupont@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Draft polite apology for delivery delay').digest('hex'),
          original_prompt: 'Draft a polite and empathetic email apologizing to a customer for a shipment delay due to severe winter weather.',
          sanitized_prompt: 'Draft a polite and empathetic email apologizing to a customer for a shipment delay due to severe winter weather.',
          risk_score: 0,
          risk_level: 'LOW',
          attack_type: 'None',
          reasons: [],
          action: 'ALLOW',
          rewritten_prompt: 'Draft a polite and empathetic email apologizing to a customer for a shipment delay due to severe winter weather.',
          suggested_safe_prompt: 'Prompt verified and approved for transmission.',
          business_impact: 'Safe compliant customer support draft.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'Prompt verified clean and approved for transmission.',
          provider_id: 'provider-safe-mock',
          latency_ms: 17,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-claire-02`,
          timestamp: new Date(Date.now() - 7200000 * 8).toISOString(),
          user: 'claire.dupont@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Customer ticket with SSN and phone').digest('hex'),
          original_prompt: 'Draft response for ticket #5821: Client Marcus Vance (SSN [REDACTED_SSN], cell [REDACTED_PHONE]) is disputing an overcharge of $240.',
          sanitized_prompt: 'Draft response for ticket #5821: Client Marcus Vance (SSN [REDACTED_SSN], cell [REDACTED_PHONE]) is disputing an overcharge of $240.',
          risk_score: 65,
          risk_level: 'MEDIUM',
          attack_type: 'PII',
          reasons: ['Detected Social Security Number (SSN).', 'Detected telephone contact number.'],
          action: 'MODIFIED',
          rewritten_prompt: 'Draft response for ticket #5821: Client Marcus Vance (SSN [REDACTED_SSN], cell [REDACTED_PHONE]) is disputing an overcharge of $240.',
          suggested_safe_prompt: 'Customer PII redacted before external AI processing.',
          business_impact: 'Privacy compliance requirement: PII masked before external forwarding.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'PII masked in accordance with GDPR / DPDP.',
          provider_id: 'provider-safe-mock',
          latency_ms: 22,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-claire-03`,
          timestamp: new Date(Date.now() - 7200000 * 6).toISOString(),
          user: 'claire.dupont@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Customer email address in prompt').digest('hex'),
          original_prompt: 'Help reply to corporate account manager at [REDACTED_EMAIL] regarding their pending subscription renewal.',
          sanitized_prompt: 'Help reply to corporate account manager at [REDACTED_EMAIL] regarding their pending subscription renewal.',
          risk_score: 40,
          risk_level: 'MEDIUM',
          attack_type: 'PII',
          reasons: ['Detected personal or corporate email address.'],
          action: 'MODIFIED',
          rewritten_prompt: 'Help reply to corporate account manager at [REDACTED_EMAIL] regarding their pending subscription renewal.',
          suggested_safe_prompt: 'Email address redacted before forwarding.',
          business_impact: 'Privacy compliance requirement: Email masked before external forwarding.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'PII masked in accordance with GDPR / DPDP.',
          provider_id: 'provider-safe-mock',
          latency_ms: 18,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-claire-04`,
          timestamp: new Date(Date.now() - 7200000 * 4).toISOString(),
          user: 'claire.dupont@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Credit card dispute ticket').digest('hex'),
          original_prompt: 'Refund verification for ticket #9034: Client card ending in [REDACTED_CREDIT_CARD] was charged twice during checkout.',
          sanitized_prompt: 'Refund verification for ticket #9034: Client card ending in [REDACTED_CREDIT_CARD] was charged twice during checkout.',
          risk_score: 75,
          risk_level: 'HIGH',
          attack_type: 'PII',
          reasons: ['Detected payment card number (PCI-DSS).'],
          action: 'MODIFIED',
          rewritten_prompt: 'Refund verification for ticket #9034: Client card ending in [REDACTED_CREDIT_CARD] was charged twice during checkout.',
          suggested_safe_prompt: 'Payment card data masked before external forwarding.',
          business_impact: 'PCI-DSS / Privacy requirement: Payment card numbers masked.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'Payment card data masked in accordance with PCI-DSS / Privacy Policy.',
          provider_id: 'provider-safe-mock',
          latency_ms: 25,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-claire-05`,
          timestamp: new Date(Date.now() - 3600000 * 2).toISOString(),
          user: 'claire.dupont@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Bulk SSN parse attempt').digest('hex'),
          original_prompt: '[REDACTED_BLOCKED_CONTENT]',
          sanitized_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          risk_score: 94,
          risk_level: 'CRITICAL',
          attack_type: 'PII',
          reasons: ['Detected unredacted Social Security Numbers (SSN) in bulk context.'],
          action: 'BLOCK',
          rewritten_prompt: '',
          suggested_safe_prompt: 'Request blocked: Bulk client PII transmission prohibited by Data Loss Prevention boundary.',
          business_impact: 'Critical privacy violation blocked.',
          alert_status: 'TRIGGERED',
          report_summary: 'Request blocked by security policy: Block SSN / National Identifiers.',
          provider_id: 'provider-safe-mock',
          latency_ms: 2,
          has_file: false,
          override_status: 'NONE'
        },
        // Tariq Al-Mansoor (Applied AI Research) - Prompt Injection -> AUP-401
        {
          id: `aegis-evt-tariq-01`,
          timestamp: new Date(Date.now() - 86400000 * 2).toISOString(),
          user: 'tariq.mansoor@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Multi-query attention explanation').digest('hex'),
          original_prompt: 'Explain how multi-query attention (MQA) reduces key-value cache memory compared to standard multi-head attention.',
          sanitized_prompt: 'Explain how multi-query attention (MQA) reduces key-value cache memory compared to standard multi-head attention.',
          risk_score: 0,
          risk_level: 'LOW',
          attack_type: 'None',
          reasons: [],
          action: 'ALLOW',
          rewritten_prompt: 'Explain how multi-query attention (MQA) reduces key-value cache memory compared to standard multi-head attention.',
          suggested_safe_prompt: 'Prompt verified clean and approved for transmission.',
          business_impact: 'Safe compliant AI research query.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'Prompt verified clean and approved for transmission.',
          provider_id: 'provider-safe-mock',
          latency_ms: 22,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-tariq-02`,
          timestamp: new Date(Date.now() - 7200000 * 6).toISOString(),
          user: 'tariq.mansoor@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('DAN jailbreak test').digest('hex'),
          original_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          sanitized_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          risk_score: 96,
          risk_level: 'CRITICAL',
          attack_type: 'PROMPT_INJECTION',
          reasons: ['Detected adversarial prompt override or jailbreak styling.', 'Detected attempt to extract system prompt / boundary configuration.'],
          action: 'BLOCK',
          rewritten_prompt: '',
          suggested_safe_prompt: 'Request blocked: Prompt Injection & Adversarial Jailbreak Guardrail.',
          business_impact: 'Adversarial bypass prevention: Jailbreak instruction intercepted.',
          alert_status: 'TRIGGERED',
          report_summary: 'Request blocked by security policy: Prompt Injection & Adversarial Jailbreak Guardrail.',
          provider_id: 'provider-safe-mock',
          latency_ms: 2,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-tariq-03`,
          timestamp: new Date(Date.now() - 7200000 * 4).toISOString(),
          user: 'tariq.mansoor@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Persona spoofing bypass').digest('hex'),
          original_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          sanitized_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          risk_score: 92,
          risk_level: 'CRITICAL',
          attack_type: 'PROMPT_INJECTION',
          reasons: ['Detected persona spoofing and behavioral bypass instruction.'],
          action: 'BLOCK',
          rewritten_prompt: '',
          suggested_safe_prompt: 'Request blocked: Boundary Guardrail Violation.',
          business_impact: 'Perimeter block: Jailbreak persona spoofing detected.',
          alert_status: 'TRIGGERED',
          report_summary: 'Request blocked by security policy: Boundary Guardrail Violation.',
          provider_id: 'provider-safe-mock',
          latency_ms: 2,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-tariq-04`,
          timestamp: new Date(Date.now() - 7200000 * 2).toISOString(),
          user: 'tariq.mansoor@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Delimiter evasion attempt').digest('hex'),
          original_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          sanitized_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          risk_score: 98,
          risk_level: 'CRITICAL',
          attack_type: 'PROMPT_INJECTION',
          reasons: ['Detected delimiter boundary evasion and system prompt exfiltration payload.'],
          action: 'BLOCK',
          rewritten_prompt: '',
          suggested_safe_prompt: 'Request blocked: Delimiter escape and system prompt exfiltration detected.',
          business_impact: 'Critical boundary block: Delimiter escape detected.',
          alert_status: 'TRIGGERED',
          report_summary: 'Request blocked by security policy: Prompt Injection & Boundary Guardrail.',
          provider_id: 'provider-safe-mock',
          latency_ms: 2,
          has_file: false,
          override_status: 'NONE'
        },
        // Kavita Sharma (Product Architecture) - Confidential Codenames -> IP-501
        {
          id: `aegis-evt-kavita-01`,
          timestamp: new Date(Date.now() - 86400000).toISOString(),
          user: 'kavita.sharma@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Event-driven microservices architecture').digest('hex'),
          original_prompt: 'Outline the key architectural components of an event-driven microservices architecture using Apache Kafka.',
          sanitized_prompt: 'Outline the key architectural components of an event-driven microservices architecture using Apache Kafka.',
          risk_score: 0,
          risk_level: 'LOW',
          attack_type: 'None',
          reasons: [],
          action: 'ALLOW',
          rewritten_prompt: 'Outline the key architectural components of an event-driven microservices architecture using Apache Kafka.',
          suggested_safe_prompt: 'Prompt verified clean and approved for transmission.',
          business_impact: 'Safe compliant product architecture query.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'Prompt verified clean and approved for transmission.',
          provider_id: 'provider-safe-mock',
          latency_ms: 20,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-kavita-02`,
          timestamp: new Date(Date.now() - 7200000 * 5).toISOString(),
          user: 'kavita.sharma@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Orion-Core roadmap draft').digest('hex'),
          original_prompt: 'Draft the Q4 product roadmap presentation focusing on [REDACTED_PROJECT_CODENAME] architecture and customer onboarding timeline.',
          sanitized_prompt: 'Draft the Q4 product roadmap presentation focusing on [REDACTED_PROJECT_CODENAME] architecture and customer onboarding timeline.',
          risk_score: 40,
          risk_level: 'MEDIUM',
          attack_type: 'CONFIDENTIAL_TECHNICAL',
          reasons: ['Matched confidential enterprise keyword: Orion-Core.'],
          action: 'MODIFIED',
          rewritten_prompt: 'Draft the Q4 product roadmap presentation focusing on [REDACTED_PROJECT_CODENAME] architecture and customer onboarding timeline.',
          suggested_safe_prompt: 'Confidential project codename redacted before external forwarding.',
          business_impact: 'Trade secret protection: Internal project codename redacted before provider transit.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'Codename redacted in accordance with IP Protection Policy.',
          provider_id: 'provider-safe-mock',
          latency_ms: 18,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-kavita-03`,
          timestamp: new Date(Date.now() - 7200000 * 3).toISOString(),
          user: 'kavita.sharma@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Internal hostname leakage').digest('hex'),
          original_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          sanitized_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          risk_score: 85,
          risk_level: 'HIGH',
          attack_type: 'CONFIDENTIAL_TECHNICAL',
          reasons: ['Prevents leakage of internal infrastructure hostnames.'],
          action: 'BLOCK',
          rewritten_prompt: '',
          suggested_safe_prompt: 'Request blocked: Internal infrastructure hostnames must not be transmitted.',
          business_impact: 'Infrastructure security: Internal hostnames blocked from transit.',
          alert_status: 'TRIGGERED',
          report_summary: 'Request blocked by security policy: Internal Infrastructure Protection.',
          provider_id: 'provider-safe-mock',
          latency_ms: 2,
          has_file: false,
          override_status: 'NONE'
        },
        // Vikram Patel (AppSec QA) - SQLi & Exploit Strings -> APPSEC-301
        {
          id: `aegis-evt-vikram-01`,
          timestamp: new Date(Date.now() - 86400000).toISOString(),
          user: 'vikram.patel@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('SAST vs DAST differences').digest('hex'),
          original_prompt: 'Explain the differences between static application security testing (SAST) and dynamic analysis (DAST) in a CI/CD pipeline.',
          sanitized_prompt: 'Explain the differences between static application security testing (SAST) and dynamic analysis (DAST) in a CI/CD pipeline.',
          risk_score: 0,
          risk_level: 'LOW',
          attack_type: 'None',
          reasons: [],
          action: 'ALLOW',
          rewritten_prompt: 'Explain the differences between static application security testing (SAST) and dynamic analysis (DAST) in a CI/CD pipeline.',
          suggested_safe_prompt: 'Prompt verified clean and approved for transmission.',
          business_impact: 'Safe compliant application security query.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'Prompt verified clean and approved for transmission.',
          provider_id: 'provider-safe-mock',
          latency_ms: 18,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-vikram-02`,
          timestamp: new Date(Date.now() - 7200000 * 5).toISOString(),
          user: 'vikram.patel@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('SQL injection test string').digest('hex'),
          original_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          sanitized_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          risk_score: 92,
          risk_level: 'CRITICAL',
          attack_type: 'APPSEC_EXPLOIT',
          reasons: ['Detected live SQL injection exploit signature.', 'Detected UNION SELECT database exfiltration payload.'],
          action: 'BLOCK',
          rewritten_prompt: '',
          suggested_safe_prompt: 'Request blocked: Active SQL injection exploit payloads cannot be forwarded to external AI providers.',
          business_impact: 'AppSec perimeter block: Active SQL injection payload intercepted.',
          alert_status: 'TRIGGERED',
          report_summary: 'Request blocked by security policy: AppSec Exploit & Injection Guardrail.',
          provider_id: 'provider-safe-mock',
          latency_ms: 2,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-vikram-03`,
          timestamp: new Date(Date.now() - 7200000 * 3).toISOString(),
          user: 'vikram.patel@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('XSS document.cookie payload').digest('hex'),
          original_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          sanitized_prompt: '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]',
          risk_score: 94,
          risk_level: 'CRITICAL',
          attack_type: 'APPSEC_EXPLOIT',
          reasons: ['Detected cross-site scripting (XSS) payload with document.cookie exfiltration.'],
          action: 'BLOCK',
          rewritten_prompt: '',
          suggested_safe_prompt: 'Request blocked: Live cross-site scripting exploit payloads intercepted.',
          business_impact: 'Perimeter block: Client-side exploit script intercepted.',
          alert_status: 'TRIGGERED',
          report_summary: 'Request blocked by security policy: Web Exploit Guardrail.',
          provider_id: 'provider-safe-mock',
          latency_ms: 2,
          has_file: false,
          override_status: 'NONE'
        },
        // Sarah Jenkins (People Operations & HR) - Compliant
        {
          id: `aegis-evt-sarah-01`,
          timestamp: new Date(Date.now() - 86400000).toISOString(),
          user: 'hr@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Interview assessment rubric').digest('hex'),
          original_prompt: 'Draft an interview assessment rubric for evaluating systems engineering candidates on collaborative problem solving.',
          sanitized_prompt: 'Draft an interview assessment rubric for evaluating systems engineering candidates on collaborative problem solving.',
          risk_score: 0,
          risk_level: 'LOW',
          attack_type: 'None',
          reasons: [],
          action: 'ALLOW',
          rewritten_prompt: 'Draft an interview assessment rubric for evaluating systems engineering candidates on collaborative problem solving.',
          suggested_safe_prompt: 'Prompt verified clean and approved for transmission.',
          business_impact: 'Safe compliant HR operations draft.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'Prompt verified clean and approved for transmission.',
          provider_id: 'provider-safe-mock',
          latency_ms: 18,
          has_file: false,
          override_status: 'NONE'
        },
        // Alex Rivera (current.user) - Compliant + Masked
        {
          id: `aegis-evt-${Date.now()}-u1`,
          timestamp: new Date(Date.now() - 3600000).toISOString(),
          user: 'current.user@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('How to optimize React performance with memoization?').digest('hex'),
          original_prompt: 'How to optimize React performance with memoization?',
          sanitized_prompt: 'How to optimize React performance with memoization?',
          risk_score: 0,
          risk_level: 'LOW',
          attack_type: 'None',
          reasons: [],
          action: 'ALLOW',
          rewritten_prompt: 'How to optimize React performance with memoization?',
          suggested_safe_prompt: 'Prompt verified and approved for transmission.',
          business_impact: 'Safe compliant interaction.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'Prompt verified and approved for transmission.',
          provider_id: 'provider-safe-mock',
          latency_ms: 18,
          has_file: false,
          override_status: 'NONE'
        },
        {
          id: `aegis-evt-${Date.now()}-u2`,
          timestamp: new Date(Date.now() - 1800000).toISOString(),
          user: 'current.user@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Draft an introductory email for client whose email is client.john@external.com and phone is +1 800-555-0199').digest('hex'),
          original_prompt: 'Draft an introductory email for client whose email is [REDACTED_EMAIL] and phone is [REDACTED_PHONE]',
          sanitized_prompt: 'Draft an introductory email for client whose email is [REDACTED_EMAIL] and phone is [REDACTED_PHONE]',
          risk_score: 45,
          risk_level: 'MEDIUM',
          attack_type: 'PII',
          reasons: ['Detected personal or corporate email address.', 'Detected telephone contact number.'],
          action: 'MODIFIED',
          rewritten_prompt: 'Draft an introductory email for client whose email is [REDACTED_EMAIL] and phone is [REDACTED_PHONE]',
          suggested_safe_prompt: 'Request sanitized before forwarding: Redacted PII entities.',
          business_impact: 'Privacy compliance requirement: PII masked before external forwarding.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'PII masked in accordance with GDPR / DPDP.',
          provider_id: 'provider-safe-mock',
          latency_ms: 22,
          has_file: false,
          override_status: 'NONE'
        },
        // Finance - Compliant
        {
          id: `aegis-evt-${Date.now()}-u4`,
          timestamp: new Date(Date.now() - 7200000).toISOString(),
          user: 'finance@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Calculate projected EBITDA margin based on Q3 budget').digest('hex'),
          original_prompt: 'Calculate projected EBITDA margin based on Q3 budget',
          sanitized_prompt: 'Calculate projected EBITDA margin based on Q3 budget',
          risk_score: 0,
          risk_level: 'LOW',
          attack_type: 'None',
          reasons: [],
          action: 'ALLOW',
          rewritten_prompt: 'Calculate projected EBITDA margin based on Q3 budget',
          suggested_safe_prompt: 'Prompt verified clean and approved for transmission.',
          business_impact: 'Compliant business query.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'Prompt verified and approved for transmission.',
          provider_id: 'provider-safe-mock',
          latency_ms: 24,
          has_file: false,
          override_status: 'NONE'
        },
        // Marketing - Compliant
        {
          id: `aegis-evt-${Date.now()}-u5`,
          timestamp: new Date(Date.now() - 5400000).toISOString(),
          user: 'marketing@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Generate SEO headlines for new product launch').digest('hex'),
          original_prompt: 'Generate SEO headlines for new product launch',
          sanitized_prompt: 'Generate SEO headlines for new product launch',
          risk_score: 0,
          risk_level: 'LOW',
          attack_type: 'None',
          reasons: [],
          action: 'ALLOW',
          rewritten_prompt: 'Generate SEO headlines for new product launch',
          suggested_safe_prompt: 'Prompt verified clean and approved for transmission.',
          business_impact: 'Compliant business query.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'Prompt verified and approved for transmission.',
          provider_id: 'provider-safe-mock',
          latency_ms: 19,
          has_file: false,
          override_status: 'NONE'
        },
        // Legal - Compliant
        {
          id: `aegis-evt-${Date.now()}-u6`,
          timestamp: new Date(Date.now() - 4800000).toISOString(),
          user: 'legal@nexus-corp.com',
          user_role: 'USER',
          prompt_hash: crypto.createHash('sha256').update('Review standard SaaS vendor agreement confidentiality clause').digest('hex'),
          original_prompt: 'Review standard SaaS vendor agreement confidentiality clause',
          sanitized_prompt: 'Review standard SaaS vendor agreement confidentiality clause',
          risk_score: 0,
          risk_level: 'LOW',
          attack_type: 'None',
          reasons: [],
          action: 'ALLOW',
          rewritten_prompt: 'Review standard SaaS vendor agreement confidentiality clause',
          suggested_safe_prompt: 'Prompt verified clean and approved for transmission.',
          business_impact: 'Compliant business query.',
          alert_status: 'NOT TRIGGERED',
          report_summary: 'Prompt verified and approved for transmission.',
          provider_id: 'provider-safe-mock',
          latency_ms: 28,
          has_file: false,
          override_status: 'NONE'
        }
      ];
      dbCache.logs = [...demoUserSeeds, ...(dbCache.logs || [])];
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

export async function getTrainings(email?: string): Promise<TrainingRecord[]> {
  const db = await initDatabase();
  const list = db.trainings || [];
  if (email) {
    return list.filter(t => t.userEmail === email);
  }
  return list;
}

export async function assignTraining(userEmail: string, moduleId: string, assignedBy: string): Promise<TrainingRecord> {
  const db = await initDatabase();
  if (!db.trainings) db.trainings = [];
  
  const existing = db.trainings.find(t => t.userEmail === userEmail && t.moduleId === moduleId && t.status === 'ASSIGNED');
  if (existing) return existing;

  const newRecord: TrainingRecord = {
    id: `trn-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    userEmail,
    moduleId,
    status: 'ASSIGNED',
    assignedBy,
    assignedAt: new Date().toISOString()
  };

  db.trainings.push(newRecord);
  await saveToDisk();
  return newRecord;
}

export async function completeTraining(userEmail: string, moduleId: string): Promise<TrainingRecord> {
  const db = await initDatabase();
  if (!db.trainings) db.trainings = [];

  let record = db.trainings.find(t => t.userEmail === userEmail && t.moduleId === moduleId && t.status === 'ASSIGNED');
  if (!record) {
    record = {
      id: `trn-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      userEmail,
      moduleId,
      status: 'COMPLETED',
      assignedBy: 'Self-Enrollment',
      assignedAt: new Date().toISOString(),
      completedAt: new Date().toISOString()
    };
    db.trainings.push(record);
  } else {
    record.status = 'COMPLETED';
    record.completedAt = new Date().toISOString();
  }

  await saveToDisk();
  return record;
}
