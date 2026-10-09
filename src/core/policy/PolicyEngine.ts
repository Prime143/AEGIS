import {
  Finding,
  PolicyRule,
  PolicyResult,
  SecurityAction,
  Severity,
  UserRole,
  OrganizationContext
} from '../types';
import { MaskingService } from '../masking/MaskingService';

export interface PolicyEvaluationContext {
  userRole: UserRole;
  userEmail: string;
  providerId: string;
  policyMode: 'strict' | 'balanced' | 'relaxed';
  isLockdownActive?: boolean;
  hasUserConsent?: boolean;
}

export const DEFAULT_POLICIES: PolicyRule[] = [
  {
    id: 'POL-001',
    name: 'Block Credentials & Private Keys',
    description: 'Enforces fail-closed blocking on private keys, API tokens, JWTs, and database connection URIs.',
    enabled: true,
    priority: 10,
    condition: {
      categories: ['CREDENTIAL'],
      minSeverity: 'HIGH'
    },
    action: 'BLOCK',
    explanation: 'Strict prohibition against forwarding cryptographic keys, credentials, or connection strings to external AI models.'
  },
  {
    id: 'POL-002',
    name: 'Block Application Security Exploits',
    description: 'Intercepts SQL injection, cross-site scripting, command execution, and directory traversal attempts.',
    enabled: true,
    priority: 20,
    condition: {
      categories: ['APPSEC_EXPLOIT'],
      minSeverity: 'HIGH'
    },
    action: 'BLOCK',
    explanation: 'Application security rule: exploit patterns and malicious payloads are blocked at the perimeter.'
  },
  {
    id: 'POL-003',
    name: 'Block Prompt Injections & Jailbreaks',
    description: 'Detects and blocks adversarial prompt injections and system instruction overrides.',
    enabled: true,
    priority: 30,
    condition: {
      categories: ['PROMPT_INJECTION'],
      minSeverity: 'HIGH'
    },
    action: 'BLOCK',
    explanation: 'Guardrail enforcement: instructions attempting to override or jailbreak AI boundaries are rejected.'
  },
  {
    id: 'POL-004',
    name: 'Block Insider Sabotage & Extortion',
    description: 'Enforces immediate perimeter block on malicious insider threats, data hostage attempts, and sabotage.',
    enabled: true,
    priority: 35,
    condition: {
      categories: ['INSIDER_THREAT'],
      minSeverity: 'HIGH'
    },
    action: 'BLOCK',
    explanation: 'Insider threat policy: queries containing extortion, sabotage, or unauthorized exfiltration intents are blocked.'
  },
  {
    id: 'POL-005',
    name: 'Redact Personally Identifiable Information (PII)',
    description: 'Sanitizes employee and customer PII (emails, phone numbers, SSNs) using category-specific redaction tokens.',
    enabled: true,
    priority: 50,
    condition: {
      categories: ['PII'],
      minSeverity: 'MEDIUM'
    },
    action: 'MASK',
    explanation: 'Privacy compliance requirement (GDPR/DPDP): PII is masked before transmission.'
  },
  {
    id: 'POL-006',
    name: 'Block Financial Account Numbers',
    description: 'Blocks credit card numbers and raw corporate financial account numbers.',
    enabled: true,
    priority: 45,
    condition: {
      categories: ['CONFIDENTIAL_FINANCIAL'],
      minSeverity: 'CRITICAL'
    },
    action: 'BLOCK',
    explanation: 'Financial DLP rule: raw payment cards and sensitive financial identifiers are blocked.'
  },
  {
    id: 'POL-007',
    name: 'Mask Internal Identifiers & Cloud URIs',
    description: 'Sanitizes internal server hostnames, RFC1918 IPs, and cloud storage bucket names.',
    enabled: true,
    priority: 60,
    condition: {
      categories: ['INTERNAL_IDENTIFIER', 'CONFIDENTIAL_TECHNICAL'],
      minSeverity: 'MEDIUM'
    },
    action: 'MASK',
    explanation: 'Infrastructure confidentiality: internal identifiers are sanitized prior to AI ingestion.'
  }
];

export class PolicyEngine {
  private policies: PolicyRule[] = [];
  private maskingService: MaskingService;

  constructor(customPolicies?: PolicyRule[]) {
    this.policies = customPolicies && customPolicies.length > 0 ? customPolicies : [...DEFAULT_POLICIES];
    this.maskingService = new MaskingService();
  }

  getPolicies(): PolicyRule[] {
    return [...this.policies];
  }

  setPolicies(policies: PolicyRule[]): void {
    this.policies = [...policies];
  }

  updatePolicy(id: string, updates: Partial<PolicyRule>): boolean {
    const idx = this.policies.findIndex(p => p.id === id);
    if (idx === -1) return false;
    this.policies[idx] = { ...this.policies[idx], ...updates };
    return true;
  }

  addPolicy(policy: PolicyRule): void {
    this.policies.push(policy);
  }

  deletePolicy(id: string): boolean {
    const idx = this.policies.findIndex(p => p.id === id);
    if (idx === -1) return false;
    this.policies.splice(idx, 1);
    return true;
  }

  /**
   * Deterministically evaluates input text and detection findings against active policies and context.
   */
  evaluate(
    rawText: string,
    findings: Finding[],
    evalContext: PolicyEvaluationContext,
    orgContext?: OrganizationContext
  ): PolicyResult {
    // 1. Fail-closed check: System Lockdown
    if (evalContext.isLockdownActive) {
      return {
        decision: 'BLOCK',
        riskScore: 100,
        riskLevel: 'CRITICAL',
        reason: 'Corporate AI Gateway is in emergency Lockdown mode. All external AI interactions are suspended by SOC.',
        triggeredPolicies: [],
        findings: [],
        transformations: []
      };
    }

    // 2. Fail-closed check: User Privacy Consent (except for ADMIN or developer service tokens)
    if (evalContext.userRole === 'USER' && evalContext.hasUserConsent === false) {
      return {
        decision: 'BLOCK',
        riskScore: 90,
        riskLevel: 'HIGH',
        reason: 'User prompt processing halted: User has not granted active Data Privacy and Monitoring consent.',
        triggeredPolicies: [],
        findings: [],
        transformations: []
      };
    }

    // 3. Provider permission check
    if (orgContext && orgContext.allowedProviders && orgContext.allowedProviders.length > 0) {
      if (!orgContext.allowedProviders.includes(evalContext.providerId)) {
        return {
          decision: 'BLOCK',
          riskScore: 85,
          riskLevel: 'HIGH',
          reason: `Access to AI Provider [${evalContext.providerId}] is restricted by corporate organizational policy.`,
          triggeredPolicies: [],
          findings: [],
          transformations: []
        };
      }
    }

    // 4. Calculate Risk Score deterministically from findings and policy mode
    let maxFindingScore = 0;
    for (const f of findings) {
      let score = 20;
      if (f.severity === 'CRITICAL') score = 100;
      else if (f.severity === 'HIGH') score = 75;
      else if (f.severity === 'MEDIUM') score = 45;
      else if (f.severity === 'LOW') score = 25;
      
      score = Math.round(score * f.confidence);
      if (score > maxFindingScore) {
        maxFindingScore = score;
      }
    }

    // Adjust thresholds according to policy mode
    const mode = evalContext.policyMode || 'balanced';
    let blockThreshold = 75;
    let maskThreshold = 30;

    if (mode === 'strict') {
      blockThreshold = 50;
      maskThreshold = 15;
    } else if (mode === 'relaxed') {
      blockThreshold = 95;
      maskThreshold = 45;
    }

    // 5. Match findings against active policy rules
    const triggeredPolicies: PolicyRule[] = [];
    let decision: SecurityAction = 'ALLOW';
    const reasons: string[] = [];

    // Sort policies by priority (ascending: 10 has higher precedence than 50)
    const activePolicies = this.policies
      .filter(p => p.enabled)
      .sort((a, b) => a.priority - b.priority);

    for (const policy of activePolicies) {
      // Check if policy condition matches any finding
      const matchingFindings = findings.filter(f => {
        if (policy.condition.categories && !policy.condition.categories.includes(f.category)) {
          return false;
        }
        if (policy.condition.roles && !policy.condition.roles.includes(evalContext.userRole)) {
          return false;
        }
        if (policy.condition.providerIds && !policy.condition.providerIds.includes(evalContext.providerId)) {
          return false;
        }
        return true;
      });

      if (matchingFindings.length > 0) {
        triggeredPolicies.push(policy);
        reasons.push(`${policy.name}: ${policy.explanation}`);

        if (policy.action === 'BLOCK') {
          decision = 'BLOCK';
          break; // BLOCK has highest precedence
        } else if (policy.action === 'MASK') {
          decision = 'MASK';
        }
      }
    }

    // Direct check for findings requiring immediate block (e.g. from custom organization rules)
    const hasImmediateBlockFinding = findings.some(f => f.recommendedAction === 'BLOCK');
    if (hasImmediateBlockFinding) {
      decision = 'BLOCK';
      if (!reasons.length) {
        reasons.push('Detected restricted entity or credential requiring immediate perimeter blocking.');
      }
    }

    // If score exceeds blockThreshold under strict mode
    if (maxFindingScore >= blockThreshold && decision !== 'BLOCK') {
      decision = 'BLOCK';
      reasons.push(`Cumulative threat risk score (${maxFindingScore}) exceeded policy threshold.`);
    }

    // If score exceeds maskThreshold and currently ALLOW
    if (decision === 'ALLOW' && maxFindingScore >= maskThreshold) {
      decision = 'MASK';
      reasons.push('Prompt sanitized to remove potentially sensitive references before external forwarding.');
    }

    // 6. Perform masking transformations if action is MASK
    let transformations: Array<{ originalLength: number; replacement: string; category: any }> = [];
    if (decision === 'MASK') {
      const maskResult = this.maskingService.mask(rawText, findings);
      transformations = maskResult.transformations.map(t => ({
        originalLength: t.originalLength,
        replacement: t.replacement,
        category: t.category
      }));
    }

    // 7. Determine risk level
    let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
    if (maxFindingScore >= 80 || decision === 'BLOCK') riskLevel = 'CRITICAL';
    else if (maxFindingScore >= 50) riskLevel = 'HIGH';
    else if (maxFindingScore >= 20 || decision === 'MASK') riskLevel = 'MEDIUM';

    // 8. Generate transparent user-facing reason (safe, no secret exposure)
    let finalReason = 'Prompt verified and approved for transmission.';
    if (decision === 'BLOCK') {
      finalReason = reasons.length > 0 
        ? `Request blocked by security policy: ${reasons[0]}`
        : 'Request blocked due to confidential data or security policy violation.';
    } else if (decision === 'MASK') {
      finalReason = `Request sanitized before forwarding: ${reasons.length > 0 ? reasons[0] : 'Sensitive entities redacted'}.`;
    }

    return {
      decision,
      riskScore: maxFindingScore,
      riskLevel,
      reason: finalReason,
      triggeredPolicies,
      findings,
      transformations
    };
  }
}
