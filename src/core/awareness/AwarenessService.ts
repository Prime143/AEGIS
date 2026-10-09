import { 
  TrainingModule, 
  TrainingAssignment, 
  UserAwarenessProfile, 
  DetectionCategory, 
  UserRole 
} from '../types';
import { LogEvent } from '../../../database';

export const ENTERPRISE_TRAINING_MODULES: TrainingModule[] = [
  {
    id: 'SEC-101',
    title: 'Secrets & API Key Governance in GenAI',
    category: 'CREDENTIAL',
    description: 'Learn safe developer workflows for handling third-party API keys, private certificates, and database connection strings without exposing them to external AI providers.',
    durationMinutes: 8,
    level: 'INTERMEDIATE',
    keyTakeaways: [
      'Never paste active API tokens, private keys, or passwords directly into AI prompts.',
      'Use mock placeholders (e.g. YOUR_API_KEY) and configure secrets via environment variables.',
      'How perimeter gateways intercept cleartext credentials fail-closed before external transit.'
    ],
    actionItem: 'Audit local prompt templates and replace hardcoded credentials with simulated tokens.',
    relevanceExplanation: 'Triggered when the gateway intercepts cleartext secrets, API tokens, or database URIs.'
  },
  {
    id: 'PRIV-201',
    title: 'Client PII & Data Privacy Compliance (GDPR/DPDP)',
    category: 'PII',
    description: 'Guidelines on protecting sensitive personal identifiers (SSNs, phone numbers, client emails, payment cards) in enterprise AI prompts.',
    durationMinutes: 6,
    level: 'BEGINNER',
    keyTakeaways: [
      'Personal data must be redacted or synthetic before feeding into external foundation models.',
      'Understand how automatic gateway masking works and when to use anonymous placeholders.',
      'Compliance obligations under global privacy frameworks (GDPR, DPDP, CCPA).'
    ],
    actionItem: 'Use synthetic identifiers (e.g. Customer-A) when asking AI to draft customer correspondence.',
    relevanceExplanation: 'Triggered when personal data or customer identifiers are detected in prompt payloads.'
  },
  {
    id: 'APPSEC-301',
    title: 'Application Security & Safe Query Prompting',
    category: 'APPSEC_EXPLOIT',
    description: 'Best practices for software developers asking AI for code generation, vulnerability testing, and database query optimization without triggering exploit alarms.',
    durationMinutes: 10,
    level: 'ADVANCED',
    keyTakeaways: [
      'Formulate security queries conceptually rather than pasting live injection payloads.',
      'Avoid running arbitrary unverified AI code directly against production database endpoints.',
      'How perimeter boundary detectors differentiate benign questions from real SQLi/XSS breakouts.'
    ],
    actionItem: 'Frame security code analysis as parameterized examples instead of raw exploit scripts.',
    relevanceExplanation: 'Triggered when code payloads contain SQL injection, script injection, or shell breakout signatures.'
  },
  {
    id: 'AUP-401',
    title: 'Enterprise AI Acceptable Use & Threat Boundaries',
    category: 'PROMPT_INJECTION',
    description: 'Understanding corporate AI safety guardrails, acceptable use boundaries, and the risks of adversarial system prompt extraction attempts.',
    durationMinutes: 7,
    level: 'INTERMEDIATE',
    keyTakeaways: [
      'Jailbreaking instructions or developer-mode exploits violate company acceptable use policies.',
      'Prompt injection techniques can unintentionally poison model context or leak enterprise data.',
      'Report suspected model vulnerabilities through official SOC channels rather than unmonitored probing.'
    ],
    actionItem: 'Review company Acceptable Use Policy regarding prompt integrity and boundary guardrails.',
    relevanceExplanation: 'Triggered when adversarial jailbreak phrases or system override instructions are detected.'
  },
  {
    id: 'IP-501',
    title: 'Protecting Proprietary Code & Trade Secrets',
    category: 'CONFIDENTIAL_TECHNICAL',
    description: 'Safeguarding unreleased R&D codenames, internal system architectures, and proprietary enterprise IP when collaborating with AI tools.',
    durationMinutes: 5,
    level: 'BEGINNER',
    keyTakeaways: [
      'Internal project codenames (such as Orion-Core) and internal hostnames should never be exposed.',
      'Use generic architectural terms (e.g. Service A -> Service B) when discussing workflows with AI.',
      'Gateway glossary controls monitor and redact protected enterprise terms automatically.'
    ],
    actionItem: 'Replace confidential internal codenames with generic descriptions prior to prompt submission.',
    relevanceExplanation: 'Triggered when internal project codenames or confidential glossary terms are matched.'
  },
  {
    id: 'GEN-001',
    title: 'Foundations of Safe & Productive AI Prompting',
    category: 'BENIGN',
    description: 'The baseline onboarding guide for all employees to achieve maximum productivity while adhering to enterprise governance standards.',
    durationMinutes: 5,
    level: 'BEGINNER',
    keyTakeaways: [
      'Overview of how AEGIS secures every interaction at the organizational perimeter.',
      'How to verify prompt results, avoid hallucinations, and use the AI Prompt Console safely.',
      'Your rights under Data Privacy & Monitoring consent agreements.'
    ],
    actionItem: 'Bookmark the AI Prompt Console and verify your data privacy consent status.',
    relevanceExplanation: 'Standard baseline recommendation for all organizational team members.'
  }
];

export class AwarenessService {
  /**
   * Retrieves all available security training modules in the curriculum
   */
  static getModules(): TrainingModule[] {
    return ENTERPRISE_TRAINING_MODULES;
  }

  /**
   * Finds a specific training module by its identifier
   */
  static getModuleById(id: string): TrainingModule | undefined {
    return ENTERPRISE_TRAINING_MODULES.find(m => m.id === id);
  }

  /**
   * Computes an individual employee's security awareness posture profile,
   * calculating their awareness score, primary knowledge gaps, tailored training
   * recommendations, and an explainable executive coaching report.
   */
  static computeProfile(
    userEmail: string,
    userRole: UserRole,
    userLogs: LogEvent[],
    userTrainings: TrainingAssignment[] = []
  ): UserAwarenessProfile {
    const totalInteractions = userLogs.length;
    const cleanInteractions = userLogs.filter(l => l.action === 'ALLOW').length;
    const violationsCount = userLogs.filter(l => l.action !== 'ALLOW').length;
    const blockedCount = userLogs.filter(l => l.action === 'BLOCK').length;
    const maskedCount = userLogs.filter(l => l.action === 'MODIFIED').length;

    // Count completions
    const completedTrainingsCount = userTrainings.filter(t => t.status === 'COMPLETED').length;

    // Compute Awareness Score (0 to 100)
    let score = 100;

    if (totalInteractions === 0) {
      // New user baseline
      score = 95;
    } else {
      // Deduct for perimeter violations
      score -= (blockedCount * 14); // Blocks are critical perimeter stops
      score -= (maskedCount * 5);    // Masks are privacy/sanitization warnings

      // Reward clean consistent compliant usage
      const cleanBonus = Math.min(15, Math.floor(cleanInteractions / 3) * 2);
      score += cleanBonus;

      // Reward completed training remediation modules
      score += (completedTrainingsCount * 10);

      // Clamp between 15 and 100
      score = Math.max(15, Math.min(100, Math.round(score)));
    }

    // Determine Posture Tier
    let postureTier: 'EXEMPLARY' | 'GOOD' | 'NEEDS_COACHING' | 'HIGH_RISK';
    if (score >= 90) {
      postureTier = 'EXEMPLARY';
    } else if (score >= 75) {
      postureTier = 'GOOD';
    } else if (score >= 50) {
      postureTier = 'NEEDS_COACHING';
    } else {
      postureTier = 'HIGH_RISK';
    }

    // Identify Primary Knowledge Gaps from violation history
    const gapMap: Record<string, number> = {};
    for (const log of userLogs) {
      if (log.action !== 'ALLOW') {
        const cat = log.attack_type || 'General Policy';
        gapMap[cat] = (gapMap[cat] || 0) + 1;
      }
    }

    const primaryGaps = Object.entries(gapMap)
      .sort((a, b) => b[1] - a[1])
      .map(([cat, count]) => {
        let description = `Encountered ${count} incident(s) involving ${cat}.`;
        if (cat === 'CREDENTIAL') {
          description = `Attempted transmission of API keys, private keys, or passwords (${count} event${count > 1 ? 's' : ''}).`;
        } else if (cat === 'PII') {
          description = `Inadvertent inclusion of customer or employee personal identifiers (${count} event${count > 1 ? 's' : ''}).`;
        } else if (cat === 'PROMPT_INJECTION') {
          description = `Use of adversarial prompt override or jailbreak styling (${count} event${count > 1 ? 's' : ''}).`;
        } else if (cat === 'APPSEC_EXPLOIT') {
          description = `Inclusion of live SQL injection or web attack test payloads (${count} event${count > 1 ? 's' : ''}).`;
        } else if (cat === 'CONFIDENTIAL_TECHNICAL') {
          description = `References to confidential internal codenames or project assets (${count} event${count > 1 ? 's' : ''}).`;
        }
        return {
          category: cat,
          incidentCount: count,
          description
        };
      });

    // Determine Recommended Modules
    const recommendedModules: TrainingModule[] = [];
    const recommendedIds = new Set<string>();

    for (const gap of primaryGaps) {
      const matchingModule = ENTERPRISE_TRAINING_MODULES.find(m => m.category === gap.category);
      if (matchingModule && !recommendedIds.has(matchingModule.id)) {
        recommendedModules.push(matchingModule);
        recommendedIds.add(matchingModule.id);
      }
    }

    // If user has no specific gaps, recommend baseline AI safety module
    if (recommendedModules.length === 0) {
      const baseline = ENTERPRISE_TRAINING_MODULES.find(m => m.id === 'GEN-001')!;
      recommendedModules.push(baseline);
    }

    // Map assigned modules with details
    const assignedWithDetails = userTrainings.map(t => {
      const mod = this.getModuleById(t.moduleId);
      return {
        ...t,
        moduleTitle: mod?.title || t.moduleId,
        durationMinutes: mod?.durationMinutes || 5
      };
    });

    // Recent Incidents
    const recentIncidentsSummary = userLogs
      .filter(l => l.action !== 'ALLOW')
      .slice(0, 5)
      .map(l => ({
        id: l.id,
        timestamp: l.timestamp,
        attackType: l.attack_type || 'Policy Violation',
        action: l.action === 'MODIFIED' ? 'MASKED' : l.action,
        riskScore: l.risk_score
      }));

    // AI Executive Coaching Summary
    const aiExecutiveSummary = this.generateExecutiveSummary(
      userEmail,
      postureTier,
      score,
      totalInteractions,
      violationsCount,
      primaryGaps,
      completedTrainingsCount
    );

    return {
      userEmail,
      userRole,
      totalInteractions,
      cleanInteractions,
      violationsCount,
      blockedCount,
      maskedCount,
      awarenessScore: score,
      postureTier,
      primaryGaps,
      recommendedModules,
      assignedModules: assignedWithDetails,
      recentIncidentsSummary,
      aiExecutiveSummary,
      lastEvaluatedAt: new Date().toISOString()
    };
  }

  /**
   * Generates a constructive, transparent, non-punitive executive summary
   * evaluating the user's security posture and specific micro-learning needs.
   */
  private static generateExecutiveSummary(
    userEmail: string,
    tier: string,
    score: number,
    total: number,
    violations: number,
    gaps: Array<{ category: string; incidentCount: number }>,
    completed: number
  ): string {
    const name = userEmail.split('@')[0];

    if (total === 0) {
      return `Welcome ${name}. You have not yet submitted prompts through the AEGIS security boundary. Your initial posture is Exemplary (${score}/100). We recommend reviewing the foundational module GEN-001 to familiarize yourself with enterprise AI acceptable use.`;
    }

    if (violations === 0) {
      return `Excellent security posture! User ${name} has logged ${total} compliant interaction(s) with 0 policy violations (${score}/100 score). Consistent safe prompting habits have been demonstrated across all external AI routes. Baseline refresher training is available if desired.`;
    }

    const gapNames = gaps.map(g => `${g.category} (${g.incidentCount})`).join(', ');

    if (tier === 'EXEMPLARY' || tier === 'GOOD') {
      return `Solid security awareness (${score}/100). Out of ${total} total prompts, ${violations} required perimeter sanitization or masking. Most interactions adhere to enterprise safety standards. Primary area for micro-coaching: ${gapNames}. Completing the recommended micro-modules will bring posture to the Exemplary tier.`;
    }

    if (tier === 'NEEDS_COACHING') {
      return `Targeted security training recommended for ${name} (${score}/100). The gateway recorded ${violations} policy interception(s) across recent interactions. Telemetry indicates recurring blind spots in: ${gapNames}. Just-in-time micro-training has been queued to prevent inadvertent data exposure.`;
    }

    return `Immediate security remediation required for ${name} (${score}/100 - High Risk). Multiple high-severity perimeter blocks were triggered due to repeated violations in: ${gapNames}. Administrator review and completion of assigned remediation curriculum is recommended before high-volume AI usage continues.`;
  }
}
