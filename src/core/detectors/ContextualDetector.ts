import { Detector } from './Detector';
import { Finding, DetectionCategory, Severity, SecurityAction } from '../types';

interface ContextRule {
  id: string;
  name: string;
  category: DetectionCategory;
  severity: Severity;
  recommendedAction: SecurityAction;
  policyClass: string;
  keywords: string[];
  explanation: string;
}

export class ContextualDetector implements Detector {
  readonly id = 'detector-contextual';
  readonly name = 'Contextual Threat & Injection Detector';
  readonly description = 'Analyzes prompt intent for prompt injection, jailbreaks, insider threats, sabotage, and covert exfiltration heuristics.';
  readonly version = '2.0.0';
  readonly isDeterministic = true;

  private rules: ContextRule[] = [
    {
      id: 'ctx-prompt-injection',
      name: 'Prompt Injection / Jailbreak Attack',
      category: 'PROMPT_INJECTION',
      severity: 'CRITICAL',
      recommendedAction: 'BLOCK',
      policyClass: 'POL-INJECTION-001',
      keywords: [
        'ignore previous instructions',
        'ignore all previous instructions',
        'act as a developer mode',
        'developer mode enabled',
        'you are an unfiltered ai',
        'ignore all safety',
        'do anything now',
        'dan mode',
        'jailbreak',
        'disregard corporate policies',
        'system prompt override'
      ],
      explanation: 'Detected adversarial attempt to override system guardrails or execute prompt injection / jailbreak.'
    },
    {
      id: 'ctx-insider-sabotage',
      name: 'Insider Sabotage & Malicious Intent',
      category: 'INSIDER_THREAT',
      severity: 'CRITICAL',
      recommendedAction: 'BLOCK',
      policyClass: 'POL-INSIDER-001',
      keywords: [
        'logic bomb',
        'backdoor',
        'deletes all corporate dbs',
        'deletes prod db',
        'destroy database',
        'wipe disk',
        'disable antivirus',
        'disable edr',
        'bypass edr'
      ],
      explanation: 'Detected indicators of corporate sabotage, backdoors, or malicious system destruction.'
    },
    {
      id: 'ctx-extortion-data-hostage',
      name: 'Extortion & Data Hostage',
      category: 'INSIDER_THREAT',
      severity: 'CRITICAL',
      recommendedAction: 'BLOCK',
      policyClass: 'POL-INSIDER-002',
      keywords: [
        'until my money is paid',
        'demand my money',
        'keeping all client db',
        'holding data hostage',
        'will leak client data',
        'sell to competitor',
        'ransom data',
        'extort management'
      ],
      explanation: 'Detected extortion, blackmail, or holding corporate data hostage.'
    },
    {
      id: 'ctx-privilege-escalation',
      name: 'Privilege Escalation & Reconnaissance',
      category: 'APPSEC_EXPLOIT',
      severity: 'HIGH',
      recommendedAction: 'BLOCK',
      policyClass: 'POL-EXPLOIT-005',
      keywords: [
        'root access',
        'bypass uac',
        'modify sudoers',
        'privilege escalation script',
        'dump ntds.dit',
        'mimikatz',
        'dump lsass'
      ],
      explanation: 'Detected offensive privilege escalation or credential dumping reconnaissance.'
    },
    {
      id: 'ctx-covert-exfiltration',
      name: 'Covert Data Exfiltration & DLP Evasion',
      category: 'INSIDER_THREAT',
      severity: 'HIGH',
      recommendedAction: 'BLOCK',
      policyClass: 'POL-INSIDER-003',
      keywords: [
        'bypass dlp',
        'covert channel',
        'dns tunneling',
        'shadow it',
        'vpn bypass',
        'shadow it with a vpn bypass',
        'exfiltrate undetected',
        'hide traffic from soc'
      ],
      explanation: 'Detected intent to establish covert exfiltration channels or deliberately circumvent DLP controls.'
    },
    {
      id: 'ctx-confidential-hr',
      name: 'Confidential Executive & Compensation Query',
      category: 'CONFIDENTIAL_FINANCIAL',
      severity: 'HIGH',
      recommendedAction: 'BLOCK',
      policyClass: 'POL-HR-001',
      keywords: [
        'ceo email',
        'manager salary',
        'salary band',
        'salary bands',
        'layoff list',
        'termination list'
      ],
      explanation: 'Detected unauthorized query targeting sensitive executive identifiers or confidential salary bands.'
    }
  ];

  analyze(input: string, _context?: any): Finding[] {
    if (!input || typeof input !== 'string') return [];

    const findings: Finding[] = [];
    const normalized = input.toLowerCase().replace(/[\u200B-\u200D\uFEFF]/g, '');

    // Check payload size anomaly (Resource exhaustion / Context Smuggling)
    if (input.length > 20000) {
      findings.push({
        id: 'ctx-anomaly-length',
        category: 'APPSEC_EXPLOIT',
        severity: 'HIGH',
        confidence: 0.90,
        detector: this.name,
        matchedSpan: {
          start: 0,
          end: Math.min(input.length, 100),
          text: input.substring(0, 100) + '...',
          maskedReplacement: '[PAYLOAD_TRUNCATED]'
        },
        policyClass: 'POL-EXPLOIT-006',
        recommendedAction: 'BLOCK',
        explanation: `Payload length anomaly (${input.length} characters) indicates potential context smuggling or resource exhaustion attack.`
      });
    }

    for (const rule of this.rules) {
      for (const kw of rule.keywords) {
        const index = normalized.indexOf(kw);
        if (index !== -1) {
          findings.push({
            id: `${rule.id}-${index}`,
            category: rule.category,
            severity: rule.severity,
            confidence: 0.92,
            detector: this.name,
            matchedSpan: {
              start: index,
              end: index + kw.length,
              text: input.substring(index, index + kw.length),
              maskedReplacement: `[REDACTED_${rule.category}]`
            },
            policyClass: rule.policyClass,
            recommendedAction: rule.recommendedAction,
            explanation: `${rule.explanation} Matched keyword phrase: "${kw}".`
          });
          break; // Avoid duplicate findings for same rule
        }
      }
    }

    return findings;
  }
}
