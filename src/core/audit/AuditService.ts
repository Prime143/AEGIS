import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { AuditEvent, SecurityAction, Severity, DetectionCategory, UserRole } from '../types';

export class AuditService {
  private logFilePath: string;

  constructor(logFilePath?: string) {
    this.logFilePath = logFilePath || path.resolve('aegis-audit.log');
  }

  /**
   * Hashes a string using SHA-256 for integrity and deduplication without exposing plaintext.
   */
  hashString(input: string): string {
    return crypto.createHash('sha256').update(input || '').digest('hex');
  }

  /**
   * Generates a pseudonymous user identifier from email for audit storage.
   */
  pseudonymizeUser(email: string): string {
    if (!email) return 'usr-anonymous';
    const hash = crypto.createHash('sha256').update(email.toLowerCase()).digest('hex').substring(0, 12);
    return `usr-${hash}`;
  }

  /**
   * Formats and safely writes an audit event to the append-only audit log file.
   */
  async writeAuditLog(event: AuditEvent): Promise<void> {
    const logLine = JSON.stringify({
      eventId: event.id,
      timestamp: event.timestamp,
      userId: event.userId,
      role: event.userRole,
      requestHash: event.requestHash,
      decision: event.decision,
      riskScore: event.riskScore,
      riskLevel: event.riskLevel,
      findingsCount: event.findingsCount,
      findings: event.findingsSummary,
      policies: event.triggeredPolicyIds,
      providerId: event.providerId,
      totalLatencyMs: event.totalLatencyMs,
      responseDecision: event.responseDecision,
      alertStatus: event.alertStatus,
      sanitizedSnippet: event.sanitizedPrompt.substring(0, 120)
    }) + '\n';

    try {
      await fs.appendFile(this.logFilePath, logLine, 'utf8');
    } catch (err) {
      console.error('AuditService: Failed to append to audit log file:', err);
    }
  }

  /**
   * Constructs an AuditEvent without storing raw passwords, keys, or sensitive text.
   */
  createEvent(params: {
    rawPrompt: string;
    sanitizedPrompt: string;
    userEmail: string;
    userRole: UserRole;
    decision: SecurityAction;
    riskScore: number;
    riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    findingsSummary: Array<{ category: DetectionCategory; severity: Severity; detector: string }>;
    triggeredPolicyIds: string[];
    decisionReason: string;
    providerId: string;
    providerLatencyMs: number;
    totalLatencyMs: number;
    responseDecision: SecurityAction;
    responseSanitized: boolean;
  }): AuditEvent {
    const timestamp = new Date().toISOString();
    const eventId = `aegis-evt-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const requestHash = this.hashString(params.rawPrompt);
    const userId = this.pseudonymizeUser(params.userEmail);

    return {
      id: eventId,
      timestamp,
      userId,
      userEmail: params.userEmail,
      userRole: params.userRole,
      requestHash,
      // Store ONLY the sanitized/redacted representation, NEVER the raw sensitive prompt
      sanitizedPrompt: params.decision === 'BLOCK' ? '[REDACTED_BLOCKED_PAYLOAD]' : params.sanitizedPrompt,
      decision: params.decision,
      riskScore: params.riskScore,
      riskLevel: params.riskLevel,
      findingsCount: params.findingsSummary.length,
      findingsSummary: params.findingsSummary,
      triggeredPolicyIds: params.triggeredPolicyIds,
      decisionReason: params.decisionReason,
      providerId: params.providerId,
      providerLatencyMs: params.providerLatencyMs,
      totalLatencyMs: params.totalLatencyMs,
      responseDecision: params.responseDecision,
      responseSanitized: params.responseSanitized,
      alertStatus: params.decision === 'BLOCK' ? 'TRIGGERED' : 'NOT TRIGGERED'
    };
  }
}
