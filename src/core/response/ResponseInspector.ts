import { DetectorRegistry } from '../detectors/DetectorRegistry';
import { PolicyEngine } from '../policy/PolicyEngine';
import { MaskingService } from '../masking/MaskingService';
import { Finding, SecurityAction, OrganizationContext } from '../types';

export interface ResponseInspectionResult {
  decision: SecurityAction;
  originalLength: number;
  outputContent: string;
  findings: Finding[];
  isModified: boolean;
  reason: string;
  inspectionLatencyMs: number;
}

export class ResponseInspector {
  private detectorRegistry: DetectorRegistry;
  private policyEngine: PolicyEngine;
  private maskingService: MaskingService;

  constructor(detectors: DetectorRegistry, policyEngine: PolicyEngine) {
    this.detectorRegistry = detectors;
    this.policyEngine = policyEngine;
    this.maskingService = new MaskingService();
  }

  async inspect(
    responseContent: string,
    orgContext?: OrganizationContext,
    providerId?: string
  ): Promise<ResponseInspectionResult> {
    const start = performance.now();
    if (!responseContent || typeof responseContent !== 'string') {
      return {
        decision: 'ALLOW',
        originalLength: 0,
        outputContent: '',
        findings: [],
        isModified: false,
        reason: 'Empty response body.',
        inspectionLatencyMs: 0
      };
    }

    // 1. Run detection on AI response
    const findings = await this.detectorRegistry.runAll(responseContent, orgContext);

    // If no sensitive entities detected in AI response, it is clean and approved
    if (findings.length === 0) {
      return {
        decision: 'ALLOW',
        originalLength: responseContent.length,
        outputContent: responseContent,
        findings: [],
        isModified: false,
        reason: 'AI response inspected and approved for delivery.',
        inspectionLatencyMs: Math.round(performance.now() - start)
      };
    }

    // 2. Evaluate policy on response content findings
    const resolvedProviderId = providerId || orgContext?.allowedProviders?.[0] || 'provider-safe-mock';
    const policyResult = this.policyEngine.evaluate(
      responseContent,
      findings,
      {
        userRole: 'USER',
        userEmail: 'response.inspector@aegis-gateway.internal',
        providerId: resolvedProviderId,
        policyMode: 'balanced',
        isLockdownActive: false,
        hasUserConsent: true
      },
      orgContext
    );

    let outputContent = responseContent;
    let isModified = false;
    let reason = 'AI response inspected and approved for delivery.';

    if (policyResult.decision === 'BLOCK') {
      outputContent = '[SECURITY INTERCEPTION]: The AI provider returned confidential data, credentials, or restricted information that violates organizational security policy. The response has been suppressed.';
      isModified = true;
      reason = `Response blocked by security policy: ${policyResult.reason}`;
    } else if (policyResult.decision === 'MASK') {
      const maskResult = this.maskingService.mask(responseContent, findings);
      outputContent = maskResult.sanitizedText;
      isModified = true;
      reason = 'Response sanitized to remove detected sensitive entities prior to client presentation.';
    }

    const inspectionLatencyMs = Math.round(performance.now() - start);

    return {
      decision: policyResult.decision,
      originalLength: responseContent.length,
      outputContent,
      findings,
      isModified,
      reason,
      inspectionLatencyMs
    };
  }
}
