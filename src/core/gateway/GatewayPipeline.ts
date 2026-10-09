import { DetectorRegistry } from '../detectors/DetectorRegistry';
import { PolicyEngine } from '../policy/PolicyEngine';
import { MaskingService } from '../masking/MaskingService';
import { ProviderRegistry } from '../providers/ProviderRegistry';
import { ResponseInspector, ResponseInspectionResult } from '../response/ResponseInspector';
import { AuditService } from '../audit/AuditService';
import {
  Finding,
  PolicyResult,
  SecurityAction,
  UserRole,
  OrganizationContext,
  AuditEvent
} from '../types';

export interface GatewayInteractionRequest {
  prompt: string;
  userEmail: string;
  userRole: UserRole;
  providerId?: string;
  policyMode?: 'strict' | 'balanced' | 'relaxed';
  isLockdownActive?: boolean;
  hasUserConsent?: boolean;
  context?: OrganizationContext;
}

export interface GatewayInteractionResponse {
  success: boolean;
  decision: SecurityAction;
  sanitizedPrompt: string;
  responseContent: string;
  policyResult: PolicyResult;
  findings: Finding[];
  responseInspection: ResponseInspectionResult | null;
  auditEvent: AuditEvent;
  executionTiming: {
    detectionLatencyMs: number;
    policyLatencyMs: number;
    providerLatencyMs: number;
    responseInspectionLatencyMs: number;
    totalLatencyMs: number;
  };
  providerMetadata: {
    id: string;
    name: string;
    model: string;
    type: 'mock' | 'external' | 'internal';
    environmentStatus: string;
  };
}

export class GatewayPipeline {
  private detectorRegistry: DetectorRegistry;
  private policyEngine: PolicyEngine;
  private maskingService: MaskingService;
  private providerRegistry: ProviderRegistry;
  private responseInspector: ResponseInspector;
  private auditService: AuditService;

  constructor(
    detectors: DetectorRegistry,
    policyEngine: PolicyEngine,
    providers: ProviderRegistry,
    auditService: AuditService
  ) {
    this.detectorRegistry = detectors;
    this.policyEngine = policyEngine;
    this.maskingService = new MaskingService();
    this.providerRegistry = providers;
    this.responseInspector = new ResponseInspector(detectors, policyEngine);
    this.auditService = auditService;
  }

  getDetectorRegistry(): DetectorRegistry {
    return this.detectorRegistry;
  }

  getPolicyEngine(): PolicyEngine {
    return this.policyEngine;
  }

  getProviderRegistry(): ProviderRegistry {
    return this.providerRegistry;
  }

  getAuditService(): AuditService {
    return this.auditService;
  }

  /**
   * Executes the full perimeter security decision pipeline.
   */
  async processInteraction(request: GatewayInteractionRequest): Promise<GatewayInteractionResponse> {
    const pipelineStartTime = performance.now();
    const rawPrompt = request.prompt || '';
    const userEmail = request.userEmail || 'unknown@nexus-corp.com';
    const userRole = request.userRole || 'USER';
    const requestedProviderId = request.providerId || this.providerRegistry.getActiveProviderId();
    const policyMode = request.policyMode || 'balanced';

    // 1. Input Validation (Fail-closed on malformed or empty input)
    if (!rawPrompt.trim()) {
      const emptyFinding: Finding = {
        id: 'err-empty-prompt',
        category: 'BENIGN',
        severity: 'LOW',
        confidence: 1.0,
        detector: 'GatewayPipelineValidator',
        policyClass: 'POL-VAL-001',
        recommendedAction: 'BLOCK',
        explanation: 'Input prompt is empty or contains only whitespace.'
      };

      const emptyPolicy: PolicyResult = {
        decision: 'BLOCK',
        riskScore: 0,
        riskLevel: 'LOW',
        reason: 'Empty prompt rejected by gateway input validation.',
        triggeredPolicies: [],
        findings: [emptyFinding],
        transformations: []
      };

      const emptyAudit = this.auditService.createEvent({
        rawPrompt: '',
        sanitizedPrompt: '',
        userEmail,
        userRole,
        decision: 'BLOCK',
        riskScore: 0,
        riskLevel: 'LOW',
        findingsSummary: [],
        triggeredPolicyIds: [],
        decisionReason: emptyPolicy.reason,
        providerId: requestedProviderId,
        providerLatencyMs: 0,
        totalLatencyMs: 0,
        responseDecision: 'BLOCK',
        responseSanitized: false
      });

      return {
        success: false,
        decision: 'BLOCK',
        sanitizedPrompt: '',
        responseContent: 'Please enter a valid, non-empty prompt.',
        policyResult: emptyPolicy,
        findings: [emptyFinding],
        responseInspection: null,
        auditEvent: emptyAudit,
        executionTiming: {
          detectionLatencyMs: 0,
          policyLatencyMs: 0,
          providerLatencyMs: 0,
          responseInspectionLatencyMs: 0,
          totalLatencyMs: 0
        },
        providerMetadata: {
          id: requestedProviderId,
          name: 'N/A',
          model: 'none',
          type: 'mock',
          environmentStatus: 'SIMULATED'
        }
      };
    }

    // 2. Sensitive Information Detection
    const detectionStart = performance.now();
    const findings = await this.detectorRegistry.runAll(rawPrompt, request.context);
    const detectionLatencyMs = Math.round(performance.now() - detectionStart);

    // 3. Policy Evaluation & Decision
    const policyStart = performance.now();
    const policyResult = this.policyEngine.evaluate(
      rawPrompt,
      findings,
      {
        userRole,
        userEmail,
        providerId: requestedProviderId,
        policyMode,
        isLockdownActive: request.isLockdownActive,
        hasUserConsent: request.hasUserConsent
      },
      request.context
    );
    const policyLatencyMs = Math.round(performance.now() - policyStart);

    // 4. Input Sanitization (Masking)
    let promptToSend = rawPrompt;
    let sanitizedRepresentation = rawPrompt;

    if (policyResult.decision === 'MASK') {
      const maskResult = this.maskingService.mask(rawPrompt, findings);
      promptToSend = maskResult.sanitizedText;
      sanitizedRepresentation = maskResult.sanitizedText;
    } else if (policyResult.decision === 'BLOCK') {
      sanitizedRepresentation = '[PAYLOAD_BLOCKED_BY_PERIMETER_GATEWAY]';
    }

    // 5. Short-circuit if BLOCKED (Do not send to AI provider!)
    if (policyResult.decision === 'BLOCK') {
      const totalLatencyMs = Math.round(performance.now() - pipelineStartTime);
      const auditEvent = this.auditService.createEvent({
        rawPrompt,
        sanitizedPrompt: sanitizedRepresentation,
        userEmail,
        userRole,
        decision: 'BLOCK',
        riskScore: policyResult.riskScore,
        riskLevel: policyResult.riskLevel,
        findingsSummary: findings.map(f => ({ category: f.category, severity: f.severity, detector: f.detector })),
        triggeredPolicyIds: policyResult.triggeredPolicies.map(p => p.id),
        decisionReason: policyResult.reason,
        providerId: requestedProviderId,
        providerLatencyMs: 0,
        totalLatencyMs,
        responseDecision: 'BLOCK',
        responseSanitized: false
      });

      await this.auditService.writeAuditLog(auditEvent);

      const activeProvider = this.providerRegistry.getProvider(requestedProviderId) || this.providerRegistry.getActiveProvider();

      return {
        success: false,
        decision: 'BLOCK',
        sanitizedPrompt: sanitizedRepresentation,
        responseContent: `[REQUEST BLOCKED]: ${policyResult.reason}`,
        policyResult,
        findings,
        responseInspection: null,
        auditEvent,
        executionTiming: {
          detectionLatencyMs,
          policyLatencyMs,
          providerLatencyMs: 0,
          responseInspectionLatencyMs: 0,
          totalLatencyMs
        },
        providerMetadata: activeProvider.metadata()
      };
    }

    // 6. Forward Approved / Sanitized Request to AI Provider
    let provider = this.providerRegistry.getProvider(requestedProviderId);
    if (!provider || !provider.metadata().isAvailable) {
      provider = this.providerRegistry.getActiveProvider();
    }

    const providerStart = performance.now();
    let providerOutput = '';
    let providerLatencyMs = 0;

    try {
      const providerRes = await provider.sendPrompt({
        prompt: promptToSend,
        systemInstruction: 'You are an enterprise AI assistant. Respect user instructions and maintain corporate confidentiality.'
      });
      providerOutput = providerRes.content;
      providerLatencyMs = providerRes.latencyMs || Math.round(performance.now() - providerStart);
    } catch (err: any) {
      providerLatencyMs = Math.round(performance.now() - providerStart);
      // Graceful provider failure handling (no crashes, clear error)
      providerOutput = `[AI PROVIDER UNAVAILABLE]: Connection to AI provider failed: ${err.message || 'Service unreachable'}. Please try again or switch to Safe Mock Provider.`;
    }

    // 7. Response Inspection
    let responseInspection: ResponseInspectionResult | null = null;
    let finalResponseContent = providerOutput;

    if (providerOutput && !providerOutput.startsWith('[AI PROVIDER UNAVAILABLE]')) {
      responseInspection = await this.responseInspector.inspect(providerOutput, request.context, provider.id);
      finalResponseContent = responseInspection.outputContent;
    }

    const totalLatencyMs = Math.round(performance.now() - pipelineStartTime);

    // 8. Generate and Record Audit Event (Safe from secrets!)
    const auditEvent = this.auditService.createEvent({
      rawPrompt,
      sanitizedPrompt: sanitizedRepresentation,
      userEmail,
      userRole,
      decision: policyResult.decision,
      riskScore: policyResult.riskScore,
      riskLevel: policyResult.riskLevel,
      findingsSummary: findings.map(f => ({ category: f.category, severity: f.severity, detector: f.detector })),
      triggeredPolicyIds: policyResult.triggeredPolicies.map(p => p.id),
      decisionReason: policyResult.reason,
      providerId: provider.id,
      providerLatencyMs,
      totalLatencyMs,
      responseDecision: responseInspection ? responseInspection.decision : 'ALLOW',
      responseSanitized: responseInspection ? responseInspection.isModified : false
    });

    await this.auditService.writeAuditLog(auditEvent);

    return {
      success: true,
      decision: policyResult.decision,
      sanitizedPrompt: sanitizedRepresentation,
      responseContent: finalResponseContent,
      policyResult,
      findings,
      responseInspection,
      auditEvent,
      executionTiming: {
        detectionLatencyMs,
        policyLatencyMs,
        providerLatencyMs,
        responseInspectionLatencyMs: responseInspection ? responseInspection.inspectionLatencyMs : 0,
        totalLatencyMs
      },
      providerMetadata: provider.metadata()
    };
  }
}
