/**
 * AEGIS: AI-Enabled Governance & Information Security
 * Core Domain Types & Interfaces
 */

export type UserRole = 'ADMIN' | 'SECURITY_ANALYST' | 'USER';

export interface UserSession {
  id: string;
  email: string;
  role: UserRole;
  token: string;
}

export type DetectionCategory =
  | 'CREDENTIAL'
  | 'PII'
  | 'INTERNAL_IDENTIFIER'
  | 'CONFIDENTIAL_TECHNICAL'
  | 'CONFIDENTIAL_FINANCIAL'
  | 'APPSEC_EXPLOIT'
  | 'PROMPT_INJECTION'
  | 'INSIDER_THREAT'
  | 'BENIGN';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type SecurityAction = 'ALLOW' | 'MASK' | 'BLOCK';

export interface MatchedSpan {
  start: number;
  end: number;
  text?: string;
  maskedReplacement?: string;
}

export interface Finding {
  id: string;
  category: DetectionCategory;
  severity: Severity;
  confidence: number; // Deterministic value between 0.0 and 1.0
  detector: string;
  matchedSpan?: MatchedSpan;
  policyClass: string;
  recommendedAction: SecurityAction;
  explanation: string;
  remediation?: string;
}

export interface OrganizationContext {
  organizationName: string;
  dataClassifications: Array<{
    id: string;
    name: string;
    level: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
    description: string;
  }>;
  glossary: Array<{
    id: string;
    term: string;
    category: DetectionCategory;
    classification: 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
    placeholder?: string;
  }>;
  sensitiveEntities: Array<{
    id: string;
    name: string;
    pattern: string;
    type: 'keyword' | 'regex';
    action: SecurityAction;
    placeholder?: string;
    explanation: string;
  }>;
  allowedProviders: string[];
  retentionDays: number;
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  condition: {
    categories?: DetectionCategory[];
    minSeverity?: Severity;
    minConfidence?: number;
    roles?: UserRole[];
    providerIds?: string[];
  };
  action: SecurityAction;
  explanation: string;
}

export interface PolicyResult {
  decision: SecurityAction;
  riskScore: number; // 0 - 100
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  reason: string;
  triggeredPolicies: PolicyRule[];
  findings: Finding[];
  transformations: Array<{
    originalLength: number;
    replacement: string;
    category: DetectionCategory;
  }>;
}

export interface ProviderRequest {
  prompt: string;
  temperature?: number;
  maxTokens?: number;
  systemInstruction?: string;
}

export interface ProviderResponse {
  content: string;
  providerId: string;
  model: string;
  latencyMs: number;
  tokenUsage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
}

export interface AIProviderMetadata {
  id: string;
  name: string;
  type: 'mock' | 'external' | 'internal';
  model: string;
  isAvailable: boolean;
  description: string;
  environmentStatus: 'CONFIGURED' | 'NOT_CONFIGURED' | 'SIMULATED';
}

export interface AIProvider {
  id: string;
  metadata(): AIProviderMetadata;
  healthCheck(): Promise<{ status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE'; latencyMs: number; message?: string }>;
  sendPrompt(request: ProviderRequest): Promise<ProviderResponse>;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  userId: string; // Pseudonymous identifier or hashed representation
  userEmail: string;
  userRole: UserRole;
  requestHash: string; // SHA-256 of original input
  sanitizedPrompt: string; // Redacted prompt; raw confidential input is NEVER logged
  decision: SecurityAction;
  riskScore: number;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  findingsCount: number;
  findingsSummary: Array<{
    category: DetectionCategory;
    severity: Severity;
    detector: string;
  }>;
  triggeredPolicyIds: string[];
  decisionReason: string;
  providerId: string;
  providerLatencyMs: number;
  totalLatencyMs: number;
  responseDecision: SecurityAction;
  responseSanitized: boolean;
  alertStatus: 'TRIGGERED' | 'NOT TRIGGERED';
  isSimulated?: boolean;
}

export interface SystemHealthReport {
  timestamp: string;
  status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE';
  components: {
    gateway: { status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE'; latencyMs: number; details: string };
    detectors: { status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE'; activeCount: number; details: string };
    policyEngine: { status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE'; activePolicies: number; details: string };
    database: { status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE'; logCount: number; details: string };
    aiProviders: { status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE'; activeProvider: string; details: string };
    auditSystem: { status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE'; details: string };
  };
}

export interface ExperimentDatasetRecord {
  id: string;
  prompt: string;
  label: 'SENSITIVE' | 'BENIGN';
  category: DetectionCategory;
  organizationTerm?: string;
  termSeenInTraining: boolean;
  templateFamily: string;
  split: 'TRAIN' | 'DEV' | 'TEST';
}

export interface BenchmarkMetrics {
  detectorId: string;
  detectorName: string;
  datasetSplit: 'TRAIN' | 'DEV' | 'TEST';
  totalEvaluated: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
  averageLatencyMs: number;
  falsePositiveRate?: number;
  falseNegativeRate?: number;
  p50LatencyMs?: number;
  p95LatencyMs?: number;
  timestamp: string;
}

export interface PerClassMetric {
  support: number;
  detected?: number;
  recall?: number;
  specificity?: number;
  falseNegatives?: number;
  falsePositives?: number;
}

export interface ComprehensiveExperimentMetrics {
  conditionId: string; // 'B0' | 'B1' | 'B2' | 'B3' | 'A0' | 'A1' | 'A2'
  conditionName: string;
  categoryType: 'BASELINE' | 'ADAPTATION_LADDER';
  executionStatus: 'EXECUTED' | 'INTERFACE_AUDITED_NO_CUSTOM_DLP_SUPPORT' | 'API_KEY_NOT_CONFIGURED' | 'ENVIRONMENT_MISSING_DEPENDENCIES';
  datasetSplit: 'TRAIN' | 'DEV' | 'TEST';
  totalEvaluated: number;
  confusionMatrix: {
    truePositives: number;
    falsePositives: number;
    trueNegatives: number;
    falseNegatives: number;
  };
  metrics: {
    precision: number;
    recall: number;
    f1Score: number;
    falsePositiveRate: number;
    falseNegativeRate: number;
  };
  seenVsUnseen: {
    seen: { precision: number; recall: number; f1Score: number; evaluated: number };
    unseen: { precision: number; recall: number; f1Score: number; evaluated: number };
    deltaF1: number;
  };
  hardNegatives: {
    evaluated: number;
    falsePositives: number;
    fpr: number;
  };
  perClass: Record<string, PerClassMetric>;
  latencyMs: {
    p50: number;
    p95: number;
    mean: number;
  };
  memoryUsage?: {
    heapUsedMb: number;
    rssMb: number;
  };
  modelMetadata?: {
    modelName: string;
    modelVersion: string;
    parameterCount: string;
    quantization: string;
    trainingMethod: string;
    trainingFramework: string;
    inferenceFramework: string;
    hardware: string;
    softwareVersions: string;
  };
  timestamp: string;
}

export interface ExperimentManifest {
  manifestVersion: string;
  researchQuestion: string;
  targetOrganization: string;
  datasetVersion: string;
  gitCommitHash: string;
  executionTimestamp: string;
  deterministicSeed: number;
  hardware: {
    cpu: string;
    cores: number;
    threads: number;
    ramTotalMb: number;
    gpu: string;
  };
  software: {
    os: string;
    nodeVersion: string;
    pythonVersion: string;
    spacyVersion?: string;
    presidioVersion?: string;
  };
  thresholds: {
    decisionThreshold: number;
    presidioConfidenceThreshold: number;
    thresholdTuningSplit: 'DEV';
    evaluationSplit: 'TEST';
  };
  conditions: Record<string, ComprehensiveExperimentMetrics>;
}

// ---------------------------------------------------------------------------
// Security Awareness & Human Risk Management (HRM) Interfaces
// ---------------------------------------------------------------------------

export interface TrainingModule {
  id: string;
  title: string;
  category: DetectionCategory;
  description: string;
  durationMinutes: number;
  level: 'BEGINNER' | 'INTERMEDIATE' | 'ADVANCED';
  keyTakeaways: string[];
  actionItem: string;
  relevanceExplanation: string;
}

export interface TrainingAssignment {
  id: string;
  userEmail: string;
  moduleId: string;
  status: 'ASSIGNED' | 'COMPLETED';
  assignedBy: string;
  assignedAt: string;
  completedAt?: string;
}

export interface UserAwarenessProfile {
  userEmail: string;
  userRole: UserRole;
  totalInteractions: number;
  cleanInteractions: number;
  violationsCount: number;
  blockedCount: number;
  maskedCount: number;
  awarenessScore: number; // 0 to 100
  postureTier: 'EXEMPLARY' | 'GOOD' | 'NEEDS_COACHING' | 'HIGH_RISK';
  primaryGaps: Array<{
    category: DetectionCategory | string;
    incidentCount: number;
    description: string;
  }>;
  recommendedModules: TrainingModule[];
  assignedModules: Array<TrainingAssignment & { moduleTitle: string; durationMinutes: number }>;
  recentIncidentsSummary: Array<{
    id: string;
    timestamp: string;
    attackType: string;
    action: string;
    riskScore: number;
  }>;
  aiExecutiveSummary: string;
  lastEvaluatedAt: string;
}

