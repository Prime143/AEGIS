import test from 'node:test';
import assert from 'node:assert';

import { RegexDetector } from '../src/core/detectors/RegexDetector';
import { DictionaryDetector } from '../src/core/detectors/DictionaryDetector';
import { ContextualDetector } from '../src/core/detectors/ContextualDetector';
import { DetectorRegistry } from '../src/core/detectors/DetectorRegistry';
import { MaskingService } from '../src/core/masking/MaskingService';
import { PolicyEngine } from '../src/core/policy/PolicyEngine';
import { ProviderRegistry } from '../src/core/providers/ProviderRegistry';
import { AuditService } from '../src/core/audit/AuditService';
import { GatewayPipeline } from '../src/core/gateway/GatewayPipeline';
import { OrganizationService } from '../src/core/organization/OrganizationService';

test('AEGIS Edge Cases & Security Robustness Suite', async (t) => {
  const registry = new DetectorRegistry();
  const policyEngine = new PolicyEngine();
  const providerRegistry = new ProviderRegistry();
  const auditService = new AuditService();
  const orgService = new OrganizationService();
  const maskingService = new MaskingService();
  const pipeline = new GatewayPipeline(registry, policyEngine, providerRegistry, auditService);

  await t.test('Edge Case 1: Huge Payload (Context Smuggling / Resource Exhaustion)', async () => {
    // 25,000 characters payload
    const hugePrompt = 'A'.repeat(25000);
    const response = await pipeline.processInteraction({
      prompt: hugePrompt,
      userEmail: 'user@nexus-corp.com',
      userRole: 'USER',
      hasUserConsent: true
    });

    assert.strictEqual(response.decision, 'BLOCK');
    assert.strictEqual(response.policyResult.riskLevel, 'CRITICAL');
    assert.ok(response.findings.some(f => f.explanation.includes('Payload length anomaly')));
  });

  await t.test('Edge Case 2: Empty, Null-like, or Whitespace-only Input', async () => {
    const emptyResponse = await pipeline.processInteraction({
      prompt: '   \n\t  ',
      userEmail: 'user@nexus-corp.com',
      userRole: 'USER',
      hasUserConsent: true
    });

    assert.strictEqual(emptyResponse.success, false);
    assert.strictEqual(emptyResponse.decision, 'BLOCK');
  });

  await t.test('Edge Case 3: Repeated Sensitive Values (Deduplication & Multi-masking)', async () => {
    const repeated = 'User email is test@domain.com, please note test@domain.com and also test@domain.com.';
    const findings = await registry.runAll(repeated);
    const masked = maskingService.mask(repeated, findings);

    assert.ok(!masked.sanitizedText.includes('test@domain.com'));
    // All 3 instances must be replaced
    const matches = masked.sanitizedText.match(/\[REDACTED_EMAIL\]/g);
    assert.strictEqual(matches?.length, 3);
  });

  await t.test('Edge Case 4: Overlapping Entity Matches (Priority Resolution)', async () => {
    // Overlapping string containing both host and organization codename
    const text = 'Cluster endpoint dev-cluster.internal.nexus-corp.com is reserved.';
    const findings = await registry.runAll(text, orgService.getContext());

    assert.ok(findings.length >= 1);
    // Overlap should be resolved cleanly without index crash in masking
    const masked = maskingService.mask(text, findings);
    assert.ok(masked.sanitizedText.length > 0);
  });

  await t.test('Edge Case 5: Sensitive Information Split Across Lines & Tabs', async () => {
    const multilineSecret = 'Here is the credential:\npassword\t=\t"MySecretPass99!"\nPlease review.';
    const findings = await registry.runAll(multilineSecret);
    const hasSecretFinding = findings.some(f => f.category === 'CREDENTIAL');
    assert.strictEqual(hasSecretFinding, true);
  });

  await t.test('Edge Case 6: Multilingual Mixed Text (Hindi / Marathi / English mixed context)', async () => {
    const mixedPrompt = 'कृपया पासवर्ड सुरक्षित ठेवा. The admin password is secret_admin_pass_9988 and contact is support@nexus-corp.com.';
    const findings = await registry.runAll(mixedPrompt);

    assert.ok(findings.some(f => f.category === 'CREDENTIAL'));
    assert.ok(findings.some(f => f.category === 'PII'));

    const response = await pipeline.processInteraction({
      prompt: mixedPrompt,
      userEmail: 'user@nexus-corp.com',
      userRole: 'USER',
      hasUserConsent: true
    });

    // Contains credentials -> must be BLOCKED
    assert.strictEqual(response.decision, 'BLOCK');
  });

  await t.test('Edge Case 7: Simultaneous / Concurrent Gateway Requests', async () => {
    const promises = [
      pipeline.processInteraction({ prompt: 'Tell me about React', userEmail: 'u1@corp.com', userRole: 'USER', hasUserConsent: true }),
      pipeline.processInteraction({ prompt: 'API key sk-proj-1234567890abcdef1234567890', userEmail: 'u2@corp.com', userRole: 'USER', hasUserConsent: true }),
      pipeline.processInteraction({ prompt: 'Send email to alice@nexus-corp.com', userEmail: 'u3@corp.com', userRole: 'USER', hasUserConsent: true }),
      pipeline.processInteraction({ prompt: 'Explain Kubernetes pods', userEmail: 'u4@corp.com', userRole: 'USER', hasUserConsent: true })
    ];

    const results = await Promise.all(promises);
    assert.strictEqual(results.length, 4);
    assert.strictEqual(results[0].decision, 'ALLOW');
    assert.strictEqual(results[1].decision, 'BLOCK');
    assert.strictEqual(results[2].decision, 'MASK');
    assert.strictEqual(results[3].decision, 'ALLOW');
  });
});
