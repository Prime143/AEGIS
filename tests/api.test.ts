import test from 'node:test';
import assert from 'node:assert';
import http from 'http';

// Configure environment for test execution
process.env.PORT = '3099';
process.env.AUTO_START_SERVER = 'false';
process.env.NODE_ENV = 'test';

import { startServer } from '../server';

test('AEGIS HTTP API & Gateway Integration Test Suite', async (t) => {
  let serverInstance: http.Server;
  let baseUrl: string;

  let adminToken: string;
  let analystToken: string;
  let userToken: string;

  // Spin up test server on dedicated port 3099
  const { server } = await startServer();
  serverInstance = server;
  baseUrl = 'http://127.0.0.1:3099';

  t.after(async () => {
    if (typeof (serverInstance as any).closeAllConnections === 'function') {
      (serverInstance as any).closeAllConnections();
    }
    await new Promise<void>((resolve) => serverInstance.close(() => resolve()));
  });

  await t.test('1. Authentication: Issues valid session tokens for ADMIN, ANALYST, and USER', async () => {
    // 1. Admin login
    const adminRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin.soc@nexus-corp.com', role: 'ADMIN' })
    });
    assert.strictEqual(adminRes.status, 200);
    const adminData = await adminRes.json();
    assert.ok(adminData.token.startsWith('aegis_admin_sess_'));
    assert.strictEqual(adminData.user.role, 'ADMIN');
    adminToken = adminData.token;

    // 2. Analyst login
    const analystRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'analyst@nexus-corp.com', role: 'SECURITY_ANALYST' })
    });
    assert.strictEqual(analystRes.status, 200);
    const analystData = await analystRes.json();
    assert.ok(analystData.token.startsWith('aegis_security_analyst_sess_'));
    assert.strictEqual(analystData.user.role, 'SECURITY_ANALYST');
    analystToken = analystData.token;

    // 3. User login
    const userRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'current.user@nexus-corp.com', role: 'USER' })
    });
    assert.strictEqual(userRes.status, 200);
    const userData = await userRes.json();
    assert.ok(userData.token.startsWith('aegis_user_sess_'));
    assert.strictEqual(userData.user.role, 'USER');
    userToken = userData.token;

    // Verify /api/auth/me
    const meRes = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(meRes.status, 200);
    const meData = await meRes.json();
    assert.strictEqual(meData.user.email, 'admin.soc@nexus-corp.com');
  });

  await t.test('2. RBAC Access Control: Enforces route authorization boundaries', async () => {
    // Admin can read audit logs
    const adminLogsRes = await fetch(`${baseUrl}/api/logs`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(adminLogsRes.status, 200);
    const logs = await adminLogsRes.json();
    assert.ok(Array.isArray(logs));

    // Security Analyst can read audit logs
    const analystLogsRes = await fetch(`${baseUrl}/api/logs`, {
      headers: { 'Authorization': `Bearer ${analystToken}` }
    });
    assert.strictEqual(analystLogsRes.status, 200);

    // Standard User is forbidden from reading organizational audit logs
    const userLogsRes = await fetch(`${baseUrl}/api/logs`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });
    assert.strictEqual(userLogsRes.status, 403);

    // Standard User CAN export their own DSAR interaction logs
    const dsarRes = await fetch(`${baseUrl}/api/dsar/export?email=current.user@nexus-corp.com`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });
    assert.strictEqual(dsarRes.status, 200);
    const dsarData = await dsarRes.json();
    assert.strictEqual(dsarData.user, 'current.user@nexus-corp.com');
    assert.ok(Array.isArray(dsarData.interactions));
  });

  await t.test('3. Gateway Interaction: Benign request is ALLOWED and returned by AI provider', async () => {
    const res = await fetch(`${baseUrl}/api/gateway/interact`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        prompt: 'What are the main architectural benefits of immutable data structures?'
      })
    });

    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.decision, 'ALLOW');
    assert.strictEqual(data.success, true);
    assert.ok(data.responseContent.length > 0);
    assert.ok(data.auditEvent.id.length > 0);
  });

  await t.test('4. Gateway Interaction: PII is MASKED before transmission', async () => {
    const res = await fetch(`${baseUrl}/api/gateway/interact`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        prompt: 'Please draft a welcome email for candidate whose email is alice.smith@external.com and phone is +1 800-555-0199.'
      })
    });

    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.decision, 'MASK');
    // Sensitive raw values must NOT be present in sanitized output
    assert.ok(!data.sanitizedPrompt.includes('alice.smith@external.com'));
    assert.ok(!data.sanitizedPrompt.includes('+1 800-555-0199'));
    assert.ok(data.sanitizedPrompt.includes('[REDACTED_EMAIL]'));
    assert.ok(data.sanitizedPrompt.includes('[REDACTED_PHONE]'));
  });

  await t.test('5. Gateway Interaction: AWS Keys & Private Keys are BLOCKED fail-closed', async () => {
    const res = await fetch(`${baseUrl}/api/gateway/interact`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        prompt: 'Is this production AWS key AKIAIOSFODNN7EXAMPLE active in IAM?'
      })
    });

    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.decision, 'BLOCK');
    assert.strictEqual(data.success, false);
    assert.ok(data.responseContent.includes('[REQUEST BLOCKED]'));
    assert.strictEqual(data.policyResult.riskLevel, 'CRITICAL');
  });

  await t.test('6. Fail-Closed Privacy Consent (GDPR / DPDP): Blocks USER when consent withdrawn', async () => {
    const testEmail = 'gdpr.test@nexus-corp.com';
    
    // 1. Login as test user
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail, role: 'USER' })
    });
    const { token: testToken } = await loginRes.json();

    // 2. Explicitly revoke consent
    const revokeConsentRes = await fetch(`${baseUrl}/api/consent`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${testToken}`
      },
      body: JSON.stringify({ email: testEmail, granted: false })
    });
    assert.strictEqual(revokeConsentRes.status, 200);

    // 3. Prompt submission must now be BLOCKED due to lack of consent
    const blockedPromptRes = await fetch(`${baseUrl}/api/gateway/interact`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${testToken}`
      },
      body: JSON.stringify({ prompt: 'Tell me about python decorators' })
    });
    const blockedData = await blockedPromptRes.json();
    assert.strictEqual(blockedData.decision, 'BLOCK');
    assert.ok(blockedData.policyResult.reason.includes('consent'));

    // 4. Grant consent
    const grantConsentRes = await fetch(`${baseUrl}/api/consent`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${testToken}`
      },
      body: JSON.stringify({ email: testEmail, granted: true })
    });
    assert.strictEqual(grantConsentRes.status, 200);

    // 5. Subsequent prompt now succeeds
    const allowedPromptRes = await fetch(`${baseUrl}/api/gateway/interact`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${testToken}`
      },
      body: JSON.stringify({ prompt: 'Tell me about python decorators' })
    });
    const allowedData = await allowedPromptRes.json();
    assert.strictEqual(allowedData.decision, 'ALLOW');
  });

  await t.test('7. Developer API Keys: Supports creation, service-to-service auth, and revocation', async () => {
    // 1. Create Developer API Key as Admin
    const createRes = await fetch(`${baseUrl}/api/keys`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({ name: 'IntegrationTestServiceBot', role: 'USER' })
    });
    assert.strictEqual(createRes.status, 200);
    const keyData = await createRes.json();
    assert.ok(keyData.key.startsWith('aegis_user_'));
    const generatedKey = keyData.key;
    const generatedKeyId = keyData.id;

    // 2. Use Developer API Key to send prompt (bypasses interactive consent)
    const promptWithKeyRes = await fetch(`${baseUrl}/api/gateway/interact`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${generatedKey}`
      },
      body: JSON.stringify({ prompt: 'Automated CI system status query' })
    });
    assert.strictEqual(promptWithKeyRes.status, 200);
    const promptData = await promptWithKeyRes.json();
    assert.strictEqual(promptData.decision, 'ALLOW');

    // 3. Revoke Developer API Key
    const revokeRes = await fetch(`${baseUrl}/api/keys/${generatedKeyId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(revokeRes.status, 200);

    // 4. Revoked key must be rejected with 401
    const rejectedKeyRes = await fetch(`${baseUrl}/api/gateway/interact`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${generatedKey}`
      },
      body: JSON.stringify({ prompt: 'Should fail' })
    });
    assert.strictEqual(rejectedKeyRes.status, 401);
  });

  await t.test('8. Centralized Policy Engine: Admin CRUD operations and RBAC guards', async () => {
    // 1. Read policies
    const getRes = await fetch(`${baseUrl}/api/policies`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(getRes.status, 200);
    const initialPolicies = await getRes.json();
    assert.ok(initialPolicies.length >= 7);

    // 2. User cannot create a policy (403 Forbidden)
    const unauthorizedCreate = await fetch(`${baseUrl}/api/policies`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userToken}`
      },
      body: JSON.stringify({
        id: 'POL-TEST-UNAUTHORIZED',
        name: 'Malicious rule',
        action: 'ALLOW',
        priority: 1
      })
    });
    assert.strictEqual(unauthorizedCreate.status, 403);

    // 3. Admin creates custom policy
    const testPolicyId = `POL-TEST-${Date.now().toString().slice(-4)}`;
    const createRes = await fetch(`${baseUrl}/api/policies`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        id: testPolicyId,
        name: 'Custom Test Policy Rule',
        description: 'Test rule created by automated test suite',
        enabled: true,
        priority: 40,
        condition: { categories: ['INTERNAL_IDENTIFIER'] },
        action: 'MASK',
        explanation: 'Enforces masking on test identifiers'
      })
    });
    assert.strictEqual(createRes.status, 200);

    // 4. Toggle policy
    const updateRes = await fetch(`${baseUrl}/api/policies/${testPolicyId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({ enabled: false })
    });
    assert.strictEqual(updateRes.status, 200);

    // 5. Delete policy
    const deleteRes = await fetch(`${baseUrl}/api/policies/${testPolicyId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(deleteRes.status, 200);
  });

  await t.test('9. DLP Policy Toggles: Admin can read and update DLP Shield configurations', async () => {
    const getDlpRes = await fetch(`${baseUrl}/api/dlp`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(getDlpRes.status, 200);
    const currentDlp = await getDlpRes.json();
    assert.ok(currentDlp.ssn !== undefined);

    // Update SSN action
    const updatedDlp = {
      ...currentDlp,
      ssn: { enabled: true, action: 'REDACT' }
    };
    const putDlpRes = await fetch(`${baseUrl}/api/dlp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify(updatedDlp)
    });
    assert.strictEqual(putDlpRes.status, 200);
  });

  await t.test('10. SOC Administrative Incident Override: Overrides blocked incident log', async () => {
    // 1. Generate a blocked incident
    const blockRes = await fetch(`${baseUrl}/api/gateway/interact`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({ prompt: 'Private key sk-proj-1234567890abcdefghijklmnop test for override' })
    });
    const blockData = await blockRes.json();
    assert.strictEqual(blockData.decision, 'BLOCK');
    const logId = blockData.auditEvent.id;

    // 2. Admin overrides the incident
    const overrideRes = await fetch(`${baseUrl}/api/override`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        logId,
        overrideReason: 'Authorized penetration testing drill exception by CISO',
        overrideText: 'Penetration test drill authorized [APPROVED]'
      })
    });
    assert.strictEqual(overrideRes.status, 200);
    const overrideResult = await overrideRes.json();
    assert.strictEqual(overrideResult.success, true);
  });

  await t.test('11. System Health Probes: Probes all 6 infrastructure components', async () => {
    const healthRes = await fetch(`${baseUrl}/api/health`);
    assert.strictEqual(healthRes.status, 200);
    const health = await healthRes.json();
    assert.strictEqual(health.status, 'HEALTHY');
    assert.strictEqual(health.components.gateway.status, 'HEALTHY');
    assert.strictEqual(health.components.detectors.status, 'HEALTHY');
    assert.strictEqual(health.components.policyEngine.status, 'HEALTHY');
    assert.strictEqual(health.components.database.status, 'HEALTHY');
    assert.strictEqual(health.components.aiProviders.status, 'HEALTHY');
    assert.strictEqual(health.components.auditSystem.status, 'HEALTHY');
  });

  await t.test('12. Input Boundary Validation: Enforces empty check and max length limit', async () => {
    // Empty prompt -> 400
    const emptyRes = await fetch(`${baseUrl}/api/gateway/interact`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({ prompt: '   ' })
    });
    assert.strictEqual(emptyRes.status, 400);

    // Oversized prompt (> 500,000 chars) -> 413 Payload Too Large
    const oversizedPrompt = 'X'.repeat(500001);
    const oversizedRes = await fetch(`${baseUrl}/api/gateway/interact`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({ prompt: oversizedPrompt })
    });
    assert.strictEqual(oversizedRes.status, 413);
  });
});
