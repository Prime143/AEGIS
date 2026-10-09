import test from 'node:test';
import assert from 'node:assert';
import http from 'http';

// Configure environment for test execution
process.env.PORT = '3099';
process.env.AUTO_START_SERVER = 'false';
process.env.NODE_ENV = 'test';

import { startServer } from '../server';
import { exportEmployeeDossierPdf, exportSecurityAuditPdf } from '../src/utils/pdfReports';
import fs from 'fs';

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

  await t.test('13. Security Awareness & Human Risk Engine: Profiles, gaps, and training assignments', async () => {
    // 1. Fetch available training modules
    const modulesRes = await fetch(`${baseUrl}/api/awareness/modules`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });
    assert.strictEqual(modulesRes.status, 200);
    const modules = await modulesRes.json();
    assert.ok(Array.isArray(modules));
    assert.ok(modules.length >= 5);
    assert.ok(modules.some((m: any) => m.id === 'SEC-101'));
    assert.ok(modules.some((m: any) => m.id === 'PRIV-201'));

    // 2. User fetches their own awareness profile
    const userProfileRes = await fetch(`${baseUrl}/api/awareness/profile/current.user@nexus-corp.com`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });
    assert.strictEqual(userProfileRes.status, 200);
    const userProfile = await userProfileRes.json();
    assert.strictEqual(userProfile.userEmail, 'current.user@nexus-corp.com');
    assert.ok(typeof userProfile.awarenessScore === 'number');
    assert.ok(Array.isArray(userProfile.recommendedModules));
    assert.ok(userProfile.aiExecutiveSummary.length > 20);

    // 3. User attempts to inspect another employee's dossier -> 403 Forbidden
    const forbiddenRes = await fetch(`${baseUrl}/api/awareness/profile/admin.soc@nexus-corp.com`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });
    assert.strictEqual(forbiddenRes.status, 403);

    // 4. Admin assigns training module PRIV-201 to user
    const assignRes = await fetch(`${baseUrl}/api/awareness/assign`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        email: 'current.user@nexus-corp.com',
        moduleId: 'PRIV-201'
      })
    });
    assert.strictEqual(assignRes.status, 200);
    const assignment = await assignRes.json();
    assert.strictEqual(assignment.moduleId, 'PRIV-201');
    assert.strictEqual(assignment.status, 'ASSIGNED');

    // 5. User marks module PRIV-201 as completed
    const completeRes = await fetch(`${baseUrl}/api/awareness/complete`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userToken}`
      },
      body: JSON.stringify({
        email: 'current.user@nexus-corp.com',
        moduleId: 'PRIV-201'
      })
    });
    assert.strictEqual(completeRes.status, 200);
    const completed = await completeRes.json();
    assert.strictEqual(completed.status, 'COMPLETED');
    assert.ok(completed.completedAt);
  });

  await t.test('14. PDF Report Generator: Generates Employee Coaching Dossier and Security Audit PDFs', async () => {
    // 1. Fetch Jordan Hayes awareness profile (DevOps with Credential violations)
    const jordanRes = await fetch(`${baseUrl}/api/awareness/profile/${encodeURIComponent('jordan.hayes@nexus-corp.com')}`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(jordanRes.status, 200);
    const jordanProfile = await jordanRes.json();
    assert.strictEqual(jordanProfile.userEmail, 'jordan.hayes@nexus-corp.com');
    assert.strictEqual(jordanProfile.postureTier, 'HIGH_RISK');
    assert.ok(jordanProfile.primaryGaps.some((g: any) => g.category === 'CREDENTIAL'));

    // 2. Export Employee Dossier PDF (verifies no runtime error during document build)
    assert.doesNotThrow(() => {
      exportEmployeeDossierPdf(jordanProfile);
    });

    // 3. Export Security Audit Log PDF
    const logsRes = await fetch(`${baseUrl}/api/logs`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(logsRes.status, 200);
    const logs = await logsRes.json();
    assert.ok(Array.isArray(logs));
    assert.ok(logs.length > 0);

    assert.doesNotThrow(() => {
      exportSecurityAuditPdf(logs, 'ADMIN', 'admin.soc@nexus-corp.com');
    });

    // 4. Test backend streaming endpoint for employee awareness PDF
    const streamedPdfRes = await fetch(`${baseUrl}/api/reports/awareness/${encodeURIComponent('jordan.hayes@nexus-corp.com')}/pdf`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(streamedPdfRes.status, 200);
    assert.strictEqual(streamedPdfRes.headers.get('content-type'), 'application/pdf');
    const pdfBuf = await streamedPdfRes.arrayBuffer();
    const pdfHeader = Buffer.from(pdfBuf).subarray(0, 5).toString('utf-8');
    assert.strictEqual(pdfHeader, '%PDF-', 'Streamed awareness dossier is a valid PDF binary');

    // 5. Test backend streaming endpoint for security audit PDF
    const streamedAuditRes = await fetch(`${baseUrl}/api/reports/audit/pdf`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(streamedAuditRes.status, 200);
    assert.strictEqual(streamedAuditRes.headers.get('content-type'), 'application/pdf');
    const auditPdfBuf = await streamedAuditRes.arrayBuffer();
    const auditHeader = Buffer.from(auditPdfBuf).subarray(0, 5).toString('utf-8');
    assert.strictEqual(auditHeader, '%PDF-', 'Streamed audit report is a valid PDF binary');

    // 6. Test DSAR export with format=pdf
    const dsarPdfRes = await fetch(`${baseUrl}/api/dsar/export?email=${encodeURIComponent('current.user@nexus-corp.com')}&format=pdf`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });
    assert.strictEqual(dsarPdfRes.status, 200);
    assert.strictEqual(dsarPdfRes.headers.get('content-type'), 'application/pdf');

    // Clean up any test PDF artifacts generated in workspace
    const files = fs.readdirSync(process.cwd());
    for (const f of files) {
      if (f.startsWith('AEGIS_') && f.endsWith('.pdf')) {
        try { fs.unlinkSync(f); } catch {}
      }
    }
  });

  await t.test('15. Fast Hydration: /api/bootstrap returns full gateway state in a single roundtrip with default token', async () => {
    // 1. Authenticate using default admin token immediately
    const bootRes = await fetch(`${baseUrl}/api/bootstrap`, {
      headers: { 'Authorization': 'Bearer aegis_admin_session_default' }
    });
    assert.strictEqual(bootRes.status, 200);
    const bootData = await bootRes.json();

    assert.ok(bootData.systemStatus);
    assert.ok(Array.isArray(bootData.policies));
    assert.ok(bootData.policies.length >= 3);
    assert.ok(Array.isArray(bootData.events));
    assert.ok(bootData.events.length > 0);
    assert.ok(bootData.dlpPolicy);
    assert.ok(Array.isArray(bootData.awarenessProfiles));
    assert.ok(bootData.awarenessProfiles.length > 0);
    assert.ok(Array.isArray(bootData.awarenessModules));

    // 2. Authenticate using default user token
    const userBootRes = await fetch(`${baseUrl}/api/bootstrap`, {
      headers: { 'Authorization': 'Bearer aegis_user_session_default' }
    });
    assert.strictEqual(userBootRes.status, 200);
    const userBootData = await userBootRes.json();
    assert.ok(Array.isArray(userBootData.events));
  });
});

