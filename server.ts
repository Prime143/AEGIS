import express from 'express';
import fs from 'fs/promises';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { GoogleGenAI, Type } from '@google/genai';
import dotenv from 'dotenv';

dotenv.config();

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '50mb' }));

  // API routes FIRST
  app.post('/api/analyze', async (req, res) => {
    const { text, user, policyMode = 'balanced', file } = req.body;
    if (!text || typeof text !== 'string') {
      return res.status(400).json({ error: 'Invalid input' });
    }

    try {
      if (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY') {
        const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
        const prompt = `You are an advanced enterprise AI Risk Governance system. Your job is to deeply understand the INTENT of employee prompts before they are sent to external AI tools. Do NOT just do keyword matching. Use agentic reasoning to identify complex security threats, focusing heavily on INSIDER THREATS: obfuscated API keys, database connection strings, intentional data exfiltration, logic bombs, sabotage, and unauthorized probes of executive/HR data.
        
        CURRENT POLICY MODE: ${policyMode.toUpperCase()}
        - STRICT: Zero tolerance. Block any prompt involving client data, credentials, API keys, DB configurations, secrets, internal financials, HR data, or sabotage/exfiltration attempts.
        - BALANCED: Redact PII and secrets. Block if the core task inherently requires exposing sensitive client data OR implies malicious intent (bypassing DLP, logic bombs, probing HR/executives).
        - RELAXED: Redact direct PII, warn on sensitive topics but strongly block malicious internal threats (sabotage, bypassing security).

        Employee Prompt: "${text}"
        ${file ? '\n[NOTE: A document is attached to this prompt.]' : ''}
        
        Tasks:
        1. Context & Agentic Threat Detection: Understand exactly what the employee is trying to achieve. Is the user intentionally trying to bypass DLP (e.g. asking to obfuscate/base64 encode client lists)? Are they asking to write backdoors or logic bombs into code? Are they digging for confidential manager/executive info or salary bands? These are INSIDER THREATS and MUST NOT pass.
        2. Document Redaction: If a document is attached, extract its text. If it contains sensitive PII, credentials, API Keys, DB URIs, or financials, you MUST redact those parts (e.g., [REDACTED_API_KEY], [REDACTED_DB_URI]) and append the sanitized document text to the rewritten_prompt.
        3. Score risk 0-100 based on severity AND the current POLICY MODE. (e.g., API Keys, Insider Threats, Exfiltration attempts are high risk, score > 80).
        4. Determine action based on score and POLICY MODE: 
           - ALLOW (0-20): Safe. General knowledge questions.
           - MODIFIED (21-70): Text or document contains specific names/numbers/secrets that can be redacted. Rewrite the prompt and/or document text to redact sensitive data using generic placeholders (e.g., [REDACTED_CLIENT_NAME], [REDACTED_API_KEY]). ALWAYS wrap your redactions in exactly this format: [REDACTED_REASON].
           - BLOCK (71-100): The core task relies on sensitive data that cannot be cleanly redacted, involves massive data leaks, or shows malicious INSIDER THREAT intent (sabotage, exfiltration, HR probe). MUST BLOCK IT.
        5. Provide the rewritten_prompt if MODIFIED. If ALLOW, rewritten_prompt = original prompt + document text. If BLOCK, rewritten_prompt = "".
        6. Provide a suggested_safe_prompt: 
           - If MODIFIED: A message explaining what was redacted (e.g., "API Key redacted") and why.
           - If BLOCK: A firm message explaining that this task should NOT be done with external AI (e.g., "Company policy prohibits analyzing raw DB credentials or attempting to bypass security controls.").
        7. Set alert_status to TRIGGERED if BLOCK, else NOT TRIGGERED.
        `;

        let contents: any[] = [{ text: prompt }];

        if (file && file.data && file.mimeType) {
          const base64Data = file.data.includes(',') ? file.data.split(',')[1] : file.data;
          contents.push({
            inlineData: {
              data: base64Data,
              mimeType: file.mimeType
            }
          });
        }

        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: contents,
          config: {
            responseMimeType: 'application/json',
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                risk_score: { type: Type.INTEGER },
                risk_level: { type: Type.STRING },
                attack_type: { type: Type.STRING },
                reasons: { type: Type.ARRAY, items: { type: Type.STRING } },
                action: { type: Type.STRING },
                rewritten_prompt: { type: Type.STRING },
                suggested_safe_prompt: { type: Type.STRING },
                business_impact: { type: Type.STRING },
                alert_status: { type: Type.STRING },
                report_summary: { type: Type.STRING }
              },
              required: ["risk_score", "risk_level", "attack_type", "reasons", "action", "rewritten_prompt", "suggested_safe_prompt", "business_impact", "alert_status", "report_summary"]
            }
          }
        });

        if (response.text) {
          const result = JSON.parse(response.text);
          try {
            await fs.appendFile('aegis-audit.log', `[${new Date().toISOString()}] [GEMINI] USER: ${user} | ACTION: ${result.action} | SCORE: ${result.risk_score} | PROMPT: ${text}\n`, 'utf8');
          } catch(e) { console.error(e); }
          return res.json({ ...result, original_prompt: text, user });
        }
      } else {
        console.warn("GEMINI_API_KEY is not set or is using the default placeholder. Falling back to rule-based logic.");
      }
    } catch (error: any) {
      if (error?.message?.includes('API key not valid')) {
        console.error("❌ Gemini API Error: The provided API key is invalid. Please configure a valid GEMINI_API_KEY in the AI Studio Secrets panel. Falling back to rule-based logic.");
      } else {
        console.error("Gemini API error, falling back to rule-based:", error);
      }
    }

    // Advanced Agentic AI Detection Fallback
    // Employs hybrid pattern-matching and contextual analysis for sensitive data
    let risk_score = 0;
    const reasons: string[] = [];
    let attack_type = 'None';
    let rewritten_prompt = text;
    const lowerText = text.toLowerCase();

    // 1. Structural Pattern Detection (API Keys, DBs, JWTs, Secrets)
    const agenticPatterns = [
      {
        pattern: /-----BEGIN(?: RSA)? PRIVATE KEY-----[A-Za-z0-9+/\s=]+-----END(?: RSA)? PRIVATE KEY-----/g,
        score: 100,
        reason: 'Detected RSA Private Key',
        redact: '[REDACTED_PRIVATE_KEY]'
      },
      { 
        pattern: /(?:sk-(?:proj-)?[a-zA-Z0-9]{20,}|(?:sk|rk)_live_[a-zA-Z0-9]{24,}|AIza[0-9A-Za-z_-]{35}|(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}|gh[pousr]_[a-zA-Z0-9]{36}|xox[bpas]-[0-9]{10,13}-[a-zA-Z0-9\-]+|ya29\.[a-zA-Z0-9_-]+|Bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*)/gi,
        score: 90, 
        reason: 'Detected explicit API Key or Access Token', 
        redact: '[REDACTED_API_KEY]' 
      },
      { 
        pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/(?:[^:@\s]+:[^:@\s]+@)?[^:\/\s]+(?::\d+)?(?:\/[^?\s]*)?(?:\?[^\s]*)?/gi,
        score: 90, 
        reason: 'Detected Database Connection String / URI', 
        redact: '[REDACTED_DB_URI]' 
      },
      { 
        pattern: /(?:password|passwd|pwd|secret|api[_\-]?key|auth[_\-]?token|access[_\-]?token|key)(?:\s+(?:is|are)\s*[:=\-]?\s*|\s*[:=\-]\s*)\s*['"]?[^\s"']+['"]?/gi,
        score: 80, 
        reason: 'Detected cleartext secret assignment', 
        redact: '[REDACTED_SECRET]' 
      },
      { 
        pattern: /eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{10,}/gi,
        score: 80,
        reason: 'Detected JWT (JSON Web Token)',
        redact: '[REDACTED_JWT]'
      },
      { 
        pattern: /(?:\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b|\b\d{15,16}\b)/g,
        score: 75,
        reason: 'Detected potential financial data (Credit Card)',
        redact: '[REDACTED_CREDIT_CARD]'
      },
      {
        pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/gi,
        score: 50,
        reason: 'Detected Email Address (PII)',
        redact: '[REDACTED_EMAIL]'
      },
      {
        pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
        score: 80,
        reason: 'Detected US Social Security Number (SSN)',
        redact: '[REDACTED_SSN]'
      },
      {
        pattern: /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b/g,
        score: 50,
        reason: 'Detected North American Phone Number (PII)',
        redact: '[REDACTED_PHONE]'
      },
      {
        pattern: /\b(?:0x[a-fA-F0-9]{40}|bc1[a-z0-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
        score: 75,
        reason: 'Detected Cryptocurrency Wallet Address',
        redact: '[REDACTED_CRYPTO_ADDRESS]'
      },
      {
        pattern: /(?:s3:\/\/[^\s]+|gs:\/\/[^\s]+|https:\/\/[^\s]+\.s3\.amazonaws\.com)/gi,
        score: 80,
        reason: 'Detected Cloud Storage URI',
        redact: '[REDACTED_CLOUD_STORAGE]'
      },
      {
        pattern: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
        score: 40,
        reason: 'Detected IP Address',
        redact: '[REDACTED_IP]'
      }
    ];

    for (const rule of agenticPatterns) {
      if (rule.pattern.test(rewritten_prompt)) {
        risk_score += rule.score;
        if (!reasons.includes(rule.reason)) reasons.push(rule.reason);
        rewritten_prompt = rewritten_prompt.replace(rule.pattern, rule.redact);
      }
    }

    // 2. Contextual Keyword Heuristics
    const keywordRules = [
      { keywords: ['logic bomb', 'backdoor', 'bypass edr', 'disable antivirus', 'vpn bypass', 'shadow it', 'vulnerabilities in internal', 'disable proxy'], score: 90, reason: 'Detected potential sabotage or security control bypass intent', redact: '[MALICIOUS_INTENT_BLOCKED]' },
      { keywords: ['ceo email', 'manager salary', 'salary band', 'termination list', 'performance review', 'disciplinary action', 'layoff list', 'manager info', 'executive summary leak'], score: 85, reason: 'Targeting sensitive Executive or HR data', redact: '[SENSITIVE_HR_DATA]' },
      { keywords: ['base64 encode client list', 'obfuscate data', 'hide this code', 'exfiltrate', 'bypass dlp', 'covert channel', 'encode database'], score: 90, reason: 'Detected data exfiltration / obfuscation attempt', redact: '[EXFILTRATION_BLOCKED]' },
      { keywords: ['password', 'credentials', 'admin123', 'supersecret99'], score: 50, reason: 'Contains sensitive authentication terms', redact: '[REDACTED_CREDENTIALS]' },
      { keywords: ['api key', 'secret key', 'access token', 'auth token'], score: 60, reason: 'Mentions API or access keys', redact: '[REDACTED_KEY_REFERENCE]' },
      { keywords: ['company db', 'client data', 'prod-db', 'database', 'internal db', 'customer list'], score: 40, reason: 'Mentions internal database or client data', redact: '[INTERNAL_SYSTEM]' },
      { keywords: ['confidential', 'internal only', 'proprietary', 'trade secret', 'do not share'], score: 40, reason: 'Contains confidential or internal markers', redact: '[CONFIDENTIAL]' },
      { keywords: ['financial', 'revenue', '$', 'routing number', 'account number'], score: 30, reason: 'Mentions financial metrics', redact: '[FINANCIAL_METRIC]' },
      { keywords: ['send', 'share', 'upload', 'join', 'connect'], score: 20, reason: 'Indicates potential data exfiltration or connection intent', redact: 'process' },
      { keywords: ['gmail.com', 'external', 'drive.google.com', 'personal cloud', 'my personal', 'dropbox'], score: 30, reason: 'Mentions external or personal systems', redact: '[EXTERNAL_ENTITY]' },
    ];

    for (const rule of keywordRules) {
      if (rule.keywords.some(kw => lowerText.includes(kw))) {
        risk_score += rule.score;
        if (!reasons.includes(rule.reason)) reasons.push(rule.reason);
        rule.keywords.forEach(kw => {
          const regex = new RegExp(kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
          rewritten_prompt = rewritten_prompt.replace(regex, rule.redact);
        });
      }
    }

    risk_score = Math.min(risk_score, 100);

    let risk_level = 'Low';
    let action = 'ALLOW';
    let business_impact = 'Minimal to no impact. Safe to process.';
    let alert_status = 'NOT TRIGGERED';
    let report_summary = 'Routine AI interaction.';
    let suggested_safe_prompt = 'Your prompt is safe.';

    if (risk_score >= 71) {
      risk_level = 'High';
      action = 'BLOCK';
      attack_type = 'Data Leakage / High Risk';
      rewritten_prompt = '';
      business_impact = 'Critical risk of data breach, compliance violation, or intellectual property loss.';
      alert_status = 'TRIGGERED';
      report_summary = `Blocked high-risk prompt containing: ${reasons.join(', ')}`;
      suggested_safe_prompt = 'Please remove all sensitive data, credentials, and internal identifiers before submitting.';
    } else if (risk_score >= 21) {
      risk_level = 'Medium';
      action = 'MODIFIED';
      attack_type = 'Suspicious / Policy Violation';
      business_impact = 'Potential policy violation. Prompt was sanitized to prevent exposure of internal metrics or confidential info.';
      report_summary = 'Prompt modified to remove sensitive keywords before sending to AI.';
      suggested_safe_prompt = 'Consider generalizing the data or removing specific financial/internal references next time.';
    } else {
      if (risk_score > 0) {
        attack_type = 'Low Risk';
      }
    }

    const finalResult = {
      risk_score,
      risk_level,
      attack_type,
      reasons,
      action,
      rewritten_prompt,
      suggested_safe_prompt,
      business_impact,
      alert_status,
      report_summary,
      original_prompt: text,
      user
    };

    try {
      await fs.appendFile('aegis-audit.log', `[${new Date().toISOString()}] [FALLBACK] USER: ${user} | ACTION: ${action} | SCORE: ${risk_score} | THREAT: ${attack_type} | PROMPT: ${text}\n`, 'utf8');
    } catch(e) { console.error('Failed to write to audit log', e); }

    res.json(finalResult);
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
