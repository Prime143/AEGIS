import express from 'express';
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
        const prompt = `You are an advanced enterprise AI Risk Governance system. Your job is to deeply understand the INTENT of employee prompts before they are sent to external AI tools. Do NOT just do keyword matching.
        
        CURRENT POLICY MODE: ${policyMode.toUpperCase()}
        - STRICT: Zero tolerance. Block any prompt involving client data, credentials, or internal financials.
        - BALANCED: Redact PII. Block if the core task inherently requires exposing sensitive client/company data.
        - RELAXED: Redact direct PII, warn on sensitive topics.

        Employee Prompt: "${text}"
        ${file ? '\n[NOTE: A document is attached to this prompt.]' : ''}
        
        Tasks:
        1. Intent & Context Analysis: Understand exactly what the employee is trying to achieve. Is the core task itself a security risk? Is the attached document highly sensitive?
        2. Document Redaction: If a document is attached, extract its text. If it contains sensitive PII, credentials, or financials, you MUST redact those parts (e.g., [REDACTED_CLIENT]) and append the sanitized document text to the rewritten_prompt.
        2. Score risk 0-100 based on severity AND the current POLICY MODE.
        3. Determine action based on score and POLICY MODE: 
           - ALLOW (0-20): Safe. General knowledge questions.
           - MODIFIED (21-70): Text or document contains specific names/numbers that can be redacted. Rewrite the prompt and/or document text to redact sensitive data using generic placeholders (e.g., [REDACTED_CLIENT_NAME]). ALWAYS wrap your redactions in exactly this format: [REDACTED_REASON].
           - BLOCK (71-100): The core task relies on sensitive data that cannot be cleanly redacted. MUST BLOCK IT.
        4. Provide the rewritten_prompt if MODIFIED. If ALLOW, rewritten_prompt = original prompt + document text. If BLOCK, rewritten_prompt = "".
        5. Provide a suggested_safe_prompt: 
           - If MODIFIED: A message explaining what was redacted and why.
           - If BLOCK: A firm message explaining that this specific task should NOT be done with external AI (e.g., "Company policy prohibits analyzing raw client data using external AI. Please use internal secure tools.").
        6. Set alert_status to TRIGGERED if BLOCK, else NOT TRIGGERED.
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

    // Fallback rule-based logic
    const lowerText = text.toLowerCase();
    let risk_score = 0;
    const reasons: string[] = [];
    let attack_type = 'None';
    let rewritten_prompt = text;

    const keywordRules = [
      { keywords: ['password', 'credentials', 'admin123', 'supersecret99'], score: 50, reason: 'Contains sensitive authentication terms', redact: '[REDACTED_CREDENTIALS]' },
      { keywords: ['client data', 'database', 'prod-db'], score: 40, reason: 'Mentions client data or database access', redact: '[INTERNAL_SYSTEM]' },
      { keywords: ['confidential', 'internal'], score: 30, reason: 'Contains confidential or internal markers', redact: '[CONFIDENTIAL]' },
      { keywords: ['financial', 'revenue', '$2.5m'], score: 40, reason: 'Mentions financial or revenue data', redact: '[FINANCIAL_METRIC]' },
      { keywords: ['send', 'share', 'upload'], score: 20, reason: 'Indicates data exfiltration intent', redact: 'process' },
      { keywords: ['gmail.com', 'external'], score: 20, reason: 'Mentions external domains or entities', redact: '[EXTERNAL_DOMAIN]' },
    ];

    for (const rule of keywordRules) {
      if (rule.keywords.some(kw => lowerText.includes(kw))) {
        risk_score += rule.score;
        reasons.push(rule.reason);
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

    res.json({
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
    });
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
