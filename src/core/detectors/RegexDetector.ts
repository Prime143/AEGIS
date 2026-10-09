import { Detector } from './Detector';
import { Finding, DetectionCategory, Severity, SecurityAction } from '../types';

interface PatternDefinition {
  id: string;
  name: string;
  regex: RegExp;
  category: DetectionCategory;
  severity: Severity;
  confidence: number;
  recommendedAction: SecurityAction;
  policyClass: string;
  replacementToken: string;
  explanation: string;
}

export class RegexDetector implements Detector {
  readonly id = 'detector-regex';
  readonly name = 'Deterministic Regex Pattern Detector';
  readonly description = 'Inspects input for explicit credentials, PII patterns, connection URIs, and structural exploits using high-precision regular expressions.';
  readonly version = '2.1.0';
  readonly isDeterministic = true;

  private patterns: PatternDefinition[] = [
    // --- CREDENTIALS & SECRETS ---
    {
      id: 'reg-priv-key',
      name: 'Cryptographic Private Key',
      regex: /-----BEGIN(?: RSA| OPENSSH| PGP| EC| DSA)? PRIVATE KEY-----[A-Za-z0-9+/\s=\-_]+-----END(?: RSA| OPENSSH| PGP| EC| DSA)? PRIVATE KEY-----/g,
      category: 'CREDENTIAL',
      severity: 'CRITICAL',
      confidence: 1.0,
      recommendedAction: 'BLOCK',
      policyClass: 'POL-SECRET-001',
      replacementToken: '[REDACTED_PRIVATE_KEY]',
      explanation: 'Detected PEM-encoded cryptographic private key block.'
    },
    {
      id: 'reg-api-keys',
      name: 'API Key or Access Token',
      regex: /(?:sk-(?:proj-)?[a-zA-Z0-9_-]{20,}|(?:sk|rk)_live_[a-zA-Z0-9]{24,}|AIza[0-9A-Za-z_-]{35}|(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z_]{16,}|gh[pousr]_[a-zA-Z0-9_]{20,}|xox[bpas]-[0-9]{10,13}-[a-zA-Z0-9\-]+|ya29\.[a-zA-Z0-9_-]+|Bearer\s+[a-zA-Z0-9\-\._~\+\/]{20,}=*|https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[a-zA-Z0-9]+|https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+)/gi,
      category: 'CREDENTIAL',
      severity: 'CRITICAL',
      confidence: 0.98,
      recommendedAction: 'BLOCK',
      policyClass: 'POL-SECRET-002',
      replacementToken: '[REDACTED_API_KEY]',
      explanation: 'Detected explicit third-party API key, access token, or incoming webhook.'
    },
    {
      id: 'reg-jwt',
      name: 'JSON Web Token (JWT)',
      regex: /eyJ[a-zA-Z0-9_-]{8,}\.eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{10,}/g,
      category: 'CREDENTIAL',
      severity: 'HIGH',
      confidence: 0.95,
      recommendedAction: 'MASK',
      policyClass: 'POL-SECRET-003',
      replacementToken: '[REDACTED_JWT]',
      explanation: 'Detected signed JSON Web Token (JWT) containing potential user claims or session credentials.'
    },
    {
      id: 'reg-db-uri',
      name: 'Database Connection String / URI',
      regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|mssql|cassandra):\/\/(?:[^:@\s]+:[^:@\s]+@)?[^:\/\s]+(?::\d+)?(?:\/[^?\s]*)?(?:\?[^\s]*)?/gi,
      category: 'CREDENTIAL',
      severity: 'CRITICAL',
      confidence: 0.95,
      recommendedAction: 'BLOCK',
      policyClass: 'POL-SECRET-004',
      replacementToken: '[REDACTED_DB_URI]',
      explanation: 'Detected database connection URI potentially containing cluster hostnames or authentication credentials.'
    },
    {
      id: 'reg-cloud-storage',
      name: 'Cloud Storage Bucket URI',
      regex: /(?:s3|gs|azure-blob):\/\/[a-zA-Z0-9.\-_]{3,63}(?:\/[a-zA-Z0-9.\-_/]+)?/gi,
      category: 'INTERNAL_IDENTIFIER',
      severity: 'HIGH',
      confidence: 0.92,
      recommendedAction: 'MASK',
      policyClass: 'POL-INTERNAL-001',
      replacementToken: '[REDACTED_CLOUD_URI]',
      explanation: 'Detected internal cloud storage bucket URI reference.'
    },
    {
      id: 'reg-cleartext-secret',
      name: 'Cleartext Secret Assignment',
      regex: /(?:password|passwd|pwd|secret_key|api[_\-]?key|auth[_\-]?token|access[_\-]?token|the\s+key|key)(?:\s+(?:is|are)\s*[-:=]?\s*|\s*[-:=]\s*)['"]?([a-zA-Z0-9!@#$%^&*()_\-+=\[\]{}]{6,})['"]?/gi,
      category: 'CREDENTIAL',
      severity: 'CRITICAL',
      confidence: 0.88,
      recommendedAction: 'BLOCK',
      policyClass: 'POL-SECRET-005',
      replacementToken: '[REDACTED_SECRET]',
      explanation: 'Detected explicit password or secret assignment syntax.'
    },

    // --- PII (PERSONALLY IDENTIFIABLE INFORMATION) ---
    {
      id: 'reg-email',
      name: 'Email Address',
      regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gi,
      category: 'PII',
      severity: 'MEDIUM',
      confidence: 0.95,
      recommendedAction: 'MASK',
      policyClass: 'POL-PII-001',
      replacementToken: '[REDACTED_EMAIL]',
      explanation: 'Detected personal or corporate email address.'
    },
    {
      id: 'reg-phone',
      name: 'Telephone Number',
      regex: /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b/g,
      category: 'PII',
      severity: 'MEDIUM',
      confidence: 0.90,
      recommendedAction: 'MASK',
      policyClass: 'POL-PII-002',
      replacementToken: '[REDACTED_PHONE]',
      explanation: 'Detected telephone contact number.'
    },
    {
      id: 'reg-ssn',
      name: 'US Social Security Number',
      regex: /\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/g,
      category: 'PII',
      severity: 'CRITICAL',
      confidence: 0.98,
      recommendedAction: 'BLOCK',
      policyClass: 'POL-PII-003',
      replacementToken: '[REDACTED_SSN]',
      explanation: 'Detected US Social Security Number (SSN).'
    },
    {
      id: 'reg-credit-card',
      name: 'Payment Card / Credit Card Number',
      regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11}|(?:\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}))\b/g,
      category: 'CONFIDENTIAL_FINANCIAL',
      severity: 'CRITICAL',
      confidence: 0.94,
      recommendedAction: 'BLOCK',
      policyClass: 'POL-FIN-001',
      replacementToken: '[REDACTED_CREDIT_CARD]',
      explanation: 'Detected payment card or credit card account number.'
    },
    {
      id: 'reg-crypto-wallet',
      name: 'Cryptocurrency Wallet Address',
      regex: /\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b/g,
      category: 'CONFIDENTIAL_FINANCIAL',
      severity: 'MEDIUM',
      confidence: 0.92,
      recommendedAction: 'MASK',
      policyClass: 'POL-FIN-002',
      replacementToken: '[REDACTED_CRYPTO_WALLET]',
      explanation: 'Detected public cryptocurrency address.'
    },
    {
      id: 'reg-ip-internal',
      name: 'Internal Network IPv4 Address',
      regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
      category: 'INTERNAL_IDENTIFIER',
      severity: 'MEDIUM',
      confidence: 0.92,
      recommendedAction: 'MASK',
      policyClass: 'POL-INTERNAL-002',
      replacementToken: '[REDACTED_INTERNAL_IP]',
      explanation: 'Detected RFC-1918 private internal network IPv4 address.'
    },

    // --- APPLICATION SECURITY EXPLOITS ---
    {
      id: 'reg-appsec-sqli',
      name: 'SQL Injection Payload Pattern',
      regex: /(?:\bUNION\s+SELECT\b|'\s+OR\s+'1'='1|"\s+OR\s+"1"="1|'\s+OR\s+1=1|\bDROP\s+TABLE\b|\bINSERT\s+INTO\b|\bDELETE\s+FROM\b|\bWAITFOR\s+DELAY\b|;\s*--|--\s*$|\bEXEC\s+xp_cmdshell\b)/gi,
      category: 'APPSEC_EXPLOIT',
      severity: 'CRITICAL',
      confidence: 0.95,
      recommendedAction: 'BLOCK',
      policyClass: 'POL-EXPLOIT-001',
      replacementToken: '[EXPLOIT_SQLI_BLOCKED]',
      explanation: 'Detected signature for SQL injection attack.'
    },
    {
      id: 'reg-appsec-xss',
      name: 'Cross-Site Scripting (XSS) Pattern',
      regex: /(?:<script[\s\S]*?>[\s\S]*?<\/script>|<img[^>]+onerror=|<svg[^>]+onload=|\bjavascript:[a-zA-Z0-9_\-\.]+\(|\bdocument\.cookie\b|\bwindow\.location\s*=)/gi,
      category: 'APPSEC_EXPLOIT',
      severity: 'CRITICAL',
      confidence: 0.95,
      recommendedAction: 'BLOCK',
      policyClass: 'POL-EXPLOIT-002',
      replacementToken: '[EXPLOIT_XSS_BLOCKED]',
      explanation: 'Detected signature for Cross-Site Scripting (XSS) exploit payload.'
    },
    {
      id: 'reg-appsec-path-traversal',
      name: 'Path Traversal / Local File Inclusion',
      regex: /(?:\.\.\/){2,}|(?:\.\.\\){2,}|\/etc\/passwd|\/etc\/shadow|c:\\windows\\system32/gi,
      category: 'APPSEC_EXPLOIT',
      severity: 'CRITICAL',
      confidence: 0.96,
      recommendedAction: 'BLOCK',
      policyClass: 'POL-EXPLOIT-003',
      replacementToken: '[EXPLOIT_LFI_BLOCKED]',
      explanation: 'Detected path traversal or operating system file enumeration string.'
    },
    {
      id: 'reg-appsec-command-injection',
      name: 'OS Command Injection Payload',
      regex: /(?:;\s*rm\s+-rf\s+|;\s*bash\s+-i|;\s*nc\s+-e|\bchmod\s+777\s+\/|\bcurl\s+https?:\/\/[^\s]+\s*\|\s*bash)/gi,
      category: 'APPSEC_EXPLOIT',
      severity: 'CRITICAL',
      confidence: 0.95,
      recommendedAction: 'BLOCK',
      policyClass: 'POL-EXPLOIT-004',
      replacementToken: '[EXPLOIT_RCE_BLOCKED]',
      explanation: 'Detected destructive command execution or reverse shell payload.'
    }
  ];

  analyze(input: string, _context?: any): Finding[] {
    if (!input || typeof input !== 'string') return [];

    const findings: Finding[] = [];

    for (const def of this.patterns) {
      // Create fresh RegExp to avoid state issues with global /g flag
      const regex = new RegExp(def.regex.source, def.regex.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(input)) !== null) {
        const matchedText = match[0];
        const start = match.index;
        const end = start + matchedText.length;

        findings.push({
          id: `${def.id}-${start}-${end}`,
          category: def.category,
          severity: def.severity,
          confidence: def.confidence,
          detector: this.name,
          matchedSpan: {
            start,
            end,
            text: matchedText,
            maskedReplacement: def.replacementToken
          },
          policyClass: def.policyClass,
          recommendedAction: def.recommendedAction,
          explanation: def.explanation
        });
      }
    }

    return findings;
  }
}
