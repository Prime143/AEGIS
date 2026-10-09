<div align="center">
  <h1>AEGIS</h1>
  <h3>AI-Enabled Governance & Information Security</h3>
  <p><b>SECURE THE BOUNDARY. GOVERN THE INTELLIGENCE.</b></p>
  <p><i>An active, inline cybersecurity gateway for securing organizational interactions with AI services.</i></p>
</div>

---

## 1. What is AEGIS?

**AEGIS** (AI-Enabled Governance & Information Security) is a security gateway prototype engineered to protect enterprise data boundaries during employee interactions with Artificial Intelligence services (such as external cloud LLMs or internal private models).

AEGIS sits directly in the communication perimeter:
```
EMPLOYEE / APPLICATION
          ↓
    AEGIS GATEWAY
          ↓
   INPUT INSPECTION
          ↓
  SECURITY DETECTION (Regex, Dictionary, Contextual)
          ↓
  RISK CLASSIFICATION
          ↓
    POLICY ENGINE (ALLOW / MASK / BLOCK)
          ↓
     AI PROVIDER (External or Safe Mock)
          ↓
  RESPONSE INSPECTION
          ↓
    SECURE RESPONSE
          ↓
       USER
```

Audit and policy telemetry are generated throughout the pipeline without persistently storing raw plaintext sensitive data.

---

## 2. Core Security Architecture & Principles

### Separation of Data and Provider
1. **User Data**: Received via TLS and authenticated with role-scoped access tokens (`ADMIN`, `SECURITY_ANALYST`, `USER`).
2. **Security Analysis Layer**: Operates independently of the target AI provider using deterministic pattern matching, dictionary verification, and contextual heuristics.
3. **Policy Decision Engine**: Centralized evaluation that maps findings, user context, and organization policy into explicit actions:
   - **`ALLOW`**: Outbound request is permitted without modification.
   - **`MASK`**: Sensitive spans (e.g. emails, internal identifiers) are sanitized with category tokens (`[REDACTED_EMAIL]`, `[REDACTED_INTERNAL_ID]`) before transmission.
   - **`BLOCK`**: Request is intercepted at the perimeter. The AI provider is **never contacted**, and a safe explanation is returned.
4. **AI Service Layer**: Abstracted via an interface (`AIProvider`) supporting multiple external and internal providers.
5. **Response Inspection Layer**: Evaluates outbound provider responses for confidential entity leakage or prohibited content before client delivery.

### Zero Plaintext Secret Retention
- Prompts are cryptographically hashed using SHA-256 for audit traceability.
- High-risk blocked prompts and credentials are never written in raw form to persistent database logs or disk files.
- Masked representations preserve context for investigations without exposing underlying credentials.

### Fail-Closed Security
- If mandatory detectors, authentication, or policy engines fail, or if Emergency Lockdown mode is active, the gateway fails closed (`BLOCK`).

---

## 3. Layered Detection Engine

AEGIS implements a modular detector provider architecture (`src/core/detectors/`):

1. **`RegexDetector`** (Deterministic Pattern Matching):
   - Cryptographic Private Keys (PEM RSA, OpenSSH, PGP)
   - API Keys & Tokens (OpenAI `sk-...`, AWS `AKIA...`, GitHub `ghp_...`, Slack/Discord webhooks)
   - Database Connection URIs (`mongodb://`, `postgres://`, `mysql://`, `redis://`)
   - Cloud Storage URIs (`s3://`, `gs://`)
   - Personally Identifiable Information (Emails, Phone numbers, US SSNs)
   - Payment Card Numbers (Credit Cards)
   - Internal RFC1918 IPv4 Addresses
   - Application Security Exploit Payloads (SQL Injection, XSS, Path Traversal, OS Command Injection)

2. **`DictionaryDetector`** (Organizational Glossary & Entities):
   - Matches against configurable corporate codenames (e.g. `Project Orion`, `Project Chimera`).
   - Identifies internal development cluster hostnames and financial spreadsheet patterns.

3. **`ContextualDetector`** (Adversarial Heuristics):
   - Prompt Injection & Jailbreak attempts (`ignore previous instructions`, `developer mode`, `dan`).
   - Insider Threats & Sabotage (`logic bomb`, `deletes prod db`, `bypass edr`).
   - Extortion & Data Hostage attempts (`until my money is paid`, `holding data hostage`).
   - Payload Anomaly & Context Smuggling detection (>20,000 character payloads).

4. **`DetectorRegistry`**:
   - Executes layered detectors in parallel.
   - Normalizes findings and resolves overlapping character spans by severity and confidence.

---

## 4. Policy Engine & Explainability

Located in `src/core/policy/PolicyEngine.ts`, the engine centralizes rule enforcement:

- Configurable priority tiers (P10 - P100).
- Explicit explainability for every security decision:
  - **What** happened?
  - **Why** did it happen?
  - **Which** detector identified the span?
  - **Which** policy rule was triggered?
  - **What** was sent to the AI provider?
  - **What** was returned to the user?

---

## 5. AI Provider Abstraction

AEGIS does not hard-code a single model. The `AIProvider` interface (`src/core/providers/`) enables pluggable models:

- **`SafeMockProvider`**: A zero-dependency deterministic simulation provider for air-gapped environments, local development, and CI testing. Clearly labeled as `(Simulated)` in the UI.
- **`GeminiProvider`**: Adapter for Google Gemini 2.5 Flash via `@google/genai` when `GEMINI_API_KEY` is configured.
- Graceful Fallback: If external API keys are missing or invalid, the system automatically routes to `SafeMockProvider` without crashing.

---

## 6. Security Capabilities Status Matrix

| Capability | Status | Implementation Details |
| :--- | :--- | :--- |
| **Deterministic Sensitive Data Detection** | `IMPLEMENTED` | RegexDetector, DictionaryDetector, ContextualDetector |
| **Centralized Policy Engine** | `IMPLEMENTED` | Allow, Mask, Block with priority ordering |
| **Non-Destructive Masking Service** | `IMPLEMENTED` | End-to-start span replacement with category tokens |
| **AI Provider Abstraction & Fallback** | `IMPLEMENTED` | Pluggable interface with SafeMockProvider & Gemini adapter |
| **Response Inspection** | `PROTOTYPE` | Perimeter response scanner with policy enforcement |
| **Secure Audit Logging** | `IMPLEMENTED` | SHA-256 prompt hashing; zero raw secret retention |
| **Role-Based Server Authorization** | `IMPLEMENTED` | Server-enforced ADMIN, SECURITY_ANALYST, USER roles |
| **Empirical Benchmark Suite** | `IMPLEMENTED` | Evaluates precision, recall, and F1 on Train/Dev/Test splits |
| **Emergency Perimeter Lockdown** | `IMPLEMENTED` | Instant fail-closed boundary suspension toggle |
| **Hardware Enclave (TEE) Isolation** | `PLANNED` | Planned for future enterprise deployment |

---

## 7. Getting Started & Local Development

### Prerequisites
- [Node.js](https://nodejs.org/) (v18.0.0 or higher; tested on v24.x)
- npm or corepack

### Installation
```bash
git clone https://github.com/Prime143/AEGIS.git
cd AEGIS
npm install
```

### Environment Configuration
Create a `.env` file in the project root:
```env
# Optional: External Gemini API Key. If omitted, AEGIS uses the built-in Safe Mock Provider.
GEMINI_API_KEY="your_api_key_here"

# Optional: Master Admin API Key for external CI/CD integrations
ADMIN_API_TOKEN="your_secure_admin_token"

# Application URL
APP_URL="http://localhost:3000"
PORT=3000
```

### Running the Application
```bash
# Start development server (backend + Vite frontend)
npm run dev

# Or run tests
npm test

# Or typecheck and build production bundle
npm run lint
npm run build
```

The gateway console will be accessible at: `http://localhost:3000`

---

## 8. Automated Testing Suite

The repository includes a comprehensive test suite across unit, integration, and security edge cases:

```bash
npm test
```

### Test Coverage:
- **`tests/core.test.ts`**:
  - Regex detection for private keys, API keys, JWTs, DB connection strings, SSNs, credit cards, exploits.
  - Organization dictionary codename detection.
  - Contextual prompt injection and insider threat detection.
  - Masking engine span replacement and non-destructive properties.
  - Policy engine deterministic decision evaluations.
  - Fail-closed security on lockdown and missing consent.
  - Response inspection interception.
  - End-to-end pipeline allow/mask/block flows.
  - Non-fabricated experiment benchmark metric calculations.
  - Audit logging verification confirming no raw secret leakage.
- **`tests/edge_cases.test.ts`**:
  - Huge payloads (>20,000 characters) triggering context smuggling blocks.
  - Empty, null, or whitespace-only inputs.
  - Repeated sensitive values and duplicate span resolution.
  - Overlapping entity spans priority resolution.
  - Multiline, tab-separated, and encoded secret values.
  - Multilingual mixed inputs (English, Hindi, Marathi).
  - High-concurrency simultaneous gateway requests.

---

## 9. Security & API Endpoints

### Core Security Endpoints:
- `POST /api/gateway/interact`: Full boundary pipeline (Inspect &rarr; Detect &rarr; Policy &rarr; Forward &rarr; Response Inspect &rarr; Audit).
- `POST /api/analyze`: Inspection and analysis preview without calling provider.
- `GET /api/policies`: Retrieve active security policies.
- `POST /api/policies`: Create new security policy (`ADMIN` only).
- `PUT /api/policies/:id`: Toggle or modify policy (`ADMIN` only).
- `GET /api/providers`: Retrieve AI providers and active route.
- `POST /api/providers/active`: Switch active AI provider (`ADMIN` only).
- `GET /api/providers/health`: Execute health check probes on all AI providers.
- `GET /api/organization`: Retrieve organization security context and glossary.
- `PUT /api/organization`: Update organization security context (`ADMIN` only).
- `POST /api/experiments/evaluate`: Execute benchmark evaluation on dataset split (`ADMIN` or `SECURITY_ANALYST`).
- `GET /api/health`: Comprehensive system readiness telemetry.
- `POST /api/auth/login`: Authenticate and obtain role session token.

---

## 10. Prototype Limitations & Honest Disclosure

1. **Detection Scope**: Pattern detection is deterministic (regex, dictionary, contextual heuristics). While highly effective against explicit keys, PII, and known exploit patterns, advanced semantic steganography or novel linguistic evasions may require dedicated machine-learned local models.
2. **Response Inspection**: Response inspection is a prototype capability and reflects perimeter DLP heuristics rather than full generative output guarantees.
3. **Database Layer**: The prototype utilizes an atomic file-backed JSON database with serialized write locks. High-throughput production deployments should substitute PostgreSQL or SQLite.
4. **Mock Provider**: When no external API key is supplied, AEGIS routes to the Safe Mock Provider. All mock interactions are clearly identified in the UI and telemetry.
