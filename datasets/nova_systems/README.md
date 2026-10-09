# NOVA Systems Empirical Research Dataset

**Project Identity**: AEGIS — AI-Enabled Governance & Information Security  
**Tagline**: *SECURE THE BOUNDARY. GOVERN THE INTELLIGENCE.*  
**Target Enterprise**: NOVA Systems (Autonomous Aerospace, Telemetry, and Defense Systems)  
**Annotation Status**: `PENDING HUMAN VALIDATION`  
**Dataset Version**: 1.0.0 (Synthetic Seeded Baseline)  
**Deterministic Random Seed**: `42` (Mulberry32 PRNG)  

---

## 1. Dataset Purpose & Research Scope

### Locked Research Question
> *"How much does organization-specific adaptation improve sensitive-information detection in employee–AI prompts, and what does it cost to keep that detection local?"*

### Research Objective
Generic baseline Data Loss Prevention (DLP) engines and off-the-shelf privacy filters rely heavily on regular expressions and broad keyword dictionaries. While effective at capturing syntactically standard patterns (e.g., credit card numbers, valid AWS keys, or generic Social Security Numbers), generic detectors fail in two primary enterprise scenarios:
1. **False Negatives on Organization-Specific Terminology**: Project codenames, internal microservice FQDNs, proprietary algorithmic descriptions, and unannounced M&A valuations are completely unknown to generic models.
2. **False Positives on Contextual Homonyms**: Words that designate confidential projects within an enterprise (e.g., *Aurora*, *Valkyrie*, *Apex*, *Hyperion*, *Chimera*) frequently occur in benign, public-domain contexts (e.g., astronomy, Norse mythology, geometry, literature). A naive keyword filter either leaks proprietary prompts or floods security operations centers with false alerts.

This dataset provides an empirical, reproducible benchmark to evaluate:
- Baseline regex and dictionary detectors (B0).
- Generic small language models (A0).
- Organization-adapted contextual models (A1 / A2) incorporating organizational policy, glossaries, and few-shot or fine-tuned contextual knowledge.

---

## 2. Classification Tiers & Target Classes

### Classification Tiers (Enterprise Policy Hierarchy)
1. **PUBLIC**: Publicly accessible information, open-source documentation, academic literature, and marketing text with zero corporate liability.
2. **INTERNAL**: Non-sensitive operational communications, general IT task tracking, and internal memos appropriate for all employees.
3. **CONFIDENTIAL**: Proprietary algorithms, telemetry protocol specifications, internal architectural designs, and employee performance appraisals requiring masking or selective restriction.
4. **RESTRICTED**: Critical cryptographic keys, database authentication URIs, unannounced M&A financial valuations, export-controlled telemetry parameters, and employee SSNs strictly barred from external transmission.

### Target Classes (5 Mutually Exclusive Gold Classes)
| Class | Description | Typical Sensitivity | Representative Examples |
|---|---|---|---|
| **PII** | Personally Identifiable Information of employees, candidates, or executives. | `CONFIDENTIAL` to `RESTRICTED` | Social Security Numbers, personal cellular numbers, direct deposit bank accounts, medical leave notes, performance ratings. |
| **secrets** | Cryptographic secrets, authentication credentials, and access tokens. | `RESTRICTED` | Database connection URIs with plaintext credentials, RSA/EC private keys, AWS access keys, GitHub personal access tokens, HMAC signing secrets. |
| **internal identifiers** | Organization-specific infrastructure and development tracking tokens. | `INTERNAL` to `CONFIDENTIAL` | Internal Jira issue keys (`NOVA-ENG-1042`), internal cluster FQDNs (`core-telemetry.internal.novasystems.net`), private Git repositories (`novasys-core/hyper-nav`), hardware revision tags (`NV-HW-REV3-B`). |
| **confidential technical/financial information** | Proprietary engineering architectures, flight telemetry schemas, and corporate finance. | `CONFIDENTIAL` to `RESTRICTED` | Hypersonic telemetry bus rates, drone swarm guidance algorithms, RTOS microkernel memory layouts, M&A cash offers ($140M Project Apex / $88M Project Talon), gross margin targets. |
| **benign** | Legitimate employee workplace queries with zero organizational sensitive data. | `PUBLIC` | General coding assistance (React, TypeScript, Python, Rust), computer science theory, public domain facts, meeting summaries, contextual hard negative homonyms. |

---

## 3. Organization-Specific Terminology & Partitions

To rigorously measure true generalization versus rote memorization, all enterprise terms are partitioned into **SEEN** and **UNSEEN** groups:

### SEEN Terminology (Restricted to `TRAIN` and `DEV` Splits)
- **Project Aurora** (`aurora_flight_seen`): Next-generation hypersonic flight computer and telemetry bus (`CONFIDENTIAL`).
- **Valkyrie-X** (`valkyrie_guidance_seen`): Decentralized autonomous swarm guidance and collision avoidance algorithm (`RESTRICTED`).
- **Zephyr-OS** (`zephyr_kernel_seen`): Real-time operating system microkernel for unmanned avionics (`CONFIDENTIAL`).
- **Project Apex** (`apex_m_and_a_seen`): M&A takeover bid for SkyLink Dynamics at $140M valuation (`RESTRICTED`).
- **Seen Infrastructure**: Hosts (`core-telemetry.internal.novasystems.net`, `vault-01.mgmt.novasystems.net`), Repos (`novasys-core/hyper-nav`, `novasys-sec/auth-broker`), Jira prefixes (`NOVA-ENG`, `NOVA-SEC`, `NOVA-AERO`).

### UNSEEN Terminology (Strictly Held-Out in `TEST` Split)
- **Project Chimera** (`chimera_payload_unseen`): Directed-energy payload subsystem and pulsed laser emitter (`RESTRICTED`).
- **Project Hyperion** (`hyperion_downlink_unseen`): Satellite-to-ground optical laser communications downlink at 40 Gbps (`CONFIDENTIAL`).
- **Project Cerberus** (`cerberus_gateway_unseen`): Zero-trust microsegmentation gateway for tactical edge communications (`CONFIDENTIAL`).
- **Project Talon** (`talon_m_and_a_unseen`): Hostile takeover bid for AeroPrecision Corp at $88M cash (`RESTRICTED`).
- **Sentinel-6** (`sentinel_sensor_unseen`): Classified multi-spectral sensor fusion suite combining SAR and IR (`CONFIDENTIAL`).
- **Unseen Infrastructure**: Hosts (`grid-quantum.internal.novasystems.net`, `secure-broker.prod.novasystems.net`, `edge-node-09.tactical.novasystems.net`), Repos (`novasys-optics/laser-downlink`, `novasys-payload/strike-core`), Jira prefixes (`NOVA-PAYLOAD`, `NOVA-OPTICS`, `NOVA-DIR`).

---

## 4. Contextual Hard-Negative Construction

To verify that detectors do not merely match keywords, the dataset incorporates **25 distinct paired groups (50 prompts total)** of contextual hard negatives:
- Each group contains a **BENIGN** prompt utilizing a term in its public, scientific, mythological, or literary sense.
- The corresponding **SENSITIVE** prompt utilizes the identical term in the proprietary NOVA Systems engineering or corporate governance context.

### Hard Negative Construction Examples

#### Seen Pair (Group `HN-AURORA-01`):
- **BENIGN** (`PUBLIC`):  
  *"The aurora borealis produced vivid geomagnetic displays across northern Norway and Iceland last night."*
- **SENSITIVE** (`CONFIDENTIAL`):  
  *"Ensure the Project Aurora hypersonic telemetry logs are archived prior to the wind-tunnel test."*

#### Unseen Pair (Group `HN-HYPERION-01`):
- **BENIGN** (`PUBLIC`):  
  *"Hyperion is a chaotic tumbling moon of Saturn characterized by an irregular spongy appearance and low density."*
- **SENSITIVE** (`CONFIDENTIAL`):  
  *"The Project Hyperion optical laser downlink achieves 40 Gbps aggregate throughput across low Earth orbit relays."*

#### Unseen Pair (Group `HN-CHIMERA-01`):
- **BENIGN** (`PUBLIC`):  
  *"In classical Greek mythology, the Chimera was a monstrous fire-breathing hybrid creature composed of lion, goat, and serpent."*
- **SENSITIVE** (`RESTRICTED`):  
  *"Project Chimera directed-energy pulse repetition interval must remain locked between 120Hz and 140Hz to prevent emitter overheating."*

---

## 5. Dataset Generation & Split Procedure

### Programmatic Generation Procedure
1. **Deterministic PRNG**: Generation uses a seeded Mulberry32 pseudo-random number generator initialized with seed `42`.
2. **Structured Prompt Templates**: Prompts are created from domain-tailored sentence structures covering 10 distinct template archetypes (debugging, code review, incident response, architecture design, HR onboarding, audit checks, financial modeling, etc.).
3. **Multi-Category Ingestion**: Prompts combining two distinct sensitive domains (e.g., PII + Internal Identifier; Credential + Confidential Technical Spec) are explicitly generated to test compound risk detection.

### Split Procedure & Leakage Prevention Rules
500 candidate prompts were generated during initial synthesis; **446 records** constitute the finalized research dataset after documented filtering (54 candidate variants were excluded during curation to eliminate near-duplicate templates and enforce strict paraphrase-family split isolation).

The finalized dataset is partitioned into `TRAIN` (199 examples), `DEV` (79 examples), and `TEST` (168 examples):
1. **Terminology Leakage Prevention**: All UNSEEN terminology groups (`Chimera`, `Hyperion`, `Cerberus`, `Talon`, `Sentinel-6`, and associated unseen hosts/repos) are strictly barred from `TRAIN` and `DEV`. They appear exclusively in `TEST`.
2. **Template & Paraphrase Leakage Prevention**: Paraphrase families (groups of 5 syntactically distinct prompts interrogating the same underlying concept) are assigned atomically to a single split. Zero paraphrase families cross split boundaries.
3. **Held-Out Evaluation Discipline**: The `TEST` set must never be used to train, tune hyperparameters, select decision thresholds, or modify detection logic.

---

## 6. Dataset Summary Statistics

```json
{
  "organization": "NOVA Systems",
  "total_examples": 446,
  "splits": {
    "TRAIN": 199,
    "DEV": 79,
    "TEST": 168
  },
  "classes": {
    "PII": 59,
    "secrets": 51,
    "internal identifiers": 113,
    "confidential technical/financial information": 129,
    "benign": 94
  },
  "seen_unseen": {
    "SEEN": 278,
    "UNSEEN": 168
  },
  "hard_negatives": {
    "total_hard_negative_examples": 50,
    "distinct_pairs": 25
  },
  "annotation_status": "PENDING HUMAN VALIDATION",
  "deterministic_seed": 42
}
```

---

## 7. Metadata Schema per Record

Every record in `nova_research_dataset.json` adheres to the following specification:

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Unique identifier (e.g., `nova-0001`). |
| `text` | `string` | Complete verbatim prompt text. |
| `gold_class` | `string` | One of the 5 target classes (`PII`, `secrets`, `internal identifiers`, `confidential technical/financial information`, `benign`). |
| `sensitivity_level` | `string` | Policy level (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`). |
| `entity_category` | `string` | Granular category (`PII`, `CREDENTIAL`, `INTERNAL_IDENTIFIER`, `CONFIDENTIAL_TECHNICAL`, `CONFIDENTIAL_FINANCIAL`, `BENIGN`, `MULTI_CATEGORY`). |
| `terminology_group` | `string` | Terminology cluster key (e.g., `aurora_flight_seen`, `chimera_payload_unseen`). |
| `seen_or_unseen` | `string` | Partition designation (`SEEN` or `UNSEEN`). |
| `template_family` | `string` | Template family identifier for leakage tracking. |
| `split` | `string` | Evaluation partition (`TRAIN`, `DEV`, `TEST`). |
| `hard_negative_group` | `string \| null` | Pair identifier for contextual hard negatives (e.g., `HN-AURORA-01`), or `null`. |
| `annotation_status` | `string` | Explicitly marked `PENDING HUMAN VALIDATION`. |

---

## 8. Limitations & Potential Leakage Risks

1. **Synthetic Generation**: Prompts are programmatically generated and rule-curated. While realistic, they lack the idiosyncratic typos, fragmented syntax, and conversational phrasing of real employee chat histories.
2. **Annotation Verification Status**: Labels are deterministically assigned by the generator. No dual-human adjudication or Cohen’s kappa inter-annotator agreement has been performed on this version. All records are explicitly flagged `PENDING HUMAN VALIDATION`.
3. **Pre-training Memorization Risk**: General-purpose LLMs (e.g., GPT-4, Gemini 2.5) may have ingested public domain facts regarding Greek mythology (Cerberus, Chimera) or astronomy (Hyperion, Aurora). While this enables contextual negative detection, it does not provide proprietary awareness of NOVA Systems.
4. **Length Distribution**: Prompts range from 15 to 60 words. Real enterprise prompts may include large multi-page code snippets or stack traces containing buried sensitive identifiers.
