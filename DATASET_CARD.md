# Dataset Card: NOVA Systems Sensitive Information Corpus

**Dataset Name**: NOVA Systems Employee Prompt Sensitivity Corpus  
**Version**: 1.0.0  
**Curators**: AEGIS Research Team  
**Annotation Status**: **`PENDING HUMAN VALIDATION`**  
**Deterministic Seed**: `42` (Mulberry32 PRNG)  
**Corpus Files**:
- [datasets/nova_systems/nova_research_dataset.json](file:///d:/antigravity/AEGIS/datasets/nova_systems/nova_research_dataset.json) (JSON array, $N = 446$)
- [datasets/nova_systems/nova_research_dataset.jsonl](file:///d:/antigravity/AEGIS/datasets/nova_systems/nova_research_dataset.jsonl) (JSON Lines, $N = 446$)

---

## 1. Dataset Summary & Research Purpose

This dataset is designed to evaluate enterprise boundary detection algorithms under realistic conditions of organizational jargon, technical specifications, and contextual homonyms. The target enterprise profile is **NOVA Systems**, a synthetic aerospace and defense contractor developing autonomous telemetry, hypersonic navigation, and directed energy avionics.

### Dataset Accounting & Partition Sizing
- **Candidate Pool**: 500 candidate prompts were programmatically generated during initial synthesis.
- **Finalized Corpus**: **446 records** constitute the finalized research dataset after documented filtering (54 candidate variants were pruned to eliminate template redundancy and ensure absolute zero-leakage paraphrase family isolation across partitions).
- **Split Accounting**:
  - `TRAIN`: **199 prompts** (Seen organizational codenames and generic patterns)
  - `DEV`: **79 prompts** (Validation and decision threshold selection)
  - `TEST`: **168 prompts** (Held-out evaluation partition; unseen terminology)
  - **Total**: $199 + 79 + 168 = \mathbf{446}$ records.

The corpus tests whether sensitive information detectors:
1. Detect standard syntactic patterns (credentials, PII).
2. Generalize to organization-specific proprietary terminology and internal infrastructure.
3. Differentiate contextual homonyms (e.g., words that are sensitive within the enterprise but benign in public discourse).

---

## 2. Classification Hierarchy & Target Classes

### Sensitivity Tiers
- **`PUBLIC`**: Publicly available scientific literature, open-source software questions, and marketing documentation.
- **`INTERNAL`**: Routine operational workflows, issue tracking, and internal memos.
- **`CONFIDENTIAL`**: Proprietary algorithms, telemetry packet schemas, and non-public product roadmaps requiring masking or operational filtering.
- **`RESTRICTED`**: Authentication secrets, cryptographic private keys, unannounced M&A valuations, and employee SSNs strictly barred from egress.

### Target Classes (5 Mutually Exclusive Categories)
| Target Class | Support in Corpus | Support in `TEST` | Primary Sensitivity | Example Entities |
|---|---|---|---|---|
| **`PII`** | 59 (13.2%) | 12 (7.1%) | `CONFIDENTIAL` to `RESTRICTED` | Social Security Numbers, personal mobile numbers, home addresses, compensation records. |
| **`secrets`** | 51 (11.4%) | 25 (14.9%) | `RESTRICTED` | Database URIs with credentials, AWS/GitHub tokens, RSA/EC private keys, JWT secrets. |
| **`internal identifiers`** | 113 (25.3%) | 41 (24.4%) | `INTERNAL` to `CONFIDENTIAL` | Cluster hostnames (`*.internal.novasystems.net`), Jira keys (`NOVA-ENG-xxxx`), git repos, hardware revision IDs. |
| **`confidential technical/financial information`** | 129 (28.9%) | 54 (32.1%) | `CONFIDENTIAL` to `RESTRICTED` | Hypersonic flight telemetry, swarm guidance algorithms, M&A valuations ($140M Apex / $88M Talon), profit margins. |
| **`benign`** | 94 (21.1%) | 36 (21.4%) | `PUBLIC` | Programming queries, operating system internals, math/physics questions, and contextual hard negatives. |
| **Total** | **446 (100.0%)** | **168 (100.0%)** | — | — |

---

## 3. Terminology Partitioning (Seen vs. Unseen)

To rigorously test generalization versus memorization, organizational entities are strictly partitioned:

### SEEN Terminology (Restricted to `TRAIN` and `DEV`)
- **Project Aurora** (`aurora_flight_seen`): Next-gen hypersonic telemetry bus (`CONFIDENTIAL`).
- **Valkyrie-X** (`valkyrie_guidance_seen`): Decentralized swarm trajectory consensus (`RESTRICTED`).
- **Zephyr-OS** (`zephyr_kernel_seen`): Avionics RTOS microkernel (`CONFIDENTIAL`).
- **Project Apex** (`apex_m_and_a_seen`): $140M M&A takeover bid for SkyLink Dynamics (`RESTRICTED`).
- **Seen Infrastructure**: `core-telemetry.internal.novasystems.net`, `novasys-core/hyper-nav`, `NOVA-ENG-xxxx`.

### UNSEEN Terminology (Strictly Held-Out in `TEST`)
- **Project Chimera** (`chimera_payload_unseen`): Directed energy pulsed laser emitter (`RESTRICTED`).
- **Project Hyperion** (`hyperion_downlink_unseen`): 40 Gbps satellite optical laser downlink (`CONFIDENTIAL`).
- **Project Cerberus** (`cerberus_gateway_unseen`): Tactical zero-trust microsegmentation gateway (`CONFIDENTIAL`).
- **Project Talon** (`talon_m_and_a_unseen`): $88M tender offer for AeroPrecision Corp (`RESTRICTED`).
- **Sentinel-6** (`sentinel_sensor_unseen`): Classified multi-spectral sensor suite (`CONFIDENTIAL`).
- **Unseen Infrastructure**: `grid-quantum.internal.novasystems.net`, `novasys-optics/laser-downlink`, `NOVA-PAYLOAD-xxxx`.

---

## 4. Contextual Hard-Negative Construction

The corpus incorporates **25 paired groups (50 total prompts)** of contextual hard negatives:
- **Benign Instance**: Uses a term in its public, scientific, mythological, or literary context (`PUBLIC`).
- **Sensitive Instance**: Uses the identical term in NOVA Systems proprietary engineering or corporate strategy (`CONFIDENTIAL` or `RESTRICTED`).

### Representative Paired Examples
1. **Chimera**:
   - *Benign*: "In classical Greek mythology, the Chimera was a monstrous fire-breathing hybrid creature composed of lion, goat, and serpent."
   - *Sensitive*: "Project Chimera directed-energy pulse repetition interval must remain locked between 120Hz and 140Hz to prevent emitter overheating."
2. **Hyperion**:
   - *Benign*: "Hyperion is a chaotic tumbling moon of Saturn characterized by an irregular spongy appearance and low density."
   - *Sensitive*: "The Project Hyperion optical laser downlink achieves 40 Gbps aggregate throughput across low Earth orbit relays."
3. **Talon**:
   - *Benign*: "The Northrop T-38 Talon is a twin-engine supersonic jet trainer utilized extensively by NASA."
   - *Sensitive*: "The Project Talon tender offer proposes purchasing AeroPrecision Corp outstanding shares at $42.50 per share in cash."

---

## 5. Dataset Splits & Leakage Prevention

| Partition | Size | Percentage | Terminology Class | Purpose |
|---|---|---|---|---|
| **`TRAIN`** | 199 | 44.6% | `SEEN` Only | Adaptation, glossary ingestion, and future fine-tuning. |
| **`DEV`** | 79 | 17.7% | `SEEN` Only | Calibration of decision thresholds and hyperparameter tuning. |
| **`TEST`** | 168 | 37.7% | **`UNSEEN` Strictly** | Final benchmark evaluation. Strictly frozen. |

### Leakage Prevention Rules
1. **Zero Unseen Terminology in Training**: Verified programmatically. Exactly 0 unseen records appear in `TRAIN` or `DEV`.
2. **Atomic Paraphrase Family Isolation**: Paraphrase families (e.g., `PARA-CHIMERA-THERMAL`, `PARA-HYPERION-DOWNLINK`) are assigned in their entirety to a single split. Zero paraphrase variants cross split boundaries.

---

## 6. Annotation Status & Limitations

- **Annotation Status**: **`PENDING HUMAN VALIDATION`**. Labels were deterministically assigned during programmatic generation.
- **Inter-Annotator Agreement**: Because formal dual-blind human adjudication has not yet been conducted on this version, no Cohen’s $\kappa$ metric is claimed.
- **Synthetic Origin**: All employee names, phone numbers, SSNs, and corporate secrets are synthetically generated. No real personal data or active credentials exist in the corpus.
