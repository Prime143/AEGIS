# Model Cards: AEGIS Detection Systems

This document provides formal model cards for the detection architectures evaluated in the AEGIS research benchmark.

---

## Model Card 1: Baseline B0 (Regex + Dictionary Reverse-Span Detector)

### Model Details
- **Model Name**: AEGIS Rule-Based Perimeter Filter (B0)
- **Version**: 2.0.0
- **Type**: Deterministic in-memory heuristic matching engine.
- **Components**:
  - `RegexDetector.ts`: Evaluates standard cryptographic credentials, database connection strings, SSNs, emails, phone numbers, and known issue keys.
  - `DictionaryDetector.ts`: Evaluates organizational glossary codenames using case-insensitive whole-word boundary matching.
- **Organization Profile**: NOVA Systems SEEN Context (`Project Aurora`, `Valkyrie-X`, `Zephyr-OS`, `Project Apex`).

### Performance Summary (Held-Out `TEST`, $N = 168$)
- **Precision**: $1.0000$ [$95\%$ CI: $1.0000, 1.0000$]
- **Recall**: $0.1667$ [$95\%$ CI: $0.1032, 0.2326$]
- **F1 Score**: $0.2857$ [$95\%$ CI: $0.1871, 0.3774$]
- **False Positive Rate**: $0.0000$ (0 / 36 benign prompts falsely flagged)
- **Contextual Hard-Negative FPR**: $0.0000$ (0 / 12 homonym prompts falsely flagged)
- **Inference Latency**: $p_{50} = 0.011$ ms, $p_{95} = 0.028$ ms, Mean = $0.034$ ms
- **Memory Footprint**: $1.05$ MB heap allocation

### Intended Use & Limitations
- **Intended Use**: Microsecond-latency first-pass filtering of standard syntactically rigid credentials and known static glossary terms.
- **Limitations**: Completely blind to unseen organizational entities (achieved **$0.0\%$ recall** on held-out internal identifiers and confidential technical specifications). Cannot extrapolate or perform contextual semantic disambiguation.

---

## Model Card 2: Baseline B1 (Microsoft Presidio Analyzer with Custom Recognizers)

### Model Details
- **Model Name**: Microsoft Presidio Analyzer + spaCy `en_core_web_sm`
- **Framework**: Presidio Analyzer 2.2.364, spaCy 3.8.16, Python 3.14.6
- **Architecture**: Hybrid named entity recognition (NER) combining token-level linguistic features with registered regular expression pattern recognizers.
- **Underlying NLP Model**: `en_core_web_sm` (12.8 MB, 4-layer CNN with word embeddings and transition-based parser).
- **Custom Recognizers Registered**:
  - `nova_api_key`, `github_pat`, `aws_key`, `jwt_token`, `db_uri` (Pattern score = 0.95).
  - `jira_keys`, `internal_fqdn`, `internal_repo` (Pattern score = 0.90).
  - `proj_aurora`, `proj_valkyrie`, `proj_zephyr`, `proj_apex` (Pattern score = 0.85).

### Performance Summary (Held-Out `TEST`, $N = 168$)
- **Precision**: $0.8662$ [$95\%$ CI: $0.8138, 0.9197$]
- **Recall**: $0.9318$ [$95\%$ CI: $0.8819, 0.9718$]
- **F1 Score**: $0.8978$ [$95\%$ CI: $0.8582, 0.9339$]
- **False Positive Rate**: $0.5278$ (19 / 36 benign prompts falsely flagged)
- **Contextual Hard-Negative FPR**: **$0.7500$** (9 / 12 homonym prompts falsely flagged)
- **Inference Latency**: $p_{50} = 13.940$ ms, $p_{95} = 23.810$ ms, Mean = $17.260$ ms
- **Memory Footprint**: $10.45$ MB peak RAM

### Intended Use & Limitations
- **Intended Use**: General-purpose PII detection and structured credential extraction.
- **Limitations**: Severe contextual blindness. Presidio pattern recognizers evaluate matches without semantic clause verification, causing an unacceptable **$75\%$ false alarm rate on contextual hard negatives** (e.g., flagging public discussions of the moon *Hyperion* or Greek mythological *Chimera* as security incidents).

---

## Model Card 3: Adaptation Ladder Specification (A0, A1, A2)

### Base Model Specification (Invariant Across All Three Tiers)
- **Base Model**: `meta-llama/Llama-3.2-1B-Instruct`
- **Parameter Count**: 1.23 Billion
- **Context Window**: 131,072 tokens
- **Target Quantization**: Q4_K_M (4-bit GGUF, ~750 MB disk footprint)
- **Execution Target**: Local CPU/GPU inference via `llama.cpp`

### Tier Specifications
1. **Tier A0 (Local Generic SLM)**:
   - *Adaptation*: Zero organizational adaptation. Generic system prompt instructing binary detection of sensitive data.
2. **Tier A1 (Local In-Context Adapted SLM)**:
   - *Adaptation*: In-context learning. System prompt contains the complete NOVA Systems data classification hierarchy, seen glossary terms, sensitive entity guidelines, and 3 few-shot demonstrations from `TRAIN`.
3. **Tier A2 (Local Fine-Tuned SLM)**:
   - *Adaptation*: Parameter-efficient fine-tuning via QLoRA on the `TRAIN` split ($N = 199$). Rank $r = 16$, scaling factor $\alpha = 32$, target linear layers `q_proj, v_proj, k_proj, o_proj`.

### Benchmark Execution Status: `FAILED / UNAVAILABLE`
- **Diagnostic**: The host system (Python 3.14.6 on Windows 11) lacks pre-compiled binary wheels for `llama-cpp-python`, `torch`, and `peft`. Because model weights could not be executed locally in this environment, results were recorded as `FAILED / UNAVAILABLE` in accordance with research ethics standards prohibiting simulated or fabricated model metrics.
