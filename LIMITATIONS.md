# Limitations: AEGIS Research Benchmark

This document details the methodological, architectural, and environmental limitations of the AEGIS experiment (`EXP-NOVA-20261005-001`).

---

## 1. Synthetic Dataset Origin & Phrasing Regularity

1. **Synthetic Generation**: The 446 prompts in the NOVA Systems corpus were generated programmatically using a deterministic seeded pseudo-random generator (Seed `42`) with structured sentence templates and paraphrase families.
2. **Syntactic Cleanliness**: While prompts were engineered to model realistic workplace interactions, they lack the idiosyncratic typos, shorthand, conversational fragmentation, and irregular formatting typical of organic enterprise communications (e.g., Slack or Microsoft Teams messages).
3. **Prompt Length Distribution**: Prompts range from 15 to 60 words. Real enterprise prompts frequently include multi-page log files, full JSON schemas, or long stack traces containing buried sensitive tokens.

---

## 2. Annotation Status & Validation Constraints

1. **Annotation Status**: **`PENDING HUMAN VALIDATION`**. Ground truth labels and sensitivity levels were programmatically assigned during dataset generation.
2. **Absence of Human Adjudication**: No dual-blind human adjudication or inter-annotator agreement metrics (e.g., Cohen’s $\kappa$ or Fleiss’ $\kappa$) have been conducted on this version of the corpus.
3. **Label Discretization**: Prompts are categorized into mutually exclusive primary gold classes. Prompts with compound entities (e.g., both PII and a credential) are designated under a single primary classification in evaluation metrics.

---

## 3. Host Environment & Runtime Missing Dependencies

1. **Host Environment**: The benchmark executed on Windows 11 with Python `3.14.6`. Because Python 3.14 is a pre-release / alpha version of the CPython interpreter, binary wheels for standard deep learning libraries (`torch`, `torchvision`, `llama-cpp-python`, `transformers`, `peft`, `bitsandbytes`) are not yet published for this platform.
2. **Unexecuted Conditions (A0, A1, A2)**: Due to the absence of a compatible local LLM execution runtime on Python 3.14, the local SLM adaptation ladder could not be executed locally. In accordance with empirical integrity principles ("Do not invent missing results"), conditions A0, A1, and A2 were recorded as `FAILED / UNAVAILABLE`.
3. **Cloud Credentials (B3)**: The cloud LLM reference condition requires an active API key. Because `.env` contained a placeholder (`GEMINI_API_KEY="your_api_key_here"`), condition B3 was recorded as `FAILED / UNAVAILABLE`.

---

## 4. Single Enterprise Domain Scope

1. **Domain Focus**: The corpus models a single enterprise: NOVA Systems (an aerospace, defense telemetry, and autonomous avionics contractor).
2. **Cross-Domain Generalizability**: While the evaluation of contextual homonyms (*Hyperion*, *Chimera*, *Valkyrie*) demonstrates fundamental limitations of pattern recognizers, the specific terminology partition reflects defense systems and may not directly extrapolate to biomedical (HIPAA/PHI) or banking (PCI-DSS/SOX) domains without domain-specific data construction.

---

## 5. Adversarial Robustness vs. Benign Information Security

1. **Scope of Investigation**: The benchmark evaluates benign employee inquiries, inadvertent data leakage, and natural homonyms.
2. **Adversarial Jailbreaks**: The experiment does not systematically benchmark sophisticated adversarial jailbreaks, Base64 obfuscation, multi-turn context smuggling, or steganographic prompt injections designed to evade perimeter filters.
