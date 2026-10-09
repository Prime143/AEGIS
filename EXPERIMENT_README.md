# AEGIS Research Evidence Package

**Project Identity**: AEGIS — AI-Enabled Governance & Information Security  
**Tagline**: *SECURE THE BOUNDARY. GOVERN THE INTELLIGENCE.*  
**Experiment Identifier**: `EXP-NOVA-20261005-001`  
**Git Commit**: `748ca9d60037d59f475fb135fd0035da45549a28`  
**Execution Timestamp**: `2026-10-05T12:58:31.268Z`  

---

## 1. Locked Research Question & Scope

> **Locked Research Question**:  
> *“How much does organization-specific adaptation improve sensitive-information detection in employee–AI prompts, and what does it cost to keep that detection local?”*

### Scope
Empirical investigation of sensitive-information detection in employee–AI prompts within an enterprise governance boundary. This package documents the experimental methodology, dataset construction, benchmark execution, and statistical analysis conducted on the **NOVA Systems** aerospace and defense telemetry corpus ($N = 446$).

---

## 2. Distinction: Product Features vs. Research Contributions

To prevent conflation between standard engineering capabilities and empirical research claims, AEGIS strictly delineates:

### Implemented Product Features (Software Architecture)
These components represent standard cybersecurity gateway engineering; **no scientific novelty is claimed for them**:
- **Reverse-Proxy AI Gateway**: Intercepts employee prompts before egress to AI inference providers (`GatewayPipeline.ts`).
- **Policy Engine**: Deterministic rules engine executing `ALLOW`, `MASK`, and `BLOCK` actions (`PolicyEngine.ts`).
- **Span-Level Redaction**: Reverse-index in-place substitution of sensitive tokens (`MaskingService.ts`).
- **Response Inspection**: Egress filter intercepting model hallucinations or prohibited outputs (`ResponseInspector.ts`).
- **Audit Logging**: Cryptographic SHA-256 prompt hashing with zero plaintext secret persistence (`AuditService.ts`).
- **Provider Abstraction**: Multi-provider dispatch supporting local mock and cloud backends (`SafeMockProvider.ts`, `GeminiProvider.ts`).

### Research Contributions (Empirically Demonstrated Findings)
Scientific claims are limited strictly to what was measured and verified in the controlled benchmark:
1. **Empirical Quantization of the Unadapted Heuristic Collapse**: Demonstrated that static regex and dictionary detectors (B0) collapse to **0.0% recall** on held-out, unseen organizational entities and confidential technical specifications, despite maintaining 100% precision.
2. **Empirical Quantization of the Contextual False-Alarm Dilemma**: Demonstrated that off-the-shelf named entity recognition with custom pattern recognizers (B1: Microsoft Presidio) recovers high recall (93.18%) but incurs a **52.78% False Positive Rate on benign text** and a **75.00% False Positive Rate on contextual hard negatives** (homonyms used in public-domain contexts).
3. **Paired Statistical Significance**: Verified via McNemar’s test ($\chi^2 = 52.9113, p = 3.49 \times 10^{-13}$) and Cohen’s $g = +0.3306$ that the difference in classification decisions between B0 and B1 represents a statistically robust, large-effect divergence.
4. **Local Execution Cost Benchmark**: Quantified the baseline execution latency tradeoff on AMD Ryzen 5 hardware: $p_{50} = 0.011$ ms (B0) versus $p_{50} = 13.940$ ms (B1), operating well within the local boundary and orders of magnitude below cloud round-trip latency.

---

## 3. Evidence Package Navigation Index

| Artifact | File Path | Description |
|---|---|---|
| **Dataset Card** | [DATASET_CARD.md](file:///d:/antigravity/AEGIS/DATASET_CARD.md) | Documentation of the NOVA Systems corpus, taxonomy, generation, and annotation status. |
| **Model Card** | [MODEL_CARD.md](file:///d:/antigravity/AEGIS/MODEL_CARD.md) | Technical cards for B0, B1, and the planned A0/A1/A2 adaptation ladder. |
| **Protocol** | [EXPERIMENT_PROTOCOL.md](file:///d:/antigravity/AEGIS/EXPERIMENT_PROTOCOL.md) | Step-by-step benchmark protocol, threshold selection rules, and bootstrap parameters. |
| **Results** | [RESULTS.md](file:///d:/antigravity/AEGIS/RESULTS.md) | Comprehensive empirical metric tables, paired test results, and figure discussions. |
| **Limitations** | [LIMITATIONS.md](file:///d:/antigravity/AEGIS/LIMITATIONS.md) | Honest assessment of synthetic data origin, missing dependencies, and scope limits. |
| **Reproducibility** | [REPRODUCIBILITY.md](file:///d:/antigravity/AEGIS/REPRODUCIBILITY.md) | End-to-end instructions to reproduce all numbers, logs, and figures from scratch. |
| **Threats to Validity**| [THREATS_TO_VALIDITY.md](file:///d:/antigravity/AEGIS/THREATS_TO_VALIDITY.md) | Examination of construct, internal, external, and statistical conclusion validity. |
| **References** | [REFERENCES.md](file:///d:/antigravity/AEGIS/REFERENCES.md) | Non-fabricated academic and industry literature citations. |
| **Summary Table (JSON)**| [results_summary.json](file:///d:/antigravity/AEGIS/results_summary.json) | Machine-readable metrics summary with McNemar statistics. |
| **Summary Table (CSV)** | [results_summary.csv](file:///d:/antigravity/AEGIS/results_summary.csv) | Spreadsheet-compatible metric export. |
| **Full Manifest** | [experiment_manifest.json](file:///d:/antigravity/AEGIS/experiment_manifest.json) | Complete execution metadata and diagnostic manifest. |

---

## 4. Benchmark Summary at a Glance

```
========================================================================================
Condition  Name                           Status     F1 (95% CI)          FPR      p50 Latency
========================================================================================
B0         Regex + Dictionary Baseline    EXECUTED   0.2857 [0.187, 0.377] 0.0000   0.011 ms
B1         Microsoft Presidio Baseline    EXECUTED   0.8978 [0.858, 0.934] 0.5278  13.940 ms
B2         OpenAI Privacy Filter Baseline FAILED     N/A                  N/A      N/A
B3         Cloud LLM Reference Condition  FAILED     N/A                  N/A      N/A
A0         Local Generic SLM              FAILED     N/A                  N/A      N/A
A1         Local Adapted SLM              FAILED     N/A                  N/A      N/A
A2         Local Fine-Tuned SLM (QLoRA)   FAILED     N/A                  N/A      N/A
========================================================================================
* Paired McNemar Test (B0 vs B1 on N = 168): Chi2 = 52.9113, p = 3.49e-13 (Statistically Significant)
* Contextual Hard-Negative FPR: B0 = 0.0% (0/12) vs. B1 = 75.0% (9/12)
* Hypotheses H1 & H2 Empirical Status: INCONCLUSIVE (Adaptation ladder unrun due to missing local wheels)
```
