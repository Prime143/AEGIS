# AEGIS Empirical Research Report: Controlled Detector Experiment

**Experiment Identifier**: `EXP-NOVA-20261005-001`  
**Execution Timestamp**: `2026-10-05T12:58:31.268Z`  
**Project Identity**: AEGIS — AI-Enabled Governance & Information Security  
**Tagline**: *SECURE THE BOUNDARY. GOVERN THE INTELLIGENCE.*  

---

## 1. Locked Research Question & Objectives

> **Locked Research Question**:  
> *“How much does organization-specific adaptation improve sensitive-information detection in employee–AI prompts, and what does it cost to keep that detection local?”*

Modern enterprises deploying AI productivity assistants face a fundamental perimeter governance dilemma: generic Data Loss Prevention (DLP) engines (e.g., regex patterns, off-the-shelf named entity recognizers, or cloud privacy filters) lack knowledge of organization-specific project codenames, internal infrastructure FQDNs, and confidential financial models. When security teams attempt to remedy this by adding broad keyword matchers, detectors suffer from severe alert fatigue caused by **contextual homonyms**—words that are confidential in an enterprise project context (e.g., *Aurora*, *Valkyrie*, *Apex*, *Hyperion*, *Chimera*) but entirely benign in public domain contexts (astronomy, mythology, geometry, literature).

This controlled experiment evaluates detection efficacy, false-positive resistance, and inference latency across baseline architectures and adaptation approaches on a frozen, held-out organizational test corpus.

---

## 2. Experimental Corpus & Partition Discipline

### Target Enterprise Profile: NOVA Systems
- **Domain**: Autonomous aerospace, defense avionics, and telemetry systems.
- **Data Classification Hierarchy**: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`.
- **Target Gold Classes**:
  1. `PII`: Employee, candidate, and executive identifiers (SSNs, personal cellular numbers, direct deposit accounts, medical leave).
  2. `secrets`: API keys, database connection strings, private keys, bearer tokens.
  3. `internal identifiers`: Internal cluster hosts, Jira keys (`NOVA-ENG-xxxx`), proprietary repositories, hardware revision tags.
  4. `confidential technical/financial information`: Hypersonic telemetry specs, swarm guidance algorithms, M&A takeover bids, quarterly margin models.
  5. `benign`: General engineering, mathematics, computer science theory, and contextual hard negatives.

### Partition Discipline & Leakage Prevention
The research dataset was deterministically generated (Seed `42`) with strict structural isolation:
- **Total Corpus**: $N = 446$ prompts.
- **`TRAIN` Split** ($N = 199$): Restricted strictly to SEEN terminology (`Project Aurora`, `Valkyrie-X`, `Zephyr-OS`, `Project Apex`, and seen internal clusters).
- **`DEV` Split** ($N = 79$): Used exclusively for threshold selection and hyperparameter tuning ($\tau = 0.50$, Presidio confidence $\tau = 0.40$).
- **`TEST` Split** ($N = 168$): **Strictly held-out evaluation partition**. All organization-specific entities in `TEST` are **UNSEEN** in training (`Project Chimera`, `Project Hyperion`, `Project Cerberus`, `Project Talon`, `Sentinel-6`, and unseen tactical clusters).

```
Dataset Split Summary:
├── TRAIN: 199 prompts (44.6%) — Seen Terminology Only
├── DEV:    79 prompts (17.7%) — Threshold Tuning Only
└── TEST:  168 prompts (37.7%) — Held-Out Evaluation (132 Sensitive, 36 Benign, 12 Hard Negatives)
```

---

## 3. Condition Matrix & Implementation Status

| ID | Condition Name | Adaptation Tier | Execution Status | Failure Reason / Diagnostic |
|---|---|---|---|---|
| **B0** | Regex + Dictionary Baseline | Unadapted (Seen Glossary Only) | **EXECUTED** | Evaluated locally on 168 `TEST` prompts via in-memory reverse-span matching. |
| **B1** | Microsoft Presidio Baseline | Custom Pattern Recognizers | **EXECUTED** | Evaluated locally on 168 `TEST` prompts via Presidio Analyzer 2.2.364 with spaCy `en_core_web_sm`. |
| **B2** | OpenAI Privacy Filter Baseline | Off-the-Shelf Safety API | **FAILED / UNAVAILABLE** | Interface audit confirms that native OpenAI Moderation API (`omni-moderation-latest`) only evaluates safety categories (`hate`, `harassment`, `sexual`, `self-harm`, `violence`). It does not support arbitrary enterprise DLP categories or organizational project glossaries. Host environment also lacks `OPENAI_API_KEY`. |
| **B3** | Cloud LLM Reference Condition | In-Context Cloud Prompting | **FAILED / UNAVAILABLE** | Task prompt and JSON schema defined; execution halted due to unconfigured API key (`GEMINI_API_KEY="your_api_key_here"` in `.env`). In accordance with research integrity guardrails, zero simulated cloud scores were substituted. |
| **A0** | Local Generic SLM | Zero Adaptation | **FAILED / UNAVAILABLE** | Model locked to `meta-llama/Llama-3.2-1B-Instruct` (1.23B, Q4_K_M GGUF). Python 3.14 on Windows 11 lacks compatible local inference wheels (`llama_cpp`, `torch`). |
| **A1** | Local In-Context Adapted SLM | In-Context Learning (Policy + Glossary) | **FAILED / UNAVAILABLE** | Identical base model; host lacks local LLM execution runtime. |
| **A2** | Local Fine-Tuned SLM | QLoRA Parameter Adaptation | **FAILED / UNAVAILABLE** | Identical base model fine-tuned on `TRAIN` ($r=16, \alpha=32$); host lacks `peft` / `bitsandbytes` / `torch`. |

---

## 4. Empirical Evaluation Results

### Table 1: Primary Benchmark Metrics on Held-Out `TEST` Split ($N = 168$)
All metrics computed on frozen `TEST` data. Confidence intervals represent non-parametric percentile bootstrap intervals ($B = 1000$ resamples with replacement, Seed `42`).

| Metric | B0: Regex + Dictionary | B1: Microsoft Presidio | Descriptive Difference | Paired Significance |
|---|---|---|---|---|
| **Detection Recall** | **0.1667** [0.1032, 0.2326] | **0.9318** [0.8819, 0.9718] | +0.7651 (+459.0%) | $p = 3.49 \times 10^{-13}$ (McNemar) |
| **Precision** | **1.0000** [1.0000, 1.0000] | **0.8662** [0.8138, 0.9197] | -0.1338 (-13.4%) | Significant drop |
| **F1 Score** | **0.2857** [0.1871, 0.3774] | **0.8978** [0.8582, 0.9339] | **+0.6121** (+214.2%) | 95% CI: [+0.5159, +0.7158] |
| **False Positive Rate (FPR)** | **0.0000** (0 / 36) | **0.5278** (19 / 36) | +0.5278 (+52.8 pp) | Catastrophic false alarm rate |
| **False Negative Rate (FNR)** | **0.8333** (110 / 132) | **0.0682** (9 / 132) | -0.7651 (-76.5 pp) | Significant sensitivity gain |
| **Hard-Negative FPR** | **0.0000** (0 / 12) | **0.7500** (9 / 12) | +0.7500 (+75.0 pp) | Complete contextual failure |
| **$p_{50}$ Latency** | **0.011 ms** | **13.940 ms** | +13.929 ms (~1,267×) | In-memory vs. NLP engine |
| **$p_{95}$ Latency** | **0.028 ms** | **23.810 ms** | +23.782 ms (~850×) | Sub-millisecond vs. 24ms tail |
| **Memory Footprint** | **1.05 MB heap** | **10.45 MB peak** | +9.40 MB | Lightweight local footprint |

---

## 5. Statistical Significance & Paired Sample Analysis

Because both B0 and B1 were evaluated on the **exact same 168 held-out test prompts**, a paired statistical analysis was conducted:

### Paired 2×2 Contingency Table
Classification correctness ($y_i == \hat{y}_i$) across identical prompts:

```
                      B1 Correct        B1 Incorrect
B0 Correct               37 (n11)          21 (n10)
B0 Incorrect            103 (n01)           7 (n00)
```

1. **Discordant Pairs**:
   - Cases where B0 was wrong and B1 was correct: $n_{01} = 103$.
   - Cases where B0 was correct and B1 was wrong: $n_{10} = 21$.
   - Total discordant pairs: $n_{01} + n_{10} = 124$.
2. **McNemar's Test (with Edwards Continuity Correction)**:
   $$\chi^2 = \frac{(|n_{01} - n_{10}| - 1)^2}{n_{01} + n_{10}} = \frac{(|103 - 21| - 1)^2}{124} = \frac{81^2}{124} = 52.9113$$
   $$p\text{-value} = 3.4905 \times 10^{-13} \quad (p < 0.0001)$$
   The decision behavior between B0 and B1 is **statistically significantly different** at the $\alpha = 0.001$ level.
3. **Effect Size**:
   - **Cohen's $g$ for Paired Proportions**:
     $$g = \frac{n_{01}}{n_{01} + n_{10}} - 0.5 = \frac{103}{124} - 0.5 = 0.8306 - 0.5 = +0.3306$$
     A Cohen's $g > 0.25$ denotes a **large directional effect size** favoring B1 in overall sample-level accuracy.
   - **Discordant Odds Ratio**:
     $$\text{OR} = \frac{n_{01}}{n_{10}} = \frac{103}{21} = 4.9048$$
     A sample misclassified by B0 is **4.9 times more likely** to be correctly resolved by B1 than vice versa.
4. **Paired Bootstrap Difference in F1 ($\Delta F1 = F1_{B1} - F1_{B0}$)**:
   $$\Delta F1_{\text{mean}} = +0.6150 \quad [95\% \text{ CI: } +0.5159, +0.7158]$$
   Because the 95% confidence interval strictly excludes zero by a substantial margin, the descriptive difference in F1 represents a statistically robust shift.

---

## 6. Detailed Analysis by Research Figure

### Figure 1: Empirical F1 Comparison Across Evaluation Conditions
- **Artifact**: [figure1_f1_comparison.png](file:///d:/antigravity/AEGIS/src/core/experiments/results/EXP-NOVA-20261005-001/figures/figure1_f1_comparison.png)
- **Key Finding**: Displays F1 scores across all 7 protocol conditions. B0 achieves $F1 = 0.286$ [0.187, 0.377], while B1 reaches $F1 = 0.898$ [0.858, 0.934]. Conditions B2, B3, A0, A1, and A2 are explicitly displayed with hatched bars and red status tags ("FAILED / UNAVAILABLE") to guarantee absolute transparency regarding missing dependencies.

### Figure 2: Operating Trade-Off: Detection Recall vs. False-Positive Rate (ROC Space)
- **Artifact**: [figure2_recall_vs_fpr.png](file:///d:/antigravity/AEGIS/src/core/experiments/results/EXP-NOVA-20261005-001/figures/figure2_recall_vs_fpr.png)
- **Key Finding**: Visualizes the severe enterprise perimeter trade-off. B0 resides at $(FPR = 0.00\%, Recall = 16.67\%)$—it causes zero operational disruption but suffers an intolerable $83.33\%$ false negative leakage rate. B1 shifts to $(FPR = 52.78\%, Recall = 93.18\%)$—it catches nearly all leaks but blocks more than half of all legitimate benign employee prompts. Neither heuristic baseline approaches the ideal operating point $(FPR = 0\%, Recall = 100\%)$.

### Figure 3: Performance by Detection Category (Failure Modes Across Sensitive Categories)
- **Artifact**: [figure3_performance_by_category.png](file:///d:/antigravity/AEGIS/src/core/experiments/results/EXP-NOVA-20261005-001/figures/figure3_performance_by_category.png)
- **Key Finding**: Illustrates the architectural collapse of unadapted baselines across distinct information categories. On standard PII and credentials, B0 achieves $50.0\%$ and $64.0\%$ recall. However, on internal identifiers and confidential technical/financial prompts, B0 drops to **$0.0\%$ recall**. Presidio maintains $>88\%$ recall across categories by matching broad patterns, but in doing so causes a $75.0\%$ false-positive rate on contextual hard negatives. (*Note*: All 168 TEST prompts are partition-level UNSEEN records; Figure 3 reflects category-level failure modes rather than a split-based seen-vs-unseen experiment).

### Figure 4: Detection Efficacy vs. p95 Local Inference Latency
- **Artifact**: [figure4_latency_vs_f1.png](file:///d:/antigravity/AEGIS/src/core/experiments/results/EXP-NOVA-20261005-001/figures/figure4_latency_vs_f1.png)
- **Key Finding**: Analyzes the cost of keeping detection local. B0 operates at in-memory speed ($p_{95} = 0.028$ ms, 1.05 MB heap). B1 incurs entity-recognition tokenization overhead ($p_{95} = 23.81$ ms, 10.45 MB RAM), but remains orders of magnitude faster than the typical cloud WAN round-trip latency envelope ($200 - 800$ ms).

### Figure 5: Per-Category Detection Efficacy Across Enterprise Information Types
- **Artifact**: [figure5_per_class_breakdown.png](file:///d:/antigravity/AEGIS/src/core/experiments/results/EXP-NOVA-20261005-001/figures/figure5_per_class_breakdown.png)
- **Key Finding**:
  - `PII` ($N=12$): B0 = 50.0%, B1 = 100.0%.
  - `Secrets` ($N=25$): B0 = 64.0%, B1 = 92.0%.
  - `Internal Identifiers` ($N=41$): B0 = **0.0%**, B1 = 97.6%.
  - `Confidential Tech/Fin` ($N=54$): B0 = **0.0%**, B1 = 88.9%.
  - `Benign Specificity` ($N=36$): B0 = **100.0%**, B1 = 47.2%.

---

## 7. Contextual Hard-Negative Failure Analysis

To evaluate whether pattern-based recognizers comprehend semantic context, the `TEST` split includes 12 paired benign prompts containing homonyms (*Hyperion*, *Chimera*, *Cerberus*, *Talon*, *Sentinel-6*) in public domains:

| Prompt Text | Public Context | Gold Class | B0 Decision | B1 Decision | Contextual Failure? |
|---|---|---|---|---|---|
| *"Hyperion is a chaotic tumbling moon of Saturn characterized by an irregular spongy appearance."* | Astronomy | `benign` | ALLOW (Correct) | **BLOCK (False Alarm)** | **YES (B1 failed)** |
| *"In classical Greek mythology, the Chimera was a monstrous fire-breathing hybrid creature."* | Mythology | `benign` | ALLOW (Correct) | **BLOCK (False Alarm)** | **YES (B1 failed)** |
| *"A genetic chimera is a single organism composed of cells with more than one distinct genotype."* | Genetics | `benign` | ALLOW (Correct) | **BLOCK (False Alarm)** | **YES (B1 failed)** |
| *"The Northrop T-38 Talon is a twin-engine supersonic jet trainer utilized extensively by NASA."* | Aviation History | `benign` | ALLOW (Correct) | **BLOCK (False Alarm)** | **YES (B1 failed)** |
| *"The Sentinel-6 Michael Freilich satellite was launched in 2020 to measure sea level rise."* | Oceanography | `benign` | ALLOW (Correct) | **BLOCK (False Alarm)** | **YES (B1 failed)** |

- **B0 Hard-Negative FPR**: **0.0%** (0 / 12). B0 avoids false alarms only because the unseen words are absent from its static dictionary.
- **B1 Hard-Negative FPR**: **75.0%** (9 / 12). Presidio flags 9 out of 12 public sentences as security incidents because its pattern recognizers trigger blindly on keywords.

This empirical finding demonstrates that naive entity recognition without contextual semantic disambiguation is incapable of differentiating confidential projects from legitimate public discourse.

---

## 8. Explicit Hypothesis Evaluation

### Hypothesis H1
> *Does organization-specific adaptation improve held-out organization-specific detection relative to the selected baselines at matched false-positive rate?*

- **Empirical Status**: **INCONCLUSIVE**
- **Evidence-Based Rationale**:
  - The executed baselines establish that rule-based systems face a severe dilemma: B0 achieves $0.00\%$ FPR but fails catastrophically on held-out organizational terms ($83.33\%$ FNR). B1 recovers recall ($93.18\%$) via broad patterns, but produces a prohibitive $52.78\%$ FPR on benign text and $75.00\%$ FPR on contextual hard negatives.
  - However, because conditions A0, A1, and A2 failed to execute locally due to missing runtime libraries (`llama_cpp`, `torch`) on host Python 3.14, no empirical curve at matched FPR between A0, A1, and A2 could be directly measured.
  - Therefore, strictly under empirical standards, H1 cannot be confirmed or rejected; it remains **INCONCLUSIVE**.

---

### Hypothesis H2
> *How close is local adapted detection to the cloud reference condition, and what latency/compute cost is incurred?*

- **Empirical Status**: **INCONCLUSIVE**
- **Evidence-Based Rationale**:
  - Condition B3 (Cloud LLM Reference) was unexecutable due to unconfigured API credentials, and conditions A1/A2 were unexecutable locally due to missing runtime libraries.
  - While local inference latency for heuristic and NLP detectors was established at $p_{50} = 0.011$ ms (B0) and $p_{50} = 13.94$ ms (B1) with a minimal peak memory footprint ($10.45$ MB), the comparative performance delta and compute cost against cloud LLMs cannot be asserted without live cloud and local SLM inference data.
  - Therefore, strictly under empirical standards, H2 remains **INCONCLUSIVE**.

---

## 9. Reproducibility Manifest & Exported Artifacts

All data, scripts, figures, and manifests are preserved for independent verification:

```
src/core/experiments/results/EXP-NOVA-20261005-001/
├── predictions.json           # Verbatim sample-level binary predictions and ground truth
├── metrics.json               # Full metric dictionary with bootstrap 95% CIs
├── latencies.json             # Microsecond latency measurements per prompt
├── experiment_manifest.json   # Machine-readable execution manifest
├── experiment_config.json     # Configuration file recording seeds and thresholds
├── experiment.log             # Step-by-step benchmark execution log
├── results_summary.json       # Machine-readable summary table with McNemar statistics
├── results_summary.csv        # Tabular export for spreadsheets and papers
└── figures/
    ├── figure1_f1_comparison.png (.svg)       # F1 comparison with 95% CIs across conditions
    ├── figure2_recall_vs_fpr.png (.svg)       # ROC space operating trade-off
    ├── figure3_seen_vs_unseen.png (.svg)      # Known patterns vs unseen terms breakdown
    ├── figure4_latency_vs_f1.png (.svg)       # F1 vs p95 local inference latency
    └── figure5_per_class_breakdown.png (.svg) # Per-category sensitivity analysis
```

Also exported to root workspace:
- [results_summary.json](file:///d:/antigravity/AEGIS/results_summary.json)
- [results_summary.csv](file:///d:/antigravity/AEGIS/results_summary.csv)
- [experiment_report.md](file:///d:/antigravity/AEGIS/experiment_report.md)
