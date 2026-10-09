# Empirical Results: Controlled Perimeter Detector Benchmark

**Experiment ID**: `EXP-NOVA-20261005-001`  
**Evaluation Partition**: Frozen Held-Out `TEST` Split ($N = 168$ prompts)  
**Execution Timestamp**: `2026-10-05T12:58:31.268Z`  

---

## 1. Benchmark Results Summary

Table 1 summarizes detection performance, error rates, confidence intervals, and inference latency across all 7 experimental conditions:

### Table 1: Complete Benchmark Performance Matrix
| Condition | Architecture | Status | Precision (95% CI) | Recall (95% CI) | F1 Score (95% CI) | FPR | FNR | Hard-Neg FPR | $p_{50}$ Latency | $p_{95}$ Latency | Peak RAM |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **B0** | Regex + Dict | **EXECUTED** | **1.0000**<br>[1.000, 1.000] | **0.1667**<br>[0.103, 0.233] | **0.2857**<br>[0.187, 0.377] | 0.0000 | 0.8333 | 0.0000 | 0.011 ms | 0.028 ms | 1.05 MB |
| **B1** | Presidio Analyzer | **EXECUTED** | **0.8662**<br>[0.814, 0.920] | **0.9318**<br>[0.882, 0.972] | **0.8978**<br>[0.858, 0.934] | 0.5278 | 0.0682 | 0.7500 | 13.940 ms | 23.810 ms | 10.45 MB |
| **B2** | OpenAI Privacy Filter | **FAILED** | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| **B3** | Cloud LLM Reference | **FAILED** | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| **A0** | Local Generic SLM | **FAILED** | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| **A1** | Local Adapted SLM | **FAILED** | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| **A2** | Local Fine-Tuned SLM | **FAILED** | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |

---

## 2. Statistical Significance & Paired Sample Analysis

Because both B0 and B1 were evaluated on the **exact same 168 held-out test prompts**, an exact paired statistical analysis was conducted:

### Paired Contingency Table (Sample-Level Accuracy)
$$\begin{array}{c|cc}
& \text{B1 Correct} & \text{B1 Incorrect} \\
\hline
\text{B0 Correct} & 37 \; (n_{11}) & 21 \; (n_{10}) \\
\text{B0 Incorrect} & 103 \; (n_{01}) & 7 \; (n_{00}) \\
\end{array}$$

1. **McNemar’s Test (with Edwards Continuity Correction)**:
   $$\chi^2 = \frac{(|103 - 21| - 1)^2}{103 + 21} = \frac{81^2}{124} = \mathbf{52.9113}$$
   $$p\text{-value} = \mathbf{3.4905 \times 10^{-13}} \quad (p < 0.0001)$$
   The decision distribution difference between B0 and B1 is **statistically significant** at the $\alpha = 0.001$ level.

2. **Directional Effect Size**:
   - **Cohen’s $g$ for Paired Proportions**:
     $$g = \frac{103}{124} - 0.5 = 0.8306 - 0.5 = \mathbf{+0.3306}$$
     A value of $g > 0.25$ denotes a **large directional effect size** favoring B1 in overall correct binary decisions.
   - **Discordant Odds Ratio (OR)**:
     $$\text{OR} = \frac{103}{21} = \mathbf{4.9048}$$
     A sample misclassified by B0 is **4.9 times more likely** to be correctly resolved by B1 than vice versa.

3. **Paired Bootstrap Difference in F1 Score ($\Delta F1 = F1_{B1} - F1_{B0}$)**:
   $$\Delta F1_{\text{mean}} = \mathbf{+0.6150} \quad [95\% \text{ Bootstrap CI: } \mathbf{+0.5159, +0.7158}]$$
   Because the paired 95% bootstrap confidence interval strictly excludes zero, the descriptive difference in F1 represents a statistically robust shift.

---

## 3. Per-Category Sensitivity & Specificity

### Table 2: Category Breakdown on Held-Out `TEST` Split
| Information Category | Support ($N$) | B0 Recall / Specificity | B1 Recall / Specificity | Performance Divergence |
|---|---|---|---|---|
| **`PII`** | 12 | 50.0% (6 / 12) | **100.0%** (12 / 12) | Presidio catches all structured personal identifiers |
| **`secrets`** | 25 | 64.0% (16 / 25) | **92.0%** (23 / 25) | Presidio regex matches broader token formats |
| **`internal identifiers`** | 41 | **0.0%** (0 / 41) | **97.6%** (40 / 41) | B0 suffers total failure on unseen hostnames / repos |
| **`confidential technical/financial`** | 54 | **0.0%** (0 / 54) | **88.9%** (48 / 54) | B0 suffers total failure on unannounced project codenames |
| **`benign` (Specificity)** | 36 | **100.0%** (36 / 36) | **47.2%** (17 / 36) | **Presidio falsely blocks 52.8% of legitimate prompts** |

---

## 4. Contextual Hard-Negative Failure Analysis

To evaluate whether pattern-based recognizers comprehend semantic context, the `TEST` split includes 12 paired benign prompts containing homonyms (*Hyperion*, *Chimera*, *Cerberus*, *Talon*, *Sentinel-6*) in public domains:

| Prompt Text | Public Context | Gold Class | B0 Decision | B1 Decision | Contextual Failure? |
|---|---|---|---|---|---|
| *"Hyperion is a chaotic tumbling moon of Saturn characterized by an irregular spongy appearance."* | Astronomy | `benign` | ALLOW (Correct) | **BLOCK (False Alarm)** | **YES (B1 failed)** |
| *"In classical Greek mythology, the Chimera was a monstrous fire-breathing hybrid creature."* | Mythology | `benign` | ALLOW (Correct) | **BLOCK (False Alarm)** | **YES (B1 failed)** |
| *"A genetic chimera is a single organism composed of cells with more than one distinct genotype."* | Genetics | `benign` | ALLOW (Correct) | **BLOCK (False Alarm)** | **YES (B1 failed)** |
| *"The Northrop T-38 Talon is a twin-engine supersonic jet trainer utilized extensively by NASA."* | Aviation History | `benign` | ALLOW (Correct) | **BLOCK (False Alarm)** | **YES (B1 failed)** |
| *"The Sentinel-6 Michael Freilich satellite was launched in 2020 to measure sea level rise."* | Oceanography | `benign` | ALLOW (Correct) | **BLOCK (False Alarm)** | **YES (B1 failed)** |

- **B0 Hard-Negative FPR**: **0.0%** (0 / 12).
- **B1 Hard-Negative FPR**: **75.0%** (9 / 12).

---

## 5. Explicit Hypothesis Evaluation

### Hypothesis H1
> *Does organization-specific adaptation improve held-out organization-specific detection relative to the selected baselines at matched false-positive rate?*

- **Formal Conclusion**: **INCONCLUSIVE**
- **Evidence-Based Rationale**:
  - The executed baselines establish that rule-based systems face a severe dilemma: B0 achieves $0.00\%$ FPR but fails catastrophically on held-out organizational terms ($83.33\%$ FNR). B1 recovers recall ($93.18\%$) via broad patterns, but produces a prohibitive $52.78\%$ FPR on benign text and $75.00\%$ FPR on contextual hard negatives.
  - However, because conditions A0, A1, and A2 failed to execute locally due to missing runtime libraries (`llama_cpp`, `torch`) on host Python 3.14, no empirical curve at matched FPR between A0, A1, and A2 could be directly measured.
  - Therefore, strictly under empirical standards, H1 cannot be confirmed or rejected; it remains **INCONCLUSIVE**.

---

### Hypothesis H2
> *How close is local adapted detection to the cloud reference condition, and what latency/compute cost is incurred?*

- **Formal Conclusion**: **INCONCLUSIVE**
- **Evidence-Based Rationale**:
  - Condition B3 (Cloud LLM Reference) was unexecutable due to unconfigured API credentials, and conditions A1/A2 were unexecutable locally due to missing runtime libraries.
  - While local inference latency for heuristic and NLP detectors was established at $p_{50} = 0.011$ ms (B0) and $p_{50} = 13.94$ ms (B1) with a minimal peak memory footprint ($10.45$ MB), the comparative performance delta and compute cost against cloud LLMs cannot be asserted without live cloud and local SLM inference data.
  - Therefore, strictly under empirical standards, H2 remains **INCONCLUSIVE**.

---

## 6. Dataset Accounting & Verified Research Figures

### Dataset Accounting
- **Candidate Pool**: 500 candidate prompts were programmatically generated during initial synthesis.
- **Finalized Corpus**: **446 records** constitute the finalized research dataset after documented filtering (54 candidate variants were pruned to eliminate template redundancy and ensure absolute zero-leakage paraphrase family isolation across partitions).
- **Split Breakdown**:
  - `TRAIN`: **199 prompts**
  - `DEV`: **79 prompts**
  - `TEST`: **168 prompts** (all 168 prompts contain held-out unseen terminology groups)
  - **Total**: $199 + 79 + 168 = \mathbf{446}$ records.

### Generated Figure Artifacts
All figures are saved in [src/core/experiments/results/EXP-NOVA-20261005-001/figures/](file:///d:/antigravity/AEGIS/src/core/experiments/results/EXP-NOVA-20261005-001/figures/):
1. **Figure 1**: [figure1_f1_comparison.png](file:///d:/antigravity/AEGIS/src/core/experiments/results/EXP-NOVA-20261005-001/figures/figure1_f1_comparison.png) — Empirical F1 Comparison Across Evaluation Conditions ($N=168$). Unrun conditions (B2, B3, A0, A1, A2) explicitly marked "FAILED / UNAVAILABLE".
2. **Figure 2**: [figure2_recall_vs_fpr.png](file:///d:/antigravity/AEGIS/src/core/experiments/results/EXP-NOVA-20261005-001/figures/figure2_recall_vs_fpr.png) — Operating Trade-Off: Detection Recall vs. False-Positive Rate in ROC space.
3. **Figure 3**: [figure3_performance_by_category.png](file:///d:/antigravity/AEGIS/src/core/experiments/results/EXP-NOVA-20261005-001/figures/figure3_performance_by_category.png) — Performance by Detection Category (Failure Modes Across Categories on Held-Out TEST Split, $N=168$). Note: All 168 TEST records are partition-level UNSEEN; this chart presents category-level performance rather than a split-based seen-vs-unseen experiment.
4. **Figure 4**: [figure4_latency_vs_f1.png](file:///d:/antigravity/AEGIS/src/core/experiments/results/EXP-NOVA-20261005-001/figures/figure4_latency_vs_f1.png) — Detection Efficacy vs. $p_{95}$ Local Inference Latency (with cloud reference envelope noted as illustrative).
5. **Figure 5**: [figure5_per_class_breakdown.png](file:///d:/antigravity/AEGIS/src/core/experiments/results/EXP-NOVA-20261005-001/figures/figure5_per_class_breakdown.png) — Per-Category Detection Efficacy Across Enterprise Information Types.
