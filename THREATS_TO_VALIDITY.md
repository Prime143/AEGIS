# Threats to Validity: AEGIS Research Benchmark

This document analyzes the threats to validity for the AEGIS controlled benchmark (`EXP-NOVA-20261005-001`) structured according to the classic validity framework (Construct, Internal, External, and Statistical Conclusion Validity).

---

## 1. Construct Validity

*Does the operationalization of our benchmark accurately reflect the theoretical construct of enterprise sensitive-information detection?*

### Potential Threats & Mitigations
1. **Reliance on Binary Sensitivity Labels**:
   - *Threat*: In real operations, sensitivity is granular (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`), requiring nuanced policy actions (e.g., masking vs. blocking).
   - *Mitigation*: While binary detection ($y_i \in \{0, 1\}$) was used for standard $F_1$, FPR, and Recall reporting, each example in the corpus preserves its multi-tier sensitivity level and category for granular per-class evaluation.
2. **Contextual Homonym Operationalization**:
   - *Threat*: An artificial distribution of homonyms might distort real-world false-alarm rates.
   - *Mitigation*: The 25 hard-negative pairs were constructed using authentic homonym candidates (e.g., astronomy moons, mythological entities, biological terms, aviation aircraft) reflecting common aerospace naming conventions.

---

## 2. Internal Validity

*Are the observed performance differences attributable solely to the detector architectures rather than experimental artifacts or data leakage?*

### Potential Threats & Mitigations
1. **Terminology Leakage Between Splits**:
   - *Threat*: If unseen terms appeared in training or tuning, baseline performance would be artificially inflated.
   - *Mitigation*: Strict verification confirmed exactly 0 UNSEEN records in `TRAIN` or `DEV`. All zero-shot project codenames (`Chimera`, `Hyperion`, `Cerberus`, `Talon`, `Sentinel-6`) were held out exclusively in `TEST`.
2. **Template Leakage**:
   - *Threat*: If syntactic templates or paraphrase groups spanned splits, detectors might memorize sentence structures rather than detecting semantic content.
   - *Mitigation*: Paraphrase families were assigned atomically to a single partition.
3. **Threshold Overfitting**:
   - *Threat*: Tuning decision thresholds on `TEST` inflates reported metrics.
   - *Mitigation*: Thresholds ($\tau = 0.50$, Presidio $\tau = 0.40$) were calibrated strictly on `DEV` ($N = 79$) and frozen prior to `TEST` evaluation.

---

## 3. External Validity

*Can the findings generalize beyond this experimental setting to production enterprise AI gateways?*

### Potential Threats & Mitigations
1. **Synthetic Prompt Origin**:
   - *Threat*: Synthetic generation may exhibit less linguistic diversity, typos, or informal slang than real corporate chat streams.
   - *Mitigation*: Templates were drafted across diverse workplace archetypes (code debugging, onboarding, incident reports, technical inquiries). However, findings must be corroborated on sanitized real-world telemetry when enterprise privacy agreements permit.
2. **Single Enterprise Domain**:
   - *Threat*: Results reflect an aerospace and defense engineering context (NOVA Systems).
   - *Mitigation*: While specific entity names vary across industries, the architectural trade-off demonstrated—the collapse of static dictionaries on unseen projects and the contextual blindness of pattern recognizers—is domain-invariant.

---

## 4. Statistical Conclusion Validity

*Are the statistical tests, effect sizes, and confidence intervals mathematically sound and appropriate for the data distribution?*

### Potential Threats & Mitigations
1. **Violation of Sample Independence**:
   - *Threat*: Comparing B0 and B1 using two-sample t-tests or standard z-tests violates independence assumptions because both models evaluated the **exact same 168 test prompts**.
   - *Mitigation*: Evaluated strictly via **McNemar’s paired test with Edwards continuity correction** ($\chi^2 = 52.9113, p = 3.49 \times 10^{-13}$).
2. **Non-Normal Metric Distributions**:
   - *Threat*: Small sub-sample class metrics (e.g., $N = 12$ for PII, $N = 12$ for hard negatives) violate normality assumptions.
   - *Mitigation*: Metric intervals were computed via non-parametric percentile bootstrap resampling ($B = 1000$ resamples with replacement, Seed `42`).
3. **Over-Reliance on p-Values**:
   - *Threat*: Citing statistical significance without effect sizes obscures operational relevance.
   - *Mitigation*: Reported Cohen’s $g = +0.3306$ (indicating a large directional effect) and discordant odds ratio ($\text{OR} = 4.9048$) alongside $p$-values.
