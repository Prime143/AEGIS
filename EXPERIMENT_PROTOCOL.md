# Experiment Protocol: Controlled Perimeter Detector Benchmark

**Document Version**: 1.0.0  
**Experiment ID**: `EXP-NOVA-20261005-001`  
**Execution Timestamp**: `2026-10-05T12:58:31.268Z`  

---

## 1. Locked Research Question & Hypotheses

### Research Question
> *“How much does organization-specific adaptation improve sensitive-information detection in employee–AI prompts, and what does it cost to keep that detection local?”*

### Formal Hypotheses
- **Hypothesis H1**: Organization-specific adaptation improves held-out organization-specific detection relative to selected baselines at matched false-positive rate.
- **Hypothesis H2**: Local adapted detection approaches cloud reference performance within an operationally viable latency and compute cost envelope.

---

## 2. Experimental Corpus & Split Protocol

### Dataset Partitions
1. **`TRAIN` Split ($N = 199$)**:
   - Contains exclusively SEEN terminology (`Project Aurora`, `Valkyrie-X`, `Zephyr-OS`, `Project Apex`, seen cluster hostnames).
   - Used for dictionary compilation, few-shot demonstration selection, and fine-tuning.
2. **`DEV` Split ($N = 79$)**:
   - Contains SEEN terminology and general benign prompts.
   - **Strict Scope**: Calibrating decision thresholds ($\tau = 0.50$) and Presidio score confidence thresholds ($\tau = 0.40$).
3. **`TEST` Split ($N = 168$)**:
   - **Held-Out Evaluation Partition**: Contains strictly UNSEEN organizational entities (`Project Chimera`, `Project Hyperion`, `Project Cerberus`, `Project Talon`, `Sentinel-6`, and unseen tactical hosts) along with standard PII, standard credentials, and general benign prompts.
   - **Frozen Rule**: The `TEST` partition must never be inspected to tune parameters, alter thresholds, or adjust dictionary rules.

---

## 3. Evaluation Protocol Across Conditions

### Condition B0 (Regex + Dictionary Baseline)
- **Harness**: [ControlledExperimentRunner.ts](file:///d:/antigravity/AEGIS/src/core/experiments/ControlledExperimentRunner.ts#L48-L177)
- **Input**: Prompt text string + `NOVA_SYSTEMS_CONTEXT`.
- **Decision Logic**: If findings count $> 0 \implies \text{predSensitive} = \text{true}$; otherwise $\text{false}$.
- **Timing**: Measured per prompt using high-resolution monotonic timer (`performance.now()`).

### Condition B1 (Microsoft Presidio Baseline)
- **Harness**: [presidio_evaluator.py](file:///d:/antigravity/AEGIS/src/core/experiments/presidio_evaluator.py)
- **Input**: Prompt text string evaluated by Presidio `AnalyzerEngine` using spaCy `en_core_web_sm` and registered custom `PatternRecognizer`s.
- **Decision Logic**: Filter findings where $\text{score} \ge \tau_{\text{presidio}} = 0.40$. If filtered findings $> 0 \implies \text{predSensitive} = \text{true}$; otherwise $\text{false}$.
- **Timing**: Measured per prompt using `time.perf_counter_ns()`.

### Conditions B2, B3, A0, A1, A2
- **Protocol**: If interface credentials or runtime dependencies are missing, the condition must be formally audited, marked `STATUS = FAILED / UNAVAILABLE`, and recorded with the explicit root cause. Under no circumstances may simulated or invented values be recorded.

---

## 4. Metrics & Statistical Testing Protocol

### Primary Classification Metrics
$$\text{Precision} = \frac{TP}{TP + FP}, \quad \text{Recall} = \frac{TP}{TP + FN}, \quad F_1 = \frac{2 \cdot \text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$
$$\text{False Positive Rate (FPR)} = \frac{FP}{FP + TN}, \quad \text{False Negative Rate (FNR)} = \frac{FN}{FN + TP}$$

### Paired Significance Testing (McNemar’s Test)
Because all detectors evaluate the **identical 168 prompts in `TEST`**, independence assumptions underlying standard two-sample tests are violated. A paired McNemar test is required:
$$\chi^2 = \frac{(|n_{01} - n_{10}| - 1)^2}{n_{01} + n_{10}}$$
Where $n_{01}$ represents prompts where system 0 failed and system 1 succeeded, and $n_{10}$ represents prompts where system 0 succeeded and system 1 failed.

### Bootstrap Confidence Intervals
- **Method**: Non-parametric percentile bootstrap.
- **Resamples**: $B = 1000$ resamples of size $N = 168$ with replacement.
- **PRNG Seed**: `42`.
- **Interval**: 2.5th percentile (lower bound) to 97.5th percentile (upper bound).

### Latency Percentiles
- Measured per-prompt latency in milliseconds.
- Sorted array: $p_{50}$ (median) and $p_{95}$ (95th percentile).
