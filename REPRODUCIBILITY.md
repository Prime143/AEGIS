# Reproducibility Guide: AEGIS Benchmark

**Experiment Identifier**: `EXP-NOVA-20261005-001`  
**Git Commit**: `748ca9d60037d59f475fb135fd0035da45549a28`  
**Deterministic Random Seed**: `42`  

This document details the exact environment, dependencies, commands, and expected checksums to reproduce every table, metric, and figure in the AEGIS research package.

---

## 1. System Requirements & Environment

### Hardware Environment
- **Processor**: AMD Ryzen 5 7430U with Radeon Graphics (6 Cores, 12 Threads) or equivalent x86-64 / ARM64 CPU.
- **Memory**: Minimum 8 GB RAM (16 GB recommended).
- **Disk Space**: 500 MB free disk space.

### Software Environment
- **Operating System**: Windows 11 / Linux (Ubuntu 22.04+) / macOS.
- **Node.js**: v20.x or v24.x (`v24.18.0` used in benchmark).
- **Python**: 3.10+ (`Python 3.14.6` used in benchmark).

---

## 2. Step-by-Step Reproduction Instructions

### Step 1: Environment Setup
Ensure Node.js and Python are available on your system path:
```bash
node --version
python --version
```

### Step 2: Install Python Dependencies
Install Presidio Analyzer, spaCy, and Matplotlib:
```bash
python -m pip install presidio-analyzer matplotlib
python -m spacy download en_core_web_sm
```

### Step 3: Deterministic Dataset Generation
Regenerate the NOVA Systems research corpus ($N = 446$ prompts) using deterministic seed `42`:
```bash
npx tsx datasets/nova_systems/generate_nova_dataset.ts
```
*Verification*: Check that `datasets/nova_systems/nova_research_dataset.json` contains exactly 446 records (TRAIN: 199, DEV: 79, TEST: 168).

### Step 4: Execute Benchmark Suite
Run the formal controlled experiment across all conditions:
```bash
npx tsx src/core/experiments/run_controlled_benchmark.ts
```
*Verification*: Check that outputs are written to `src/core/experiments/results/EXP-NOVA-20261005-001/`.

### Step 5: Statistical Analysis & Figure Generation
Run the paired significance analysis and generate Figures 1–5:
```bash
python src/core/experiments/generate_research_figures.py
```
*Verification*: Confirm that PNG and SVG figures are written to `src/core/experiments/results/EXP-NOVA-20261005-001/figures/`.

---

## 3. Expected Metric Verifications

Reproduced runs must match the following benchmark values:

| Condition | Metric | Expected Target Value | Permissible Delta |
|---|---|---|---|
| **B0** | Evaluated Samples | `168` | Exact match |
| **B0** | Precision | `1.0000` | Exact match |
| **B0** | Recall | `0.1667` | $\pm 0.0005$ |
| **B0** | F1 Score | `0.2857` | $\pm 0.0005$ |
| **B0** | False Positive Rate | `0.0000` | Exact match |
| **B0** | Hard-Negative FPR | `0.0000` (0 / 12) | Exact match |
| **B1** | Precision | `0.8662` | $\pm 0.0010$ |
| **B1** | Recall | `0.9318` | $\pm 0.0010$ |
| **B1** | F1 Score | `0.8978` | $\pm 0.0010$ |
| **B1** | False Positive Rate | `0.5278` | $\pm 0.0010$ |
| **B1** | Hard-Negative FPR | `0.7500` (9 / 12) | Exact match |
| **Paired** | McNemar $\chi^2$ | `52.9113` | $\pm 0.05$ |
| **Paired** | McNemar $p$-value | $3.49 \times 10^{-13}$ | $p < 0.0001$ |
| **Paired** | Cohen's $g$ | `+0.3306` | $\pm 0.005$ |

---

## 4. Verification Checksums

To verify data file integrity, check line and byte counts:
- `datasets/nova_systems/nova_research_dataset.json`: 446 JSON records.
- `src/core/experiments/results/EXP-NOVA-20261005-001/predictions.json`: 3,366 lines.
- `src/core/experiments/results/EXP-NOVA-20261005-001/metrics.json`: 242 lines.
