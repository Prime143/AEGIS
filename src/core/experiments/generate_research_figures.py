"""
AEGIS: AI-Enabled Governance & Information Security
Statistical Analysis and Publication-Ready Research Figures Generator

Locked Research Question:
"How much does organization-specific adaptation improve sensitive-information detection
 in employee–AI prompts, and what does it cost to keep that detection local?"

Unique Experiment ID: EXP-NOVA-20261005-001
"""

import os
import json
import csv
import math
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
# Scipy optional / manual exact calculation used to ensure zero external scipy dependency issues

# Output Directories
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
EXP_ID = "EXP-NOVA-20261005-001"
RESULTS_DIR = os.path.join(BASE_DIR, "results", EXP_ID)
FIGURES_DIR = os.path.join(RESULTS_DIR, "figures")
os.makedirs(FIGURES_DIR, exist_ok=True)

# Load Experiment Data
with open(os.path.join(RESULTS_DIR, "predictions.json"), "r", encoding="utf-8") as f:
    predictions = json.load(f)

with open(os.path.join(RESULTS_DIR, "metrics.json"), "r", encoding="utf-8") as f:
    metrics = json.load(f)

with open(os.path.join(RESULTS_DIR, "latencies.json"), "r", encoding="utf-8") as f:
    latencies = json.load(f)

b0_preds = predictions["B0"]
b1_preds = predictions["B1"]
n_total = len(b0_preds)

print(f"Loaded {n_total} TEST sample predictions for B0 and B1.")

# =========================================================================
# 1. PAIRED STATISTICAL COMPARISON (McNemar's Test & Paired Bootstrap)
# =========================================================================

# For each sample, evaluate correctness
# Correctness: (pred == isGoldSensitive)
b0_correct = [p["predSensitive"] == p["isGoldSensitive"] for p in b0_preds]
b1_correct = [p["predSensitive"] == p["isGoldSensitive"] for p in b1_preds]

n11 = sum(1 for c0, c1 in zip(b0_correct, b1_correct) if c0 and c1)       # Both correct
n10 = sum(1 for c0, c1 in zip(b0_correct, b1_correct) if c0 and not c1)   # B0 correct, B1 wrong
n01 = sum(1 for c0, c1 in zip(b0_correct, b1_correct) if not c0 and c1)   # B0 wrong, B1 correct
n00 = sum(1 for c0, c1 in zip(b0_correct, b1_correct) if not c0 and not c1) # Both wrong

print(f"\n--- PAIRED CONTINGENCY TABLE (N = {n_total}) ---")
print(f"Both Correct (n11): {n11}")
print(f"B0 Correct, B1 Wrong (n10): {n10}")
print(f"B0 Wrong, B1 Correct (n01): {n01}")
print(f"Both Wrong (n00): {n00}")

# McNemar's Chi-squared with Edwards continuity correction:
# chi2 = (|n01 - n10| - 1)^2 / (n01 + n10)
discordant = n01 + n10
mcnemar_chi2 = ((abs(n01 - n10) - 1.0) ** 2) / discordant if discordant > 0 else 0.0

# Approximate p-value from chi2 with 1 df using survival function:
# P(X >= x) = 2 * (1 - Phi(sqrt(x)))
z_score = math.sqrt(mcnemar_chi2) if mcnemar_chi2 > 0 else 0.0
# Standard normal error function approximation
mcnemar_p = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(z_score / math.sqrt(2.0))))

# Effect size: Cohen's g for paired proportions
# g = (n01 / (n01 + n10)) - 0.5
cohens_g = (n01 / discordant) - 0.5 if discordant > 0 else 0.0
odds_ratio = (n01 / n10) if n10 > 0 else float("inf")

# Paired Bootstrap on F1 Difference (B1 - B0)
np.random.seed(42)
b_samples = 1000
delta_f1_list = []

for _ in range(b_samples):
    boot_indices = np.random.choice(n_total, size=n_total, replace=True)
    # B0 PRF1
    b0_tp = sum(1 for i in boot_indices if b0_preds[i]["isGoldSensitive"] and b0_preds[i]["predSensitive"])
    b0_fp = sum(1 for i in boot_indices if not b0_preds[i]["isGoldSensitive"] and b0_preds[i]["predSensitive"])
    b0_fn = sum(1 for i in boot_indices if b0_preds[i]["isGoldSensitive"] and not b0_preds[i]["predSensitive"])
    p0 = b0_tp / (b0_tp + b0_fp) if (b0_tp + b0_fp) > 0 else 0.0
    r0 = b0_tp / (b0_tp + b0_fn) if (b0_tp + b0_fn) > 0 else 0.0
    f1_0 = (2 * p0 * r0) / (p0 + r0) if (p0 + r0) > 0 else 0.0

    # B1 PRF1
    b1_tp = sum(1 for i in boot_indices if b1_preds[i]["isGoldSensitive"] and b1_preds[i]["predSensitive"])
    b1_fp = sum(1 for i in boot_indices if not b1_preds[i]["isGoldSensitive"] and b1_preds[i]["predSensitive"])
    b1_fn = sum(1 for i in boot_indices if b1_preds[i]["isGoldSensitive"] and not b1_preds[i]["predSensitive"])
    p1 = b1_tp / (b1_tp + b1_fp) if (b1_tp + b1_fp) > 0 else 0.0
    r1 = b1_tp / (b1_tp + b1_fn) if (b1_tp + b1_fn) > 0 else 0.0
    f1_1 = (2 * p1 * r1) / (p1 + r1) if (p1 + r1) > 0 else 0.0

    delta_f1_list.append(f1_1 - f1_0)

delta_f1_sorted = sorted(delta_f1_list)
delta_f1_mean = float(np.mean(delta_f1_list))
delta_f1_ci_lower = float(delta_f1_sorted[int(b_samples * 0.025)])
delta_f1_ci_upper = float(delta_f1_sorted[int(b_samples * 0.975)])

print(f"\nMcNemar Chi2: {mcnemar_chi2:.4f}, p-value: {mcnemar_p:.4e}")
print(f"Cohen's g effect size: {cohens_g:.4f} (Large effect if |g| > 0.25)")
print(f"Paired Delta F1 (B1 - B0): {delta_f1_mean:.4f} (95% CI: [{delta_f1_ci_lower:.4f}, {delta_f1_ci_upper:.4f}])")

# Statistical test dictionary
paired_test_results = {
    "test_name": "McNemar's Test with Edwards Continuity Correction",
    "contingency_table": {
        "both_correct_n11": n11,
        "b0_correct_b1_wrong_n10": n10,
        "b0_wrong_b1_correct_n01": n01,
        "both_wrong_n00": n00,
        "total_discordant": discordant
    },
    "mcnemar_chi2": round(mcnemar_chi2, 4),
    "p_value": float(f"{mcnemar_p:.4e}"),
    "statistically_significant_at_alpha_0_01": mcnemar_p < 0.01,
    "cohens_g_effect_size": round(cohens_g, 4),
    "odds_ratio": round(odds_ratio, 4),
    "paired_delta_f1": {
        "mean": round(delta_f1_mean, 4),
        "ci_95_lower": round(delta_f1_ci_lower, 4),
        "ci_95_upper": round(delta_f1_ci_upper, 4),
        "excludes_zero": delta_f1_ci_lower > 0.0
    }
}

# =========================================================================
# 2. SCIENTIFIC VISUALIZATION PALETTE & SETTINGS
# =========================================================================

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Segoe UI", "DejaVu Sans", "Helvetica", "Arial"],
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.titleweight": "bold",
    "axes.labelsize": 11,
    "axes.labelweight": "medium",
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 10,
    "figure.titlesize": 14,
    "figure.titleweight": "bold",
    "figure.autolayout": True,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.35,
    "grid.linestyle": "--",
})

# Color Constants
C_NAVY = "#0F172A"
C_SLATE = "#334155"
C_BLUE = "#0284C7"
C_TEAL = "#0D9488"
C_AMBER = "#D97706"
C_RED = "#DC2626"
C_GRAY = "#94A3B8"
C_LIGHT_GRAY = "#E2E8F0"

# =========================================================================
# FIGURE 1: F1 Comparison Across All 7 Conditions (B0, B1, B2, B3, A0, A1, A2)
# =========================================================================
fig, ax = plt.subplots(figsize=(10, 5.5))

conditions = ["B0\nRegex+Dict", "B1\nPresidio", "B2\nOpenAI Priv.", "B3\nCloud LLM", "A0\nGeneric SLM", "A1\nAdapted SLM", "A2\nFine-Tuned"]
f1_scores = [0.2857, 0.8978, 0.0, 0.0, 0.0, 0.0, 0.0]
ci_lowers = [0.1871, 0.8582, 0.0, 0.0, 0.0, 0.0, 0.0]
ci_uppers = [0.3774, 0.9339, 0.0, 0.0, 0.0, 0.0, 0.0]
statuses = ["EXECUTED", "EXECUTED", "UNAVAILABLE", "UNAVAILABLE", "UNAVAILABLE", "UNAVAILABLE", "UNAVAILABLE"]

yerr_lower = [f1 - low if f1 > 0 else 0 for f1, low in zip(f1_scores, ci_lowers)]
yerr_upper = [up - f1 if f1 > 0 else 0 for f1, up in zip(f1_scores, ci_uppers)]

bar_colors = [C_BLUE, C_TEAL, C_LIGHT_GRAY, C_LIGHT_GRAY, C_LIGHT_GRAY, C_LIGHT_GRAY, C_LIGHT_GRAY]
edge_colors = [C_SLATE, C_SLATE, C_GRAY, C_GRAY, C_GRAY, C_GRAY, C_GRAY]
hatches = ["", "", "//", "//", "//", "//", "//"]

bars = ax.bar(conditions, f1_scores, yerr=[yerr_lower, yerr_upper], capsize=5,
              color=bar_colors, edgecolor=edge_colors, hatch=hatches, width=0.6, linewidth=1.5,
              error_kw={"elinewidth": 1.5, "capthick": 1.5, "ecolor": C_NAVY})

# Value annotations
for i, (b, f1, st) in enumerate(zip(bars, f1_scores, statuses)):
    if st == "EXECUTED":
        ax.text(b.get_x() + b.get_width()/2, f1 + yerr_upper[i] + 0.03, f"F1 = {f1:.3f}\n[95% CI]",
                ha="center", va="bottom", fontsize=9.5, fontweight="bold", color=C_NAVY)
    else:
        ax.text(b.get_x() + b.get_width()/2, 0.05, "FAILED /\nUNAVAILABLE",
                ha="center", va="bottom", fontsize=8.5, color=C_RED, fontweight="bold", rotation=0)

ax.set_ylim(0, 1.15)
ax.set_ylabel("F1 Score (Binary Detection)")
ax.set_title("FIGURE 1: Empirical F1 Comparison Across Evaluation Conditions\n(NOVA Systems Held-Out TEST Split, N = 168 Prompts)", pad=15)

# Custom legend
from matplotlib.patches import Patch
legend_elements = [
    Patch(facecolor=C_BLUE, edgecolor=C_SLATE, label="B0: Regex + Dictionary Baseline (Executed)"),
    Patch(facecolor=C_TEAL, edgecolor=C_SLATE, label="B1: Microsoft Presidio Baseline (Executed)"),
    Patch(facecolor=C_LIGHT_GRAY, edgecolor=C_GRAY, hatch="//", label="Unrun Conditions (Runtime / Credentials Unavailable)"),
]
ax.legend(handles=legend_elements, loc="upper right", framealpha=0.9)

fig1_path_png = os.path.join(FIGURES_DIR, "figure1_f1_comparison.png")
fig1_path_svg = os.path.join(FIGURES_DIR, "figure1_f1_comparison.svg")
fig.savefig(fig1_path_png, dpi=300)
fig.savefig(fig1_path_svg)
plt.close(fig)
print(f"Saved: {fig1_path_png}")

# =========================================================================
# FIGURE 2: Recall versus False-Positive Rate (ROC Space)
# =========================================================================
fig, ax = plt.subplots(figsize=(8, 6.5))

# Diagonal random baseline
ax.plot([0, 1], [0, 1], linestyle=":", color=C_GRAY, linewidth=1.5, label="Random Guess Line (AUC = 0.50)")

# Plot B0 and B1
# B0: FPR = 0.00, Recall = 0.1667
# B1: FPR = 0.5278, Recall = 0.9318
ax.scatter([0.00], [0.1667], color=C_BLUE, s=180, edgecolors=C_NAVY, linewidth=2, zorder=5, label="B0: Regex + Dictionary (FPR = 0.0%, Rec = 16.7%)")
ax.scatter([0.5278], [0.9318], color=C_TEAL, s=180, edgecolors=C_NAVY, linewidth=2, zorder=5, label="B1: Presidio (FPR = 52.8%, Rec = 93.2%)")

# Ideal operating point
ax.scatter([0.0], [1.0], marker="*", color="#16A34A", s=250, edgecolors=C_NAVY, linewidth=1.5, zorder=5, label="Ideal Perimeter Gate (FPR = 0%, Rec = 100%)")

# Annotations
ax.annotate("B0: Zero False Positives,\nCatastrophic Under-detection\n(FNR = 83.3%)",
            xy=(0.00, 0.1667), xytext=(0.08, 0.28),
            arrowprops=dict(arrowstyle="->", color=C_BLUE, lw=1.5),
            bbox=dict(boxstyle="round,pad=0.4", fc="#EFF6FF", ec=C_BLUE, lw=1),
            fontsize=9.5)

ax.annotate("B1: High Recall, Extreme Alert Fatigue\n(FPR = 52.8%, Hard-Negative FPR = 75.0%)",
            xy=(0.5278, 0.9318), xytext=(0.28, 0.78),
            arrowprops=dict(arrowstyle="->", color=C_TEAL, lw=1.5),
            bbox=dict(boxstyle="round,pad=0.4", fc="#F0FDFA", ec=C_TEAL, lw=1),
            fontsize=9.5)

ax.set_xlim(-0.05, 1.05)
ax.set_ylim(-0.05, 1.05)
ax.set_xlabel("False Positive Rate (FPR = FP / (FP + TN))")
ax.set_ylabel("Detection Recall (True Positive Rate = TP / (TP + FN))")
ax.set_title("FIGURE 2: Operating Trade-Off: Detection Recall vs. False-Positive Rate\n(NOVA Systems TEST Split, N = 168 Prompts)", pad=15)
ax.legend(loc="lower right", framealpha=0.95)

fig2_path_png = os.path.join(FIGURES_DIR, "figure2_recall_vs_fpr.png")
fig2_path_svg = os.path.join(FIGURES_DIR, "figure2_recall_vs_fpr.svg")
fig.savefig(fig2_path_png, dpi=300)
fig.savefig(fig2_path_svg)
plt.close(fig)
print(f"Saved: {fig2_path_png}")

# =========================================================================
# FIGURE 3: Performance by Detection Category
# =========================================================================
fig, ax = plt.subplots(figsize=(9, 5.5))

categories = ["PII\n(N=12)", "Secrets\n(N=25)", "Internal Identifiers\n(N=41)", "Confidential Tech/Fin\n(N=54)", "Hard Negatives\n(N=12)", "Benign Specificity\n(N=36)"]
x = np.arange(len(categories))
width = 0.35

# B0 recalls / rates
b0_rates = [0.50, 0.64, 0.00, 0.00, 0.00, 1.00]
# B1 recalls / rates
b1_rates = [1.00, 0.92, 0.976, 0.889, 0.75, 0.472]

rects1 = ax.bar(x - width/2, b0_rates, width, label="B0: Regex + Dictionary", color=C_BLUE, edgecolor=C_NAVY)
rects2 = ax.bar(x + width/2, b1_rates, width, label="B1: Microsoft Presidio", color=C_TEAL, edgecolor=C_NAVY)

# Add values above bars
for r in rects1:
    h = r.get_height()
    ax.annotate(f"{h:.1%}", xy=(r.get_x() + r.get_width() / 2, h),
                xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8.5, fontweight="bold")
for r in rects2:
    h = r.get_height()
    ax.annotate(f"{h:.1%}", xy=(r.get_x() + r.get_width() / 2, h),
                xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8.5, fontweight="bold")

ax.set_ylabel("Detection Recall / Rate (0.0 - 1.0)")
ax.set_title("FIGURE 3: Performance by Detection Category\n(Failure Modes Across Sensitive-Information Categories on Held-Out TEST Split, N = 168)", pad=15)
ax.set_xticks(x)
ax.set_xticklabels(categories)
ax.set_ylim(0, 1.18)
ax.axhline(0, color="black", linewidth=0.8)
ax.legend(loc="upper center", bbox_to_anchor=(0.5, 0.98), ncol=2, framealpha=0.95)

fig3_path_png = os.path.join(FIGURES_DIR, "figure3_performance_by_category.png")
fig3_path_svg = os.path.join(FIGURES_DIR, "figure3_performance_by_category.svg")
fig.savefig(fig3_path_png, dpi=300)
fig.savefig(fig3_path_svg)
# Also save with legacy filename for existing link compatibility
fig.savefig(os.path.join(FIGURES_DIR, "figure3_seen_vs_unseen.png"), dpi=300)
fig.savefig(os.path.join(FIGURES_DIR, "figure3_seen_vs_unseen.svg"))
plt.close(fig)
print(f"Saved: {fig3_path_png}")

# =========================================================================
# FIGURE 4: F1 vs. p95 Inference Latency (Local vs. Cloud)
# =========================================================================
fig, ax = plt.subplots(figsize=(9, 6))

# B0: F1 = 0.2857, p95 = 0.028 ms
# B1: F1 = 0.8978, p95 = 23.81 ms
ax.scatter([0.028], [0.2857], color=C_BLUE, s=220, edgecolors=C_NAVY, linewidth=2, zorder=5, label="B0: Regex + Dict (p95 = 0.028 ms, F1 = 0.286)")
ax.scatter([23.81], [0.8978], color=C_TEAL, s=220, edgecolors=C_NAVY, linewidth=2, zorder=5, label="B1: Presidio Analyzer (p95 = 23.81 ms, F1 = 0.898)")

# Cloud Reference region (illustrative operational band)
ax.axvspan(200, 800, color=C_AMBER, alpha=0.15, label="Cloud LLM Reference Latency Envelope (Typical WAN Round-Trip: 200-800 ms)")
ax.axvline(200, color=C_AMBER, linestyle="--", linewidth=1.2)
ax.axvline(800, color=C_AMBER, linestyle="--", linewidth=1.2)

ax.set_xscale("log")
ax.set_xlim(0.005, 2000)
ax.set_ylim(0.1, 1.05)
ax.set_xlabel("p95 Latency (milliseconds, Log Scale)")
ax.set_ylabel("F1 Score on Held-Out Prompts")
ax.set_title("FIGURE 4: Detection Efficacy vs. p95 Local Inference Latency\n(Showing Local Sub-Millisecond Speed vs. Pipeline Memory Overhead)", pad=15)

# Annotations
ax.annotate("B0: In-Memory Microsecond Gate\n(0.028 ms, 1.0 MB Heap)",
            xy=(0.028, 0.2857), xytext=(0.007, 0.45),
            arrowprops=dict(arrowstyle="->", color=C_BLUE, lw=1.5),
            bbox=dict(boxstyle="round,pad=0.4", fc="#EFF6FF", ec=C_BLUE, lw=1),
            fontsize=9)

ax.annotate("B1: Multi-Recognizer Pipeline\n(23.81 ms, 10.5 MB Peak RAM)",
            xy=(23.81, 0.8978), xytext=(1.5, 0.95),
            arrowprops=dict(arrowstyle="->", color=C_TEAL, lw=1.5),
            bbox=dict(boxstyle="round,pad=0.4", fc="#F0FDFA", ec=C_TEAL, lw=1),
            fontsize=9)

ax.text(400, 0.55, "Cloud LLM (B3)\n[Unconfigured in .env]\nNetwork Overhead Incurred",
        ha="center", va="center", color=C_AMBER, fontweight="bold", fontsize=9.5,
        bbox=dict(boxstyle="round,pad=0.4", fc="#FEF3C7", ec=C_AMBER, lw=1))

ax.legend(loc="lower right", framealpha=0.95)

fig4_path_png = os.path.join(FIGURES_DIR, "figure4_latency_vs_f1.png")
fig4_path_svg = os.path.join(FIGURES_DIR, "figure4_latency_vs_f1.svg")
fig.savefig(fig4_path_png, dpi=300)
fig.savefig(fig4_path_svg)
plt.close(fig)
print(f"Saved: {fig4_path_png}")

# =========================================================================
# FIGURE 5: Per-Class Performance Breakdown
# =========================================================================
fig, ax = plt.subplots(figsize=(10, 5.5))

classes = ["PII", "Secrets", "Internal Identifiers", "Confidential Tech/Fin", "Benign"]
b0_vals = [50.0, 64.0, 0.0, 0.0, 100.0]
b1_vals = [100.0, 92.0, 97.6, 88.9, 47.2]
supports = [12, 25, 41, 54, 36]

x = np.arange(len(classes))
width = 0.35

rects1 = ax.bar(x - width/2, b0_vals, width, label="B0: Regex + Dict", color=C_BLUE, edgecolor=C_NAVY)
rects2 = ax.bar(x + width/2, b1_vals, width, label="B1: Presidio Analyzer", color=C_TEAL, edgecolor=C_NAVY)

# Labels
for r, s in zip(rects1, supports):
    h = r.get_height()
    ax.annotate(f"{h:.1f}%", xy=(r.get_x() + r.get_width() / 2, h),
                xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8.5, fontweight="bold")

for r, s in zip(rects2, supports):
    h = r.get_height()
    ax.annotate(f"{h:.1f}%", xy=(r.get_x() + r.get_width() / 2, h),
                xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8.5, fontweight="bold")

ax.set_ylabel("Per-Class Metric (% Recall for Sensitive, % Specificity for Benign)")
ax.set_title("FIGURE 5: Per-Category Detection Efficacy Across Enterprise Information Types\n(Held-Out TEST Partition, N = 168 Total Prompts)", pad=15)
ax.set_xticks(x)
ax.set_xticklabels([f"{c}\n(N={s})" for c, s in zip(classes, supports)])
ax.set_ylim(0, 118)
ax.legend(loc="upper right", framealpha=0.95)

fig5_path_png = os.path.join(FIGURES_DIR, "figure5_per_class_breakdown.png")
fig5_path_svg = os.path.join(FIGURES_DIR, "figure5_per_class_breakdown.svg")
fig.savefig(fig5_path_png, dpi=300)
fig.savefig(fig5_path_svg)
plt.close(fig)
print(f"Saved: {fig5_path_png}")

# =========================================================================
# 3. EXPORT RESULTS SUMMARY JSON & CSV
# =========================================================================

summary_table = [
    {
        "Condition": "B0",
        "Name": "Regex + Dictionary Baseline",
        "Status": "EXECUTED",
        "Evaluated_N": 168,
        "Precision": 1.0000,
        "Precision_95CI": "[1.0000, 1.0000]",
        "Recall": 0.1667,
        "Recall_95CI": "[0.1032, 0.2326]",
        "F1_Score": 0.2857,
        "F1_95CI": "[0.1871, 0.3774]",
        "FPR": 0.0000,
        "FNR": 0.8333,
        "HardNegative_FPR": 0.0000,
        "Latency_p50_ms": 0.011,
        "Latency_p95_ms": 0.028,
        "Memory_Peak_MB": 1.05,
    },
    {
        "Condition": "B1",
        "Name": "Microsoft Presidio (Custom Recognizers)",
        "Status": "EXECUTED",
        "Evaluated_N": 168,
        "Precision": 0.8662,
        "Precision_95CI": "[0.8138, 0.9197]",
        "Recall": 0.9318,
        "Recall_95CI": "[0.8819, 0.9718]",
        "F1_Score": 0.8978,
        "F1_95CI": "[0.8582, 0.9339]",
        "FPR": 0.5278,
        "FNR": 0.0682,
        "HardNegative_FPR": 0.7500,
        "Latency_p50_ms": 13.94,
        "Latency_p95_ms": 23.81,
        "Memory_Peak_MB": 10.45,
    },
    {
        "Condition": "B2",
        "Name": "OpenAI Privacy Filter",
        "Status": "FAILED / UNAVAILABLE",
        "Evaluated_N": 0,
        "Precision": "N/A",
        "Precision_95CI": "N/A",
        "Recall": "N/A",
        "Recall_95CI": "N/A",
        "F1_Score": "N/A",
        "F1_95CI": "N/A",
        "FPR": "N/A",
        "FNR": "N/A",
        "HardNegative_FPR": "N/A",
        "Latency_p50_ms": "N/A",
        "Latency_p95_ms": "N/A",
        "Memory_Peak_MB": "N/A",
    },
    {
        "Condition": "B3",
        "Name": "Cloud LLM Reference (Gemini 2.5 Flash)",
        "Status": "FAILED / UNAVAILABLE",
        "Evaluated_N": 0,
        "Precision": "N/A",
        "Precision_95CI": "N/A",
        "Recall": "N/A",
        "Recall_95CI": "N/A",
        "F1_Score": "N/A",
        "F1_95CI": "N/A",
        "FPR": "N/A",
        "FNR": "N/A",
        "HardNegative_FPR": "N/A",
        "Latency_p50_ms": "N/A",
        "Latency_p95_ms": "N/A",
        "Memory_Peak_MB": "N/A",
    },
    {
        "Condition": "A0",
        "Name": "Local Generic SLM (Llama-3.2-1B-Instruct)",
        "Status": "FAILED / UNAVAILABLE",
        "Evaluated_N": 0,
        "Precision": "N/A",
        "Precision_95CI": "N/A",
        "Recall": "N/A",
        "Recall_95CI": "N/A",
        "F1_Score": "N/A",
        "F1_95CI": "N/A",
        "FPR": "N/A",
        "FNR": "N/A",
        "HardNegative_FPR": "N/A",
        "Latency_p50_ms": "N/A",
        "Latency_p95_ms": "N/A",
        "Memory_Peak_MB": "N/A",
    },
    {
        "Condition": "A1",
        "Name": "Local In-Context Adapted SLM",
        "Status": "FAILED / UNAVAILABLE",
        "Evaluated_N": 0,
        "Precision": "N/A",
        "Precision_95CI": "N/A",
        "Recall": "N/A",
        "Recall_95CI": "N/A",
        "F1_Score": "N/A",
        "F1_95CI": "N/A",
        "FPR": "N/A",
        "FNR": "N/A",
        "HardNegative_FPR": "N/A",
        "Latency_p50_ms": "N/A",
        "Latency_p95_ms": "N/A",
        "Memory_Peak_MB": "N/A",
    },
    {
        "Condition": "A2",
        "Name": "Local Fine-Tuned SLM (QLoRA)",
        "Status": "FAILED / UNAVAILABLE",
        "Evaluated_N": 0,
        "Precision": "N/A",
        "Precision_95CI": "N/A",
        "Recall": "N/A",
        "Recall_95CI": "N/A",
        "F1_Score": "N/A",
        "F1_95CI": "N/A",
        "FPR": "N/A",
        "FNR": "N/A",
        "HardNegative_FPR": "N/A",
        "Latency_p50_ms": "N/A",
        "Latency_p95_ms": "N/A",
        "Memory_Peak_MB": "N/A",
    },
]

# Write results_summary.json
json_summary_path = os.path.join(RESULTS_DIR, "results_summary.json")
with open(json_summary_path, "w", encoding="utf-8") as f:
    json.dump({
        "experiment_id": EXP_ID,
        "dataset_split": "TEST",
        "total_test_samples": 168,
        "paired_test_b0_vs_b1": paired_test_results,
        "conditions": summary_table
    }, f, indent=2)
print(f"Saved: {json_summary_path}")

# Write results_summary.csv
csv_summary_path = os.path.join(RESULTS_DIR, "results_summary.csv")
with open(csv_summary_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=summary_table[0].keys())
    writer.writeheader()
    writer.writerows(summary_table)
print(f"Saved: {csv_summary_path}")

# Also write to root directory for immediate visibility
root_json = os.path.join(os.path.abspath(os.path.join(BASE_DIR, "..", "..", "..")), "results_summary.json")
root_csv = os.path.join(os.path.abspath(os.path.join(BASE_DIR, "..", "..", "..")), "results_summary.csv")
with open(root_json, "w", encoding="utf-8") as f:
    json.dump({
        "experiment_id": EXP_ID,
        "dataset_split": "TEST",
        "paired_test_b0_vs_b1": paired_test_results,
        "conditions": summary_table
    }, f, indent=2)
with open(root_csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=summary_table[0].keys())
    writer.writeheader()
    writer.writerows(summary_table)

print("\n--- STATISTICAL ANALYSIS & FIGURE GENERATION COMPLETE ---")
