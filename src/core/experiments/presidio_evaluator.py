"""
AEGIS: AI-Enabled Governance & Information Security
Baseline B1: Microsoft Presidio Evaluator with Custom Recognizers

Locked Research Question:
"How much does organization-specific adaptation improve sensitive-information detection
 in employee–AI prompts, and what does it cost to keep that detection local?"
"""

import sys
import json
import time
import os
import tracemalloc
from typing import Dict, Any, List, Tuple

try:
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
    from presidio_analyzer.nlp_engine import NlpEngineProvider
except ImportError as e:
    print(json.dumps({"error": f"Presidio import failed: {str(e)}"}))
    sys.exit(1)


def create_presidio_analyzer() -> AnalyzerEngine:
    """Configures Presidio AnalyzerEngine with en_core_web_sm and custom recognizers."""
    configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }
    provider = NlpEngineProvider(nlp_configuration=configuration)
    nlp_engine = provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])

    # Register custom pattern recognizers for B1 baseline
    # 1. API Keys & Secrets
    secret_patterns = [
        Pattern(name="nova_api_key", regex=r"nova_sec_[a-zA-Z0-9_]{16,}", score=0.95),
        Pattern(name="github_pat", regex=r"gh[pousr]_[a-zA-Z0-9_]{20,}", score=0.95),
        Pattern(name="aws_key", regex=r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", score=0.95),
        Pattern(name="jwt_token", regex=r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", score=0.95),
        Pattern(name="db_uri", regex=r"(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql):\/\/[^\s]+", score=0.95),
    ]
    analyzer.registry.add_recognizer(
        PatternRecognizer(supported_entity="SECRETS_CREDENTIAL", patterns=secret_patterns, supported_language="en")
    )

    # 2. Internal Infrastructure Identifiers
    infra_patterns = [
        Pattern(name="jira_keys", regex=r"\bNOVA-(?:ENG|SEC|AERO|SWARM|PAYLOAD|OPTICS|DIR)-\d{4,}\b", score=0.90),
        Pattern(name="internal_fqdn", regex=r"\b[a-zA-Z0-9.-]+\.(?:internal|mgmt|prod|tactical)\.novasystems\.net\b", score=0.90),
        Pattern(name="internal_repo", regex=r"\bnovasys-(?:core|sec|avionics|swarm|optics|payload|edge)\/[a-zA-Z0-9_-]+\b", score=0.85),
    ]
    analyzer.registry.add_recognizer(
        PatternRecognizer(supported_entity="INTERNAL_IDENTIFIER", patterns=infra_patterns, supported_language="en")
    )

    # 3. Known Seen Organizational Glossary Codenames (Custom recognizers)
    glossary_patterns = [
        Pattern(name="proj_aurora", regex=r"\b(?:Project Aurora|Aurora-V)\b", score=0.85),
        Pattern(name="proj_valkyrie", regex=r"\bValkyrie-X\b", score=0.85),
        Pattern(name="proj_zephyr", regex=r"\bZephyr-OS\b", score=0.85),
        Pattern(name="proj_apex", regex=r"\bProject Apex\b", score=0.85),
    ]
    analyzer.registry.add_recognizer(
        PatternRecognizer(supported_entity="ORG_CODENAME", patterns=glossary_patterns, supported_language="en")
    )

    return analyzer


def evaluate_split(split_name: str = "TEST", confidence_threshold: float = 0.40) -> Dict[str, Any]:
    dataset_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "datasets", "nova_systems", "nova_research_dataset.json")
    dataset_path = os.path.abspath(dataset_path)

    if not os.path.exists(dataset_path):
        return {"error": f"Dataset file not found at {dataset_path}"}

    with open(dataset_path, "r", encoding="utf-8") as f:
        all_records = json.load(f)

    split_records = [r for r in all_records if r.get("split") == split_name]
    if not split_records:
        return {"error": f"No records found for split {split_name}"}

    analyzer = create_presidio_analyzer()

    # Track metrics
    tp, fp, tn, fn = 0, 0, 0, 0
    seen_tp, seen_fp, seen_tn, seen_fn = 0, 0, 0, 0
    unseen_tp, unseen_fp, unseen_tn, unseen_fn = 0, 0, 0, 0
    hn_fp, hn_total = 0, 0

    class_stats = {
        "PII": {"tp": 0, "fn": 0, "support": 0},
        "secrets": {"tp": 0, "fn": 0, "support": 0},
        "internal identifiers": {"tp": 0, "fn": 0, "support": 0},
        "confidential technical/financial information": {"tp": 0, "fn": 0, "support": 0},
        "benign": {"tn": 0, "fp": 0, "support": 0},
    }

    latencies_ms: List[float] = []
    tracemalloc.start()
    start_time_all = time.perf_counter()

    predictions = []

    for rec in split_records:
        text = rec["text"]
        gold_class = rec["gold_class"]
        is_gold_sensitive = gold_class != "benign"
        is_seen = rec.get("seen_or_unseen") == "SEEN"
        is_hn = rec.get("hard_negative_group") is not None

        if gold_class in class_stats:
            class_stats[gold_class]["support"] += 1

        t0 = time.perf_counter_ns()
        results = analyzer.analyze(text=text, language="en")
        t1 = time.perf_counter_ns()
        latency_ms = (t1 - t0) / 1_000_000.0
        latencies_ms.append(latency_ms)

        # Filter by confidence threshold
        significant_findings = [r for r in results if r.score >= confidence_threshold]
        pred_sensitive = len(significant_findings) > 0

        # Classify detected category
        detected_types = [r.entity_type for r in significant_findings]
        
        predictions.append({
            "id": rec["id"],
            "pred_sensitive": pred_sensitive,
            "gold_class": gold_class,
            "detected_types": detected_types,
            "latency_ms": round(latency_ms, 3)
        })

        if is_gold_sensitive and pred_sensitive:
            tp += 1
            if is_seen: seen_tp += 1
            else: unseen_tp += 1
            if gold_class in class_stats:
                class_stats[gold_class]["tp"] += 1
        elif is_gold_sensitive and not pred_sensitive:
            fn += 1
            if is_seen: seen_fn += 1
            else: unseen_fn += 1
            if gold_class in class_stats:
                class_stats[gold_class]["fn"] += 1
        elif not is_gold_sensitive and not pred_sensitive:
            tn += 1
            if is_seen: seen_tn += 1
            else: unseen_tn += 1
            if gold_class in class_stats:
                class_stats[gold_class]["tn"] += 1
        elif not is_gold_sensitive and pred_sensitive:
            fp += 1
            if is_seen: seen_fp += 1
            else: unseen_fp += 1
            if gold_class in class_stats:
                class_stats[gold_class]["fp"] += 1

        # Check hard negative false positive specifically
        if not is_gold_sensitive and is_hn:
            hn_total += 1
            if pred_sensitive:
                hn_fp += 1

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    latencies_sorted = sorted(latencies_ms)
    p50_latency = latencies_sorted[int(len(latencies_sorted) * 0.50)] if latencies_sorted else 0.0
    p95_latency = latencies_sorted[int(len(latencies_sorted) * 0.95)] if latencies_sorted else 0.0
    mean_latency = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0

    def calc_p_r_f1(t_pos: int, f_pos: int, f_neg: int) -> Tuple[float, float, float]:
        p = t_pos / (t_pos + f_pos) if (t_pos + f_pos) > 0 else 0.0
        r = t_pos / (t_pos + f_neg) if (t_pos + f_neg) > 0 else 0.0
        f1 = (2 * p * r) / (p + r) if (p + r) > 0 else 0.0
        return round(p, 4), round(r, 4), round(f1, 4)

    precision, recall, f1 = calc_p_r_f1(tp, fp, fn)
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    fnr = round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0

    # Seen metrics
    seen_p, seen_r, seen_f1 = calc_p_r_f1(seen_tp, seen_fp, seen_fn)
    # Unseen metrics
    unseen_p, unseen_r, unseen_f1 = calc_p_r_f1(unseen_tp, unseen_fp, unseen_fn)

    # Hard negative FPR
    hn_fpr = round(hn_fp / hn_total, 4) if hn_total > 0 else 0.0

    # Per-class metrics
    per_class_results = {}
    for c_name, st in class_stats.items():
        if c_name == "benign":
            spec = round(st["tn"] / (st["tn"] + st["fp"]), 4) if (st["tn"] + st["fp"]) > 0 else 0.0
            per_class_results[c_name] = {
                "support": st["support"],
                "specificity": spec,
                "false_positives": st["fp"]
            }
        else:
            rec = round(st["tp"] / (st["tp"] + st["fn"]), 4) if (st["tp"] + st["fn"]) > 0 else 0.0
            per_class_results[c_name] = {
                "support": st["support"],
                "recall": rec,
                "false_negatives": st["fn"],
                "detected": st["tp"]
            }

    return {
        "condition_id": "B1",
        "condition_name": "Microsoft Presidio Baseline (with Custom Recognizers)",
        "dataset_split": split_name,
        "total_evaluated": len(split_records),
        "confusion_matrix": {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn
        },
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr
        },
        "seen_vs_unseen": {
            "seen": {"precision": seen_p, "recall": seen_r, "f1_score": seen_f1, "evaluated": seen_tp + seen_fp + seen_tn + seen_fn},
            "unseen": {"precision": unseen_p, "recall": unseen_r, "f1_score": unseen_f1, "evaluated": unseen_tp + unseen_fp + unseen_tn + unseen_fn},
            "delta_f1": round(seen_f1 - unseen_f1, 4)
        },
        "hard_negatives": {
            "evaluated": hn_total,
            "false_positives": hn_fp,
            "fpr": hn_fpr
        },
        "per_class": per_class_results,
        "latency_ms": {
            "p50": round(p50_latency, 2),
            "p95": round(p95_latency, 2),
            "mean": round(mean_latency, 2)
        },
        "memory": {
            "peak_mb": round(peak_mem / (1024 * 1024), 2),
            "current_mb": round(current_mem / (1024 * 1024), 2)
        },
        "predictions": predictions,
        "confidence_threshold": confidence_threshold,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }



if __name__ == "__main__":
    split = sys.argv[1] if len(sys.argv) > 1 else "TEST"
    conf = float(sys.argv[2]) if len(sys.argv) > 2 else 0.40
    res = evaluate_split(split, conf)
    print(json.dumps(res, indent=2))
