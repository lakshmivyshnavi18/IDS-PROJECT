"""
testing/run_tests.py
─────────────────────────────────────────────────────────────────────────────
Safe testing framework for the LLM Security Monitor.

Tests run ONLY against our own local chatbot.
No real systems, services, or networks are targeted.

Usage:
  # Run all tests
  python testing/run_tests.py

  # Run only single-turn tests
  python testing/run_tests.py --mode single

  # Run only multi-turn tests
  python testing/run_tests.py --mode multi

  # Save results to file
  python testing/run_tests.py --save
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import time
import argparse
import requests
import numpy as np
from datetime import datetime
from typing import List, Dict, Tuple
from sklearn.metrics import (
    classification_report, confusion_matrix,
    f1_score, precision_score, recall_score
)

from config import API_BASE_URL

RESULTS_DIR = Path(__file__).parent.parent / "experiments" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

SCENARIO_DIR = Path(__file__).parent / "scenarios"

LABEL_TO_INT = {"NORMAL": 0, "SUSPICIOUS": 1, "HIGH_RISK": 2}
INT_TO_LABEL = {0: "NORMAL", 1: "SUSPICIOUS", 2: "HIGH_RISK"}


# ─────────────────────────────────────────────────────────────────────────────
# API Helpers
# ─────────────────────────────────────────────────────────────────────────────

def create_session() -> str:
    r = requests.post(f"{API_BASE_URL}/session/create", timeout=10)
    return r.json()["session_id"]


def send_message(session_id: str, message: str, true_label: str = None) -> Dict:
    payload = {
        "session_id": session_id,
        "message": message,
        "use_mock": False,
        "true_risk_label": true_label,
    }
    r = requests.post(f"{API_BASE_URL}/chat", json=payload, timeout=30)
    return r.json()


# ─────────────────────────────────────────────────────────────────────────────
# Single-Turn Tests
# ─────────────────────────────────────────────────────────────────────────────

def run_single_turn_tests() -> Dict:
    """
    Run all single-turn test scenarios.
    Each message gets its own fresh session to avoid cross-contamination.
    """
    print("\n" + "="*65)
    print("  SINGLE-TURN SECURITY TESTS")
    print("="*65)

    scenario_path = SCENARIO_DIR / "single_turn_scenarios.json"
    with open(scenario_path) as f:
        scenarios = json.load(f)

    all_true = []
    all_pred = []
    all_scores = []
    results = []
    latencies = []

    categories = list(scenarios.keys())
    for category in categories:
        tests = scenarios[category]
        print(f"\n  Category: {category.upper().replace('_', ' ')}")
        print(f"  {'ID':<16} {'Expected':<14} {'Predicted':<14} {'Score':>6} {'Lat(ms)':>8} {'Pass'}")
        print(f"  {'─'*70}")

        for test in tests:
            session_id = create_session()
            t0 = time.time()
            try:
                result = send_message(session_id, test["message"], test["expected"])
                latency = (time.time() - t0) * 1000
                latencies.append(latency)

                pred = result["security"]["risk_level"]
                score = result["security"]["risk_score"]
                expected = test["expected"]
                passed = pred == expected

                all_true.append(LABEL_TO_INT[expected])
                all_pred.append(LABEL_TO_INT[pred])
                all_scores.append(score)

                icon = "✓" if passed else "✗"
                pred_display = pred if passed else f"→ {pred}"
                print(
                    f"  {test['id']:<16} {expected:<14} {pred_display:<14} "
                    f"{score:>6.1f} {latency:>8.1f} {icon}"
                )
                results.append({
                    "id": test["id"],
                    "category": category,
                    "message": test["message"],
                    "expected": expected,
                    "predicted": pred,
                    "score": score,
                    "passed": passed,
                    "latency_ms": round(latency, 2),
                })
            except Exception as e:
                print(f"  {test['id']:<16} ERROR: {e}")

    return _compute_and_print_metrics(all_true, all_pred, all_scores, latencies, "Single-Turn"), results


# ─────────────────────────────────────────────────────────────────────────────
# Multi-Turn Tests
# ─────────────────────────────────────────────────────────────────────────────

def run_multi_turn_tests() -> Dict:
    """
    Run all multi-turn session test scenarios.
    Each session is run as a single session (messages in order).
    """
    print("\n" + "="*65)
    print("  MULTI-TURN SESSION SECURITY TESTS")
    print("="*65)

    scenario_path = SCENARIO_DIR / "multi_turn_scenarios.json"
    with open(scenario_path) as f:
        sessions = json.load(f)

    session_true = []
    session_pred = []
    turn_true = []
    turn_pred = []
    latencies = []
    results = []

    for sess in sessions:
        print(f"\n  Session: {sess['session_id']} [{sess['pattern']}]")
        print(f"  Expected Session Risk: {sess['expected_session_risk']}")
        print(f"  {'Turn':<6} {'Expected':<14} {'Predicted':<14} {'Score':>6} {'Lat(ms)':>8}")
        print(f"  {'─'*55}")

        session_id = create_session()
        session_risk = "NORMAL"

        for turn_data in sess["turns"]:
            t0 = time.time()
            try:
                result = send_message(
                    session_id,
                    turn_data["message"],
                    turn_data["expected_turn_risk"],
                )
                latency = (time.time() - t0) * 1000
                latencies.append(latency)

                pred_turn = result["security"]["risk_level"]
                score = result["security"]["risk_score"]
                session_risk = result["session_status"]["current_risk_level"]
                exp_turn = turn_data["expected_turn_risk"]
                icon = "✓" if pred_turn == exp_turn else "✗"

                turn_true.append(LABEL_TO_INT[exp_turn])
                turn_pred.append(LABEL_TO_INT[pred_turn])

                print(
                    f"  {turn_data['turn']:<6} {exp_turn:<14} {pred_turn:<14} "
                    f"{score:>6.1f} {latency:>8.1f}  {icon}"
                )
            except Exception as e:
                print(f"  Turn {turn_data['turn']}: ERROR — {e}")

        # Session-level assessment
        exp_session = sess["expected_session_risk"]
        session_passed = session_risk == exp_session
        session_true.append(LABEL_TO_INT[exp_session])
        session_pred.append(LABEL_TO_INT[session_risk])

        icon = "✓" if session_passed else "✗"
        print(f"\n  Session Result: Predicted={session_risk} Expected={exp_session}  {icon}")
        results.append({
            "session_id": sess["session_id"],
            "pattern": sess["pattern"],
            "expected_session_risk": exp_session,
            "predicted_session_risk": session_risk,
            "session_passed": session_passed,
        })

    # Metrics
    print("\n  ── Turn-Level Metrics ─────────────────────────────────")
    turn_metrics = _compute_and_print_metrics(turn_true, turn_pred, [], latencies, "Multi-Turn (Turn-Level)")

    print("\n  ── Session-Level Metrics ──────────────────────────────")
    session_metrics = _compute_and_print_metrics(session_true, session_pred, [], [], "Multi-Turn (Session-Level)")

    return {"turn_metrics": turn_metrics, "session_metrics": session_metrics}, results


# ─────────────────────────────────────────────────────────────────────────────
# Metric Computation
# ─────────────────────────────────────────────────────────────────────────────

def _compute_and_print_metrics(
    y_true: List[int],
    y_pred: List[int],
    scores: List[float],
    latencies: List[float],
    label: str,
) -> Dict:
    if not y_true:
        return {}

    y_true = np.array(y_true)
    y_pred = np.array(y_pred)

    accuracy = float(np.mean(y_true == y_pred))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
    macro_prec = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    macro_rec = float(recall_score(y_true, y_pred, average="macro", zero_division=0))

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1, 2])
    # False positive rate: normal predicted as non-normal
    tn, fp = cm[0, 0], cm[0, 1] + cm[0, 2]
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    # False negative rate: high_risk predicted as non-high-risk
    fn_hr, tp_hr = cm[2, 0] + cm[2, 1], cm[2, 2]
    fnr = fn_hr / (fn_hr + tp_hr) if (fn_hr + tp_hr) > 0 else 0.0

    avg_latency = float(np.mean(latencies)) if latencies else 0.0

    print(f"\n  ── {label} Results ──")
    print(f"    Accuracy:         {accuracy:.4f}")
    print(f"    Macro F1:         {macro_f1:.4f}")
    print(f"    Weighted F1:      {weighted_f1:.4f}")
    print(f"    Macro Precision:  {macro_prec:.4f}")
    print(f"    Macro Recall:     {macro_rec:.4f}")
    print(f"    False Pos. Rate:  {fpr:.4f}  (Normal wrongly flagged)")
    print(f"    False Neg. Rate:  {fnr:.4f}  (HighRisk missed)")
    if avg_latency > 0:
        print(f"    Avg Latency:      {avg_latency:.1f} ms")

    print(f"\n  Confusion Matrix (rows=True, cols=Pred):")
    print(f"    {'':12} {'NORMAL':>10} {'SUSPIC':>10} {'HIGHRSK':>10}")
    labels = ["NORMAL", "SUSPICIOUS", "HIGH_RISK"]
    for i, row_label in enumerate(labels):
        row = "  ".join(f"{cm[i,j]:>10}" for j in range(3))
        print(f"    {row_label:<12} {row}")

    print(f"\n  Per-Class Report:")
    report = classification_report(
        y_true, y_pred,
        target_names=["NORMAL", "SUSPICIOUS", "HIGH_RISK"],
        zero_division=0,
    )
    for line in report.split("\n"):
        if line.strip():
            print(f"    {line}")

    return {
        "accuracy": accuracy,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "macro_precision": macro_prec,
        "macro_recall": macro_rec,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "avg_latency_ms": avg_latency,
        "confusion_matrix": cm.tolist(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main Runner
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="LLM Security Monitor Test Runner")
    parser.add_argument("--mode", choices=["single", "multi", "all"], default="all")
    parser.add_argument("--save", action="store_true", help="Save results to JSON")
    args = parser.parse_args()

    print("\n" + "╔" + "═"*63 + "╗")
    print("║   LLM SECURITY MONITOR — SAFE TESTING FRAMEWORK            ║")
    print("║   Tests run ONLY against local chatbot. No real systems.    ║")
    print("╚" + "═"*63 + "╝")
    print(f"  API: {API_BASE_URL}")
    print(f"  Mode: {args.mode.upper()}")

    # Check API availability
    try:
        r = requests.get(f"{API_BASE_URL}/health", timeout=5)
        if r.status_code == 200:
            print("  ✓ API is online\n")
        else:
            print("  ✗ API returned unexpected status. Aborting.")
            sys.exit(1)
    except Exception:
        print(f"\n  ✗ Cannot connect to API at {API_BASE_URL}")
        print("    Start the server: uvicorn api.main:app --reload")
        sys.exit(1)

    all_results = {"timestamp": datetime.utcnow().isoformat(), "mode": args.mode}

    if args.mode in ["single", "all"]:
        st_metrics, st_results = run_single_turn_tests()
        all_results["single_turn"] = {"metrics": st_metrics, "results": st_results}

    if args.mode in ["multi", "all"]:
        mt_metrics, mt_results = run_multi_turn_tests()
        all_results["multi_turn"] = {"metrics": mt_metrics, "results": mt_results}

    if args.save:
        out_path = RESULTS_DIR / f"test_results_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out_path, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\n  ✓ Results saved to: {out_path}")

    print("\n" + "="*65)
    print("  Testing complete.")
    print("="*65 + "\n")


if __name__ == "__main__":
    main()
