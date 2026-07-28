"""
models/cnn_lstm/evaluator.py
─────────────────────────────────────────────────────────────────────────────
Model evaluation: metrics, confusion matrix, ablation comparison.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import json
import numpy as np
import torch
from torch.utils.data import DataLoader
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
import matplotlib.pyplot as plt
import seaborn as sns

from models.cnn_lstm.architecture import build_model
from models.cnn_lstm.trainer import (
    TurnLevelDataset,
    SessionLevelDataset,
    load_sessions,
    evaluate,
)
from config import MODELS_DIR, RISK_CLASSES, BATCH_SIZE

LABEL_MAP = {label: idx for idx, label in enumerate(RISK_CLASSES)}
IDX_TO_LABEL = {v: k for k, v in LABEL_MAP.items()}
RESULTS_DIR = Path(__file__).parent.parent.parent / "experiments" / "results"
VIZ_DIR = Path(__file__).parent.parent.parent / "experiments" / "visualizations"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
VIZ_DIR.mkdir(parents=True, exist_ok=True)


def load_trained_model(model_type: str):
    """Load a saved checkpoint."""
    ckpt_path = MODELS_DIR / f"{model_type}.pt"
    if not ckpt_path.exists():
        raise FileNotFoundError(
            f"No checkpoint found: {ckpt_path}\n"
            f"Run: python models/cnn_lstm/trainer.py {model_type}"
        )
    model = build_model(model_type)
    checkpoint = torch.load(ckpt_path, map_location="cpu")
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    return model


def get_predictions(model_type: str) -> tuple:
    """Get test set predictions for a model."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = load_trained_model(model_type).to(device)

    test_sessions = load_sessions("test")
    is_turn_level = (model_type == "cnn_only")
    DatasetClass = TurnLevelDataset if is_turn_level else SessionLevelDataset

    test_ds = DatasetClass(test_sessions)
    test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE, shuffle=False)

    import torch.nn as nn
    criterion = nn.CrossEntropyLoss()
    _, acc, preds, labels = evaluate(model, test_loader, criterion, device, model_type)

    return preds, labels, acc


def compute_metrics(preds: np.ndarray, labels: np.ndarray) -> dict:
    """Compute all evaluation metrics."""
    cm = confusion_matrix(labels, preds, labels=[0, 1, 2])
    report = classification_report(
        labels, preds,
        target_names=RISK_CLASSES,
        output_dict=True,
    )

    # False positive rate (NORMAL predicted as something else)
    tn = cm[0, 0]
    fp = cm[0, 1] + cm[0, 2]
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # False negative rate (HIGH_RISK predicted as something else)
    fn = cm[2, 0] + cm[2, 1]
    tp = cm[2, 2]
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": float(np.mean(preds == labels)),
        "macro_f1": float(f1_score(labels, preds, average="macro")),
        "weighted_f1": float(f1_score(labels, preds, average="weighted")),
        "macro_precision": float(precision_score(labels, preds, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(labels, preds, average="macro", zero_division=0)),
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "per_class": report,
        "confusion_matrix": cm.tolist(),
    }


def plot_confusion_matrix(cm: list, model_type: str):
    """Plot and save confusion matrix."""
    cm = np.array(cm)
    fig, ax = plt.subplots(figsize=(7, 5))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=RISK_CLASSES, yticklabels=RISK_CLASSES, ax=ax
    )
    ax.set_ylabel("True Label", fontsize=12)
    ax.set_xlabel("Predicted Label", fontsize=12)
    ax.set_title(f"Confusion Matrix — {model_type.upper()}", fontsize=14)
    plt.tight_layout()
    save_path = VIZ_DIR / f"confusion_matrix_{model_type}.png"
    plt.savefig(save_path, dpi=150)
    plt.close()
    return save_path


def run_ablation_study():
    """
    Run evaluation for all model variants and produce comparison table.
    """
    print("\n" + "="*60)
    print("  ABLATION STUDY — Comparing All Model Variants")
    print("="*60)

    model_types = ["cnn_only", "lstm_only", "cnn_lstm"]
    all_results = {}

    for mt in model_types:
        print(f"\n  Evaluating: {mt.upper()} ...")
        try:
            preds, labels, acc = get_predictions(mt)
            metrics = compute_metrics(preds, labels)
            all_results[mt] = metrics

            cm_path = plot_confusion_matrix(metrics["confusion_matrix"], mt)
            print(f"    Accuracy:       {metrics['accuracy']:.4f}")
            print(f"    Macro F1:       {metrics['macro_f1']:.4f}")
            print(f"    Weighted F1:    {metrics['weighted_f1']:.4f}")
            print(f"    FPR (Normal):   {metrics['false_positive_rate']:.4f}")
            print(f"    FNR (HighRisk): {metrics['false_negative_rate']:.4f}")
            print(f"    Confusion matrix saved: {cm_path.name}")
        except FileNotFoundError as e:
            print(f"    [SKIP] {e}")
            all_results[mt] = None

    # Save comparison
    summary_path = RESULTS_DIR / "ablation_summary.json"
    with open(summary_path, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\n  ✓ Ablation results saved: {summary_path}")

    # Print comparison table
    print("\n" + "─"*60)
    print(f"  {'Model':<15} {'Acc':>8} {'MacroF1':>9} {'WtdF1':>8} {'FPR':>8} {'FNR':>8}")
    print("  " + "─"*57)
    for mt, res in all_results.items():
        if res:
            print(
                f"  {mt:<15} {res['accuracy']:>8.4f} {res['macro_f1']:>9.4f} "
                f"{res['weighted_f1']:>8.4f} {res['false_positive_rate']:>8.4f} "
                f"{res['false_negative_rate']:>8.4f}"
            )

    return all_results


if __name__ == "__main__":
    run_ablation_study()
