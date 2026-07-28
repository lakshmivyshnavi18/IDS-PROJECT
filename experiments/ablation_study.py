"""
experiments/ablation_study.py
─────────────────────────────────────────────────────────────────────────────
Ablation study: train and evaluate all model variants, produce comparison.

Research Question:
  "Does combining local prompt-pattern analysis (CNN) with temporal session
   behavior modeling (LSTM) improve detection compared to either alone?"

Experiments:
  E1: CNN-Only  — per-turn classification, no session context
  E2: LSTM-Only — session sequences, no CNN preprocessing
  E3: CNN+LSTM  — full hybrid architecture

Usage:
  python experiments/ablation_study.py --train   # train all variants
  python experiments/ablation_study.py --eval    # evaluate all variants
  python experiments/ablation_study.py --all     # train + eval + plot
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import argparse
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

from models.cnn_lstm.trainer import train_model
from models.cnn_lstm.evaluator import run_ablation_study, plot_confusion_matrix

RESULTS_DIR = Path(__file__).parent / "results"
VIZ_DIR = Path(__file__).parent / "visualizations"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
VIZ_DIR.mkdir(parents=True, exist_ok=True)

MODEL_TYPES = ["cnn_only", "lstm_only", "cnn_lstm"]
COLORS = {"cnn_only": "#3b82f6", "lstm_only": "#8b5cf6", "cnn_lstm": "#22c55e"}
LABELS = {"cnn_only": "CNN Only", "lstm_only": "LSTM Only", "cnn_lstm": "CNN + LSTM (Ours)"}


def train_all():
    """Train all model variants sequentially."""
    print("\n" + "="*60)
    print("  ABLATION STUDY — Training All Variants")
    print("="*60)
    for mt in MODEL_TYPES:
        train_model(mt)
    print("\n✓ All variants trained.")


def evaluate_all():
    """Evaluate all trained variants and save results."""
    return run_ablation_study()


def plot_comparison(results: dict):
    """Generate publication-quality comparison charts."""
    print("\n  Generating comparison visualizations...")

    valid = {k: v for k, v in results.items() if v is not None}
    if not valid:
        print("  No results to plot.")
        return

    metrics_to_plot = {
        "Accuracy": "accuracy",
        "Macro F1": "macro_f1",
        "Weighted F1": "weighted_f1",
        "False Positive Rate": "false_positive_rate",
        "False Negative Rate": "false_negative_rate",
    }

    # ── Bar chart comparison ─────────────────────────────────────────────────
    fig, axes = plt.subplots(1, len(metrics_to_plot), figsize=(18, 5))
    fig.patch.set_facecolor("#0a0e1a")

    for ax, (metric_name, metric_key) in zip(axes, metrics_to_plot.items()):
        ax.set_facecolor("#111827")

        model_names = list(valid.keys())
        values = [valid[m][metric_key] for m in model_names]
        bar_colors = [COLORS.get(m, "#64748b") for m in model_names]
        display_names = [LABELS.get(m, m) for m in model_names]

        bars = ax.bar(display_names, values, color=bar_colors, alpha=0.85, edgecolor="none",
                      width=0.5)

        # Value labels on bars
        for bar, val in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.01,
                f"{val:.3f}",
                ha="center", va="bottom",
                color="#e2e8f0", fontsize=9, fontweight="bold"
            )

        ax.set_title(metric_name, color="#63b3ed", fontsize=11, fontweight="bold", pad=10)
        ax.set_ylim(0, min(max(values) * 1.25, 1.05))
        ax.tick_params(colors="#94a3b8", labelsize=8)
        ax.spines[:].set_color("#1e293b")
        ax.yaxis.label.set_color("#64748b")
        for label in ax.get_xticklabels():
            label.set_color("#94a3b8")
            label.set_fontsize(8)

    fig.suptitle(
        "Ablation Study: CNN-Only vs LSTM-Only vs CNN+LSTM",
        color="#f1f5f9", fontsize=14, fontweight="bold", y=1.02
    )
    plt.tight_layout()
    out_path = VIZ_DIR / "ablation_comparison.png"
    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor="#0a0e1a")
    plt.close()
    print(f"  ✓ Comparison chart: {out_path.name}")

    # ── Training curves (if available) ──────────────────────────────────────
    from config import MODELS_DIR
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.patch.set_facecolor("#0a0e1a")

    for ax in axes:
        ax.set_facecolor("#111827")
        ax.spines[:].set_color("#1e293b")
        ax.tick_params(colors="#94a3b8")

    for mt in MODEL_TYPES:
        curve_path = MODELS_DIR / f"{mt}_training_curves.json"
        if not curve_path.exists():
            continue
        with open(curve_path) as f:
            curves = json.load(f)

        color = COLORS.get(mt, "#64748b")
        label = LABELS.get(mt, mt)
        epochs = range(1, len(curves["val_losses"]) + 1)

        axes[0].plot(epochs, curves["val_losses"], color=color, linewidth=2.5,
                     label=label, alpha=0.9)
        axes[1].plot(epochs, curves["val_accs"], color=color, linewidth=2.5,
                     label=label, alpha=0.9)

    axes[0].set_title("Validation Loss", color="#63b3ed", fontsize=11, fontweight="bold")
    axes[0].set_xlabel("Epoch", color="#94a3b8")
    axes[0].set_ylabel("Loss", color="#94a3b8")
    axes[0].legend(facecolor="#1e293b", labelcolor="#e2e8f0", edgecolor="#334155")
    axes[0].grid(color="#1e293b", linewidth=0.5)

    axes[1].set_title("Validation Accuracy", color="#63b3ed", fontsize=11, fontweight="bold")
    axes[1].set_xlabel("Epoch", color="#94a3b8")
    axes[1].set_ylabel("Accuracy", color="#94a3b8")
    axes[1].legend(facecolor="#1e293b", labelcolor="#e2e8f0", edgecolor="#334155")
    axes[1].grid(color="#1e293b", linewidth=0.5)

    fig.suptitle("Training Curves — All Model Variants",
                 color="#f1f5f9", fontsize=13, fontweight="bold")
    plt.tight_layout()
    curve_out = VIZ_DIR / "training_curves.png"
    plt.savefig(curve_out, dpi=150, bbox_inches="tight", facecolor="#0a0e1a")
    plt.close()
    print(f"  ✓ Training curves: {curve_out.name}")

    # ── Summary table ─────────────────────────────────────────────────────────
    summary = []
    for mt in MODEL_TYPES:
        if mt in valid:
            r = valid[mt]
            summary.append({
                "Model": LABELS.get(mt, mt),
                "Accuracy": f"{r['accuracy']:.4f}",
                "Macro F1": f"{r['macro_f1']:.4f}",
                "Weighted F1": f"{r['weighted_f1']:.4f}",
                "FPR": f"{r['false_positive_rate']:.4f}",
                "FNR": f"{r['false_negative_rate']:.4f}",
            })

    print("\n  ── Final Ablation Table ─────────────────────────────────")
    print(f"  {'Model':<22} {'Acc':>8} {'MF1':>8} {'WF1':>8} {'FPR':>8} {'FNR':>8}")
    print("  " + "─"*66)
    for row in summary:
        print(
            f"  {row['Model']:<22} {row['Accuracy']:>8} {row['Macro F1']:>8} "
            f"{row['Weighted F1']:>8} {row['FPR']:>8} {row['FNR']:>8}"
        )

    # Save summary
    summary_path = RESULTS_DIR / "ablation_table.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n  ✓ Summary table: {summary_path.name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ablation Study Runner")
    parser.add_argument("--train", action="store_true", help="Train all variants")
    parser.add_argument("--eval", action="store_true", help="Evaluate all variants")
    parser.add_argument("--all", action="store_true", help="Train + evaluate + plot")
    args = parser.parse_args()

    if args.all or args.train:
        train_all()

    if args.all or args.eval:
        results = evaluate_all()
        plot_comparison(results)

    if not any([args.train, args.eval, args.all]):
        print("Usage: python experiments/ablation_study.py --all")
        print("       python experiments/ablation_study.py --train")
        print("       python experiments/ablation_study.py --eval")
