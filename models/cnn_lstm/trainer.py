"""
models/cnn_lstm/trainer.py
─────────────────────────────────────────────────────────────────────────────
Training pipeline for CNN-Only, LSTM-Only, and CNN+LSTM models.

Features:
  - Session-level data loading (respects session boundaries)
  - Class-weighted loss (handles imbalanced risk labels)
  - Early stopping
  - Learning rate scheduling
  - Checkpoint saving
  - Training curve plotting
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import json
import pickle
import time
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from torch.optim.lr_scheduler import ReduceLROnPlateau
from sklearn.utils.class_weight import compute_class_weight
from typing import List, Dict, Tuple, Optional
import matplotlib.pyplot as plt

from models.cnn_lstm.architecture import build_model, CNNLSTMModel
from security.feature_extractor import build_feature_vector, build_session_feature_matrix
from config import (
    BATCH_SIZE, LEARNING_RATE, WEIGHT_DECAY, NUM_EPOCHS,
    EARLY_STOPPING_PATIENCE, MODELS_DIR, DATA_DIR, RISK_CLASSES,
    SESSION_WINDOW_SIZE,
)

MODELS_DIR.mkdir(parents=True, exist_ok=True)
LABEL_MAP = {label: idx for idx, label in enumerate(RISK_CLASSES)}


# ═════════════════════════════════════════════════════════════════════════════
# Dataset Classes
# ═════════════════════════════════════════════════════════════════════════════

class TurnLevelDataset(Dataset):
    """
    Dataset for CNN-Only ablation.
    Each sample: (feature_vector, turn_risk_label)
    Session context is NOT used.
    """

    def __init__(self, sessions: List[Dict]):
        self.samples = []
        for session in sessions:
            for turn in session["turns"]:
                vec, _, _ = build_feature_vector(turn["message_text"])
                label = LABEL_MAP[turn["turn_risk_label"]]
                self.samples.append((vec, label))

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        vec, label = self.samples[idx]
        return torch.tensor(vec, dtype=torch.float32), torch.tensor(label, dtype=torch.long)


class SessionLevelDataset(Dataset):
    """
    Dataset for LSTM-Only and CNN+LSTM models.
    Each sample: (session_feature_matrix, session_risk_label)
    Pads or truncates sessions to SESSION_WINDOW_SIZE.
    """

    def __init__(self, sessions: List[Dict], window_size: int = SESSION_WINDOW_SIZE):
        self.window_size = window_size
        self.samples = []

        for session in sessions:
            texts = [t["message_text"] for t in session["turns"]]
            label = LABEL_MAP[session["session_risk_label"]]

            # Truncate to window size
            texts = texts[-window_size:]  # Keep the most recent turns
            mat = build_session_feature_matrix(texts)  # (T, feat_dim)

            # Pad if session is shorter than window_size
            if len(texts) < window_size:
                pad_rows = window_size - len(texts)
                padding = np.zeros((pad_rows, mat.shape[1]), dtype=np.float32)
                mat = np.vstack([padding, mat])  # Prepend zeros (mask early turns)

            self.samples.append((mat, label))

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        mat, label = self.samples[idx]
        return (
            torch.tensor(mat, dtype=torch.float32),
            torch.tensor(label, dtype=torch.long),
        )


# ═════════════════════════════════════════════════════════════════════════════
# Data Loading
# ═════════════════════════════════════════════════════════════════════════════

def load_sessions(split: str) -> List[Dict]:
    """Load session JSONL from the dataset directory."""
    path = DATA_DIR / "raw" / f"{split}_sessions.jsonl"
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}\n"
            f"Run: python data/generation/dataset_generator.py"
        )
    sessions = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            sessions.append(json.loads(line.strip()))
    return sessions


def get_class_weights(sessions: List[Dict]) -> torch.Tensor:
    """Compute inverse-frequency class weights for balanced training."""
    labels = [LABEL_MAP[s["session_risk_label"]] for s in sessions]
    weights = compute_class_weight(
        class_weight="balanced",
        classes=np.array([0, 1, 2]),
        y=np.array(labels),
    )
    return torch.tensor(weights, dtype=torch.float32)


# ═════════════════════════════════════════════════════════════════════════════
# Training Loop
# ═════════════════════════════════════════════════════════════════════════════

def train_epoch(model, loader, optimizer, criterion, device, model_type):
    model.train()
    total_loss = 0.0
    correct = 0
    total = 0

    for batch in loader:
        features, labels = batch
        features, labels = features.to(device), labels.to(device)

        optimizer.zero_grad()

        if model_type == "cnn_only":
            logits = model(features)
        else:
            logits = model(features) if model_type == "lstm_only" else model(features)["logits"]

        loss = criterion(logits, labels)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()

        total_loss += loss.item()
        preds = logits.argmax(dim=-1)
        correct += (preds == labels).sum().item()
        total += labels.size(0)

    return total_loss / len(loader), correct / total


@torch.no_grad()
def evaluate(model, loader, criterion, device, model_type):
    model.eval()
    total_loss = 0.0
    correct = 0
    total = 0
    all_preds = []
    all_labels = []

    for batch in loader:
        features, labels = batch
        features, labels = features.to(device), labels.to(device)

        if model_type == "cnn_only":
            logits = model(features)
        elif model_type == "lstm_only":
            logits = model(features)
        else:
            logits = model(features)["logits"]

        loss = criterion(logits, labels)
        total_loss += loss.item()

        preds = logits.argmax(dim=-1)
        correct += (preds == labels).sum().item()
        total += labels.size(0)
        all_preds.extend(preds.cpu().numpy())
        all_labels.extend(labels.cpu().numpy())

    return (
        total_loss / len(loader),
        correct / total,
        np.array(all_preds),
        np.array(all_labels),
    )


def train_model(model_type: str = "cnn_lstm"):
    """
    Full training pipeline for a given model variant.

    Args:
        model_type: "cnn_only" | "lstm_only" | "cnn_lstm"
    """
    print(f"\n{'='*55}")
    print(f"  Training: {model_type.upper()}")
    print(f"{'='*55}")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"  Device: {device}")

    # ── Load data ─────────────────────────────────────────────
    print("  Loading dataset...")
    train_sessions = load_sessions("train")
    val_sessions = load_sessions("val")

    # ── Build datasets ─────────────────────────────────────────
    is_turn_level = (model_type == "cnn_only")
    DatasetClass = TurnLevelDataset if is_turn_level else SessionLevelDataset

    print("  Building feature datasets (this may take a few minutes)...")
    train_ds = DatasetClass(train_sessions)
    val_ds = DatasetClass(val_sessions)

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False, num_workers=0)

    print(f"  Train samples: {len(train_ds)}  |  Val samples: {len(val_ds)}")

    # ── Build model ────────────────────────────────────────────
    model = build_model(model_type).to(device)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"  Model parameters: {total_params:,}")

    # ── Class-weighted loss ────────────────────────────────────
    class_weights = get_class_weights(train_sessions if is_turn_level else train_sessions)
    criterion = nn.CrossEntropyLoss(weight=class_weights.to(device))

    # ── Optimizer & Scheduler ─────────────────────────────────
    optimizer = AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)
    scheduler = ReduceLROnPlateau(optimizer, mode="min", patience=3, factor=0.5)

    # ── Training loop ─────────────────────────────────────────
    best_val_loss = float("inf")
    patience_counter = 0
    train_losses, val_losses = [], []
    train_accs, val_accs = [], []
    best_epoch = 0

    print(f"\n  Starting training ({NUM_EPOCHS} epochs max, patience={EARLY_STOPPING_PATIENCE})...")
    print(f"  {'Epoch':>6} {'Train Loss':>11} {'Train Acc':>10} {'Val Loss':>10} {'Val Acc':>9} {'LR':>10}")
    print(f"  {'─'*60}")

    for epoch in range(1, NUM_EPOCHS + 1):
        t0 = time.time()

        train_loss, train_acc = train_epoch(
            model, train_loader, optimizer, criterion, device, model_type
        )
        val_loss, val_acc, _, _ = evaluate(
            model, val_loader, criterion, device, model_type
        )
        scheduler.step(val_loss)

        train_losses.append(train_loss)
        val_losses.append(val_loss)
        train_accs.append(train_acc)
        val_accs.append(val_acc)

        lr = optimizer.param_groups[0]["lr"]
        elapsed = time.time() - t0
        print(
            f"  {epoch:>6} {train_loss:>11.4f} {train_acc:>10.3f} "
            f"{val_loss:>10.4f} {val_acc:>9.3f} {lr:>10.2e}  [{elapsed:.1f}s]"
        )

        # ── Early stopping & checkpointing ─────────────────────
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_epoch = epoch
            patience_counter = 0
            save_path = MODELS_DIR / f"{model_type}.pt"
            torch.save({
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "val_loss": val_loss,
                "val_acc": val_acc,
                "model_type": model_type,
            }, save_path)
        else:
            patience_counter += 1
            if patience_counter >= EARLY_STOPPING_PATIENCE:
                print(f"\n  Early stopping at epoch {epoch} (best: {best_epoch})")
                break

    # ── Save training curves ───────────────────────────────────
    curve_data = {
        "model_type": model_type,
        "train_losses": train_losses,
        "val_losses": val_losses,
        "train_accs": train_accs,
        "val_accs": val_accs,
        "best_epoch": best_epoch,
        "best_val_loss": best_val_loss,
    }
    curve_path = MODELS_DIR / f"{model_type}_training_curves.json"
    with open(curve_path, "w") as f:
        json.dump(curve_data, f, indent=2)

    print(f"\n  ✓ Best model saved: {MODELS_DIR}/{model_type}.pt")
    print(f"  ✓ Training curves:  {curve_path.name}")
    print(f"  Best epoch: {best_epoch} | Best val loss: {best_val_loss:.4f}")

    return model, curve_data


if __name__ == "__main__":
    import sys
    model_type = sys.argv[1] if len(sys.argv) > 1 else "cnn_lstm"
    train_model(model_type)
