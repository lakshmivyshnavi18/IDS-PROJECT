"""
models/cnn_lstm/architecture.py
─────────────────────────────────────────────────────────────────────────────
CNN-LSTM Architecture for LLM Interaction Security Classification.

SCIENTIFIC RATIONALE:

  CNN Component:
    Operates on the per-turn feature vector (404-dim) reshaped as a 1D sequence.
    Convolutional filters learn to detect local patterns — clusters of features
    that co-activate together in suspicious prompts (e.g., override language +
    high structural urgency + probing semantic clusters). This is analogous to
    how CNNs detect edge patterns in images — here they detect "semantic-structural
    co-patterns" in the feature space.

  LSTM Component:
    Receives the CNN output for each session turn as a time-series.
    The LSTM has memory — it tracks how the CNN feature maps evolve across turns.
    This enables the model to recognize session-level behavioral patterns:
    - Escalating risk across turns
    - Repeated override attempts after refusals
    - Gradual manipulation sequences

  Combined:
    CNN answers: "What kind of prompt is THIS?"
    LSTM answers: "How has the user's behavior EVOLVED over this session?"

ABLATION VARIANTS:
  - CNN_Only:  CNN → GlobalPool → Dense(3)
  - LSTM_Only: Raw features → LSTM → Dense(3)
  - CNN_LSTM:  CNN → LSTM → Dense(3)   [main architecture]
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import torch
import torch.nn as nn
import torch.nn.functional as F
from config import (
    TOTAL_FEATURE_DIM, CNN_OUTPUT_DIM,
    LSTM_HIDDEN_DIM, LSTM_NUM_LAYERS, LSTM_DROPOUT,
    RISK_CLASSES,
)

NUM_CLASSES = len(RISK_CLASSES)  # 3


# ═════════════════════════════════════════════════════════════════════════════
# CNN Block
# ═════════════════════════════════════════════════════════════════════════════

class CNNBlock(nn.Module):
    """
    1D Convolutional feature extractor for a single prompt.

    Input:  (batch, feature_dim, 1) — feature vector as 1D sequence
    Output: (batch, CNN_OUTPUT_DIM) — compressed local pattern representation

    Architecture:
      Conv1D(64, k=7) → BN → ReLU
      Conv1D(128, k=5) → BN → ReLU
      MaxPool
      Conv1D(CNN_OUTPUT_DIM, k=3) → BN → ReLU
      GlobalAvgPool → flatten
    """

    def __init__(self, input_dim: int = TOTAL_FEATURE_DIM, output_dim: int = CNN_OUTPUT_DIM):
        super().__init__()
        self.input_dim = input_dim

        self.conv_layers = nn.Sequential(
            # Layer 1: broad feature detection
            nn.Conv1d(in_channels=1, out_channels=64, kernel_size=7, padding=3),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),

            # Layer 2: refined pattern extraction
            nn.Conv1d(in_channels=64, out_channels=128, kernel_size=5, padding=2),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.MaxPool1d(kernel_size=2, stride=2),
            nn.Dropout(0.2),

            # Layer 3: compact representation
            nn.Conv1d(in_channels=128, out_channels=output_dim, kernel_size=3, padding=1),
            nn.BatchNorm1d(output_dim),
            nn.ReLU(),
        )

        # Global average pooling → fixed-size output regardless of input length
        self.global_pool = nn.AdaptiveAvgPool1d(1)

        self.output_dim = output_dim

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (batch, feature_dim)   — one prompt's feature vector
        Returns:
            (batch, CNN_OUTPUT_DIM)
        """
        # Reshape: (batch, feature_dim) → (batch, 1, feature_dim)
        x = x.unsqueeze(1)

        # Conv layers: (batch, 1, feature_dim) → (batch, output_dim, L)
        x = self.conv_layers(x)

        # Global pool: (batch, output_dim, L) → (batch, output_dim, 1)
        x = self.global_pool(x)

        # Flatten: (batch, output_dim, 1) → (batch, output_dim)
        x = x.squeeze(-1)

        return x


# ═════════════════════════════════════════════════════════════════════════════
# CNN-Only Model (Ablation Variant)
# ═════════════════════════════════════════════════════════════════════════════

class CNNOnlyModel(nn.Module):
    """
    Ablation Variant: CNN only (no session context).
    Classifies each prompt independently without temporal awareness.
    """

    def __init__(self, input_dim: int = TOTAL_FEATURE_DIM, num_classes: int = NUM_CLASSES):
        super().__init__()
        self.cnn = CNNBlock(input_dim=input_dim, output_dim=CNN_OUTPUT_DIM)
        self.classifier = nn.Sequential(
            nn.Linear(CNN_OUTPUT_DIM, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (batch, feature_dim) — single prompt feature vector
        Returns:
            (batch, num_classes) — logits
        """
        features = self.cnn(x)
        return self.classifier(features)

    def get_cnn_features(self, x: torch.Tensor) -> torch.Tensor:
        """Extract CNN features without classification head."""
        return self.cnn(x)


# ═════════════════════════════════════════════════════════════════════════════
# LSTM-Only Model (Ablation Variant)
# ═════════════════════════════════════════════════════════════════════════════

class LSTMOnlyModel(nn.Module):
    """
    Ablation Variant: LSTM only (no CNN preprocessing).
    Uses raw feature vectors directly as LSTM input sequence.
    """

    def __init__(
        self,
        input_dim: int = TOTAL_FEATURE_DIM,
        hidden_dim: int = LSTM_HIDDEN_DIM,
        num_layers: int = LSTM_NUM_LAYERS,
        num_classes: int = NUM_CLASSES,
        dropout: float = LSTM_DROPOUT,
    ):
        super().__init__()

        # Project raw features to smaller dim before LSTM
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
        )

        self.lstm = nn.LSTM(
            input_size=128,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )

        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (batch, seq_len, feature_dim) — session sequence of feature vectors
        Returns:
            (batch, num_classes) — logits
        """
        batch, seq, feat = x.shape
        # Project each timestep
        x_proj = self.input_proj(x.view(batch * seq, feat)).view(batch, seq, -1)

        lstm_out, (hidden, _) = self.lstm(x_proj)
        # Use the last hidden state
        last_hidden = hidden[-1]  # (batch, hidden_dim)

        return self.classifier(last_hidden)


# ═════════════════════════════════════════════════════════════════════════════
# CNN + LSTM Combined Model (Main Architecture)
# ═════════════════════════════════════════════════════════════════════════════

class CNNLSTMModel(nn.Module):
    """
    Main Research Architecture: CNN + LSTM for LLM Interaction Security.

    Processing pipeline per session:
      For each turn t in session:
        feature_vector_t (404-dim)
          ↓ CNN
        cnn_feature_t (64-dim)        ← local pattern for this turn
      Session sequence: [cnn_f_1, cnn_f_2, ..., cnn_f_T]
          ↓ LSTM
        lstm_hidden (128-dim)         ← temporal behavioral context
          ↓ Dense layers
        risk_logits (3-dim)           → NORMAL / SUSPICIOUS / HIGH_RISK
    """

    def __init__(
        self,
        input_dim: int = TOTAL_FEATURE_DIM,
        cnn_output_dim: int = CNN_OUTPUT_DIM,
        lstm_hidden_dim: int = LSTM_HIDDEN_DIM,
        lstm_num_layers: int = LSTM_NUM_LAYERS,
        lstm_dropout: float = LSTM_DROPOUT,
        num_classes: int = NUM_CLASSES,
    ):
        super().__init__()

        # CNN block — processes each turn's feature vector
        self.cnn = CNNBlock(input_dim=input_dim, output_dim=cnn_output_dim)

        # LSTM — processes the sequence of CNN feature maps
        self.lstm = nn.LSTM(
            input_size=cnn_output_dim,
            hidden_size=lstm_hidden_dim,
            num_layers=lstm_num_layers,
            batch_first=True,
            dropout=lstm_dropout if lstm_num_layers > 1 else 0.0,
        )

        # Classification head
        self.classifier = nn.Sequential(
            nn.Dropout(lstm_dropout),
            nn.Linear(lstm_hidden_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, num_classes),
        )

        # Risk score head (for continuous 0–100 output)
        self.risk_scorer = nn.Sequential(
            nn.Dropout(0.2),
            nn.Linear(lstm_hidden_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid(),  # Output in [0, 1], scaled to [0, 100] externally
        )

    def forward(
        self,
        session_features: torch.Tensor,
        return_cnn_features: bool = False,
    ) -> dict:
        """
        Forward pass for a batch of sessions.

        Args:
            session_features: (batch, seq_len, feature_dim)
                Each element is a sequence of per-turn feature vectors.
            return_cnn_features: If True, also return per-turn CNN features.

        Returns:
            dict with keys:
              'logits':         (batch, num_classes)
              'probabilities':  (batch, num_classes)
              'risk_score':     (batch,) — values in [0, 1]
              'cnn_features':   (batch, seq_len, cnn_output_dim) — if requested
              'lstm_hidden':    (batch, lstm_hidden_dim)
        """
        batch_size, seq_len, feat_dim = session_features.shape

        # ── CNN: process each turn independently ──────────────────────────────
        # Reshape to (batch * seq_len, feat_dim) to pass all turns through CNN
        x_flat = session_features.view(batch_size * seq_len, feat_dim)
        cnn_out = self.cnn(x_flat)                              # (B*T, cnn_dim)
        cnn_features = cnn_out.view(batch_size, seq_len, -1)    # (B, T, cnn_dim)

        # ── LSTM: process the session sequence ────────────────────────────────
        lstm_out, (hidden, cell) = self.lstm(cnn_features)      # lstm_out: (B, T, hidden)
        last_hidden = hidden[-1]                                 # (B, hidden_dim)

        # ── Classification ────────────────────────────────────────────────────
        logits = self.classifier(last_hidden)                   # (B, num_classes)
        probs = F.softmax(logits, dim=-1)                       # (B, num_classes)
        risk_score = self.risk_scorer(last_hidden).squeeze(-1)  # (B,)

        result = {
            "logits": logits,
            "probabilities": probs,
            "risk_score": risk_score,
            "lstm_hidden": last_hidden,
        }

        if return_cnn_features:
            result["cnn_features"] = cnn_features

        return result

    def predict_single_turn(self, feature_vector: torch.Tensor) -> dict:
        """
        Process a single turn's feature vector (seq_len=1).
        Used in real-time inference where session is built incrementally.

        Args:
            feature_vector: (1, feature_dim) — single turn features
        Returns:
            CNN feature map for this turn: (1, cnn_output_dim)
        """
        cnn_out = self.cnn(feature_vector)  # (1, cnn_dim)
        return cnn_out

    def predict_from_buffer(self, session_buffer: torch.Tensor) -> dict:
        """
        Run full inference from the current session CNN feature buffer.

        Args:
            session_buffer: (1, T, cnn_output_dim) — accumulated CNN features
        Returns:
            Full prediction dict from the LSTM onward
        """
        lstm_out, (hidden, _) = self.lstm(session_buffer)
        last_hidden = hidden[-1]

        logits = self.classifier(last_hidden)
        probs = F.softmax(logits, dim=-1)
        risk_score = self.risk_scorer(last_hidden).squeeze(-1)

        return {
            "logits": logits,
            "probabilities": probs,
            "risk_score": risk_score,
            "lstm_hidden": last_hidden,
        }


# ═════════════════════════════════════════════════════════════════════════════
# Model Factory
# ═════════════════════════════════════════════════════════════════════════════

def build_model(model_type: str = "cnn_lstm") -> nn.Module:
    """
    Factory function for building ablation variants.

    Args:
        model_type: "cnn_only" | "lstm_only" | "cnn_lstm"

    Returns:
        The requested PyTorch model
    """
    if model_type == "cnn_only":
        return CNNOnlyModel()
    elif model_type == "lstm_only":
        return LSTMOnlyModel()
    elif model_type == "cnn_lstm":
        return CNNLSTMModel()
    else:
        raise ValueError(f"Unknown model_type: {model_type}. Choose from: cnn_only, lstm_only, cnn_lstm")


if __name__ == "__main__":
    # Quick architecture verification
    print("=== Architecture Verification ===\n")

    batch_size = 4
    seq_len = 5
    feat_dim = TOTAL_FEATURE_DIM

    # CNN only
    cnn_model = CNNOnlyModel()
    x_single = torch.randn(batch_size, feat_dim)
    out = cnn_model(x_single)
    print(f"CNN-Only:  input={x_single.shape} → output={out.shape}")
    print(f"  Params: {sum(p.numel() for p in cnn_model.parameters()):,}")

    # LSTM only
    lstm_model = LSTMOnlyModel()
    x_seq = torch.randn(batch_size, seq_len, feat_dim)
    out = lstm_model(x_seq)
    print(f"\nLSTM-Only: input={x_seq.shape} → output={out.shape}")
    print(f"  Params: {sum(p.numel() for p in lstm_model.parameters()):,}")

    # CNN + LSTM
    full_model = CNNLSTMModel()
    x_seq = torch.randn(batch_size, seq_len, feat_dim)
    result = full_model(x_seq)
    print(f"\nCNN+LSTM:  input={x_seq.shape}")
    print(f"  logits={result['logits'].shape}")
    print(f"  probs={result['probabilities'].shape}")
    print(f"  risk_score={result['risk_score'].shape}")
    print(f"  Params: {sum(p.numel() for p in full_model.parameters()):,}")
    print("\n✓ All architecture checks passed.")
