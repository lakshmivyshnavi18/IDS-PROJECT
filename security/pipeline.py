"""
security/pipeline.py
─────────────────────────────────────────────────────────────────────────────
The central security pipeline — orchestrates all components for real-time
analysis of every user message.

Pipeline stages:
  1. Heuristic pre-check
  2. Feature extraction (embedding + structural + heuristic)
  3. CNN: local pattern extraction for current turn
  4. LSTM: session-level behavioral analysis
  5. Risk scoring
  6. AI explanation generation
  7. Database persistence
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import time
import torch
import numpy as np
from typing import Dict, Optional, Any

from security.feature_extractor import build_feature_vector
from security.heuristic_filter import compute_heuristic_signals, heuristic_risk_estimate, signals_to_vector
from security.risk_scorer import compute_risk_score
from security.explainer import explain
from security.session_manager import session_manager, ActiveSession
from config import MODELS_DIR, RISK_CLASSES, CNN_OUTPUT_DIM, SESSION_WINDOW_SIZE


LABEL_MAP = {label: idx for idx, label in enumerate(RISK_CLASSES)}
IDX_TO_LABEL = {v: k for k, v in LABEL_MAP.items()}

# ── Model cache (loaded once) ─────────────────────────────────────────────────
_model_cache: Dict[str, Any] = {}


def _load_model():
    """Load the CNN+LSTM model (cached after first load)."""
    if "cnn_lstm" not in _model_cache:
        from models.cnn_lstm.architecture import CNNLSTMModel
        ckpt_path = MODELS_DIR / "cnn_lstm.pt"
        model = CNNLSTMModel()
        if ckpt_path.exists():
            checkpoint = torch.load(ckpt_path, map_location="cpu", weights_only=False)
            model.load_state_dict(checkpoint["model_state_dict"])
            print(f"  [Pipeline] ✓ Loaded trained model from {ckpt_path.name}")
        else:
            print(
                f"  [Pipeline] ⚠️  No trained model found at {ckpt_path}. "
                f"Using untrained model — run training first for accurate predictions."
            )
        model.eval()
        _model_cache["cnn_lstm"] = model
    return _model_cache["cnn_lstm"]


def _run_cnn(model, feature_vector: np.ndarray) -> tuple:
    """
    Run the CNN block on a single turn's feature vector.

    Returns:
        cnn_features: list of floats (CNN_OUTPUT_DIM)
        cnn_local_score: float 0–1 (rough per-turn risk from CNN features)
    """
    tensor = torch.tensor(feature_vector, dtype=torch.float32).unsqueeze(0)  # (1, feat_dim)
    with torch.no_grad():
        cnn_out = model.predict_single_turn(tensor)  # (1, CNN_OUTPUT_DIM)
    cnn_features = cnn_out.squeeze(0).numpy().tolist()
    # Use mean activation magnitude as a rough per-turn CNN score (0–1)
    cnn_local_score = float(np.mean(np.abs(cnn_out.numpy())))
    return cnn_features, cnn_local_score


def _run_lstm(model, session: ActiveSession) -> tuple:
    """
    Run the LSTM on the session's CNN feature buffer.

    Returns:
        probs: [p_normal, p_suspicious, p_high_risk]
        raw_risk_score: float 0–1
    """
    buffer = session.cnn_feature_buffer
    if not buffer:
        # No session context yet — return neutral probs
        return [0.8, 0.15, 0.05], 0.05

    # Build session tensor: (1, T, CNN_OUTPUT_DIM)
    seq = torch.tensor(buffer, dtype=torch.float32).unsqueeze(0)
    with torch.no_grad():
        result = model.predict_from_buffer(seq)

    probs = result["probabilities"].squeeze(0).numpy().tolist()
    raw_risk_score = float(result["risk_score"].item())
    return probs, raw_risk_score


def analyze_message(
    session_id: str,
    message_text: str,
    db,
    true_risk_label: Optional[str] = None,
    use_llm_explanation: bool = True,
) -> Dict[str, Any]:
    """
    Full security analysis pipeline for one user message.

    Args:
        session_id:          Active session ID
        message_text:        The user's raw message text
        db:                  SQLAlchemy database session
        true_risk_label:     Optional ground truth (for evaluation runs)
        use_llm_explanation: Whether to call Groq for LLM explanation

    Returns:
        Complete analysis result dict
    """
    t_start = time.time()

    # ── Get active session ─────────────────────────────────────────────────
    session = session_manager.get_session(session_id)
    if not session:
        raise ValueError(f"Session {session_id} not found.")

    # ── Stage 1: Heuristic pre-check ──────────────────────────────────────
    heuristic_signals = compute_heuristic_signals(message_text)
    heuristic_score, heuristic_level = heuristic_risk_estimate(heuristic_signals)

    # ── Stage 2: Feature extraction ───────────────────────────────────────
    feature_vector, structural_features, _ = build_feature_vector(message_text)

    # ── Stage 3: Load model and run CNN ───────────────────────────────────
    model = _load_model()
    cnn_features, cnn_local_score = _run_cnn(model, feature_vector)

    # Add CNN features to session buffer (before running LSTM)
    session.cnn_feature_buffer.append(cnn_features)
    if len(session.cnn_feature_buffer) > SESSION_WINDOW_SIZE:
        session.cnn_feature_buffer.pop(0)

    # ── Stage 4: LSTM session analysis ────────────────────────────────────
    lstm_probs, _ = _run_lstm(model, session)

    # ── Stage 5: Risk scoring ─────────────────────────────────────────────
    session_signals = session.get_session_signals()
    risk_score, risk_level = compute_risk_score(
        lstm_probs=lstm_probs,
        session_signals=session_signals,
        heuristic_score=heuristic_score,
        cnn_local_score=cnn_local_score,
    )

    # ── Stage 6: AI explanation ───────────────────────────────────────────
    explanation_result = explain(
        risk_level=risk_level,
        risk_score=risk_score,
        session_signals=session_signals,
        heuristic_signals=heuristic_signals,
        structural_features=structural_features,
        use_llm=use_llm_explanation,
    )

    processing_time_ms = (time.time() - t_start) * 1000

    # ── Stage 7: Persist to database ──────────────────────────────────────
    event = session_manager.record_event(
        session_id=session_id,
        message_text=message_text,
        structural_features=structural_features,
        heuristic_signals=heuristic_signals,
        prompt_risk_features={
            "heuristic_score": heuristic_score,
            "heuristic_level": heuristic_level,
            "cnn_local_score": cnn_local_score,
        },
        cnn_local_score=cnn_local_score,
        cnn_features=cnn_features,
        lstm_sequence_probs=lstm_probs,
        risk_score=risk_score,
        risk_level=risk_level,
        explanation=explanation_result["combined"],
        chatbot_response=None,  # Updated after chatbot responds
        processing_time_ms=processing_time_ms,
        db=db,
        true_risk_label=true_risk_label,
    )

    return {
        "event_id": event.id,
        "session_id": session_id,
        "turn_number": event.turn_number,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "lstm_probs": lstm_probs,
        "cnn_local_score": cnn_local_score,
        "heuristic_signals": heuristic_signals,
        "structural_features": structural_features,
        "explanation": explanation_result,
        "session_signals": session.get_session_signals(),
        "processing_time_ms": round(processing_time_ms, 2),
    }
