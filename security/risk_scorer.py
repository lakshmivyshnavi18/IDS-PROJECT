"""
security/risk_scorer.py
─────────────────────────────────────────────────────────────────────────────
Computes the final 0–100 risk score by fusing multiple signals:

  1. LSTM model probability output (primary signal)
  2. Session-level behavioral signals (amplifiers/dampeners)
  3. Heuristic safety signals (auxiliary support)

DESIGN PRINCIPLE:
  A single suspicious message should NOT immediately result in HIGH_RISK.
  The risk scorer weighs the model's prediction against session context:
  - Repeated suspicious behavior amplifies the score
  - A single anomaly in an otherwise clean session is dampened
  - Post-refusal persistence is a strong amplifier
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from typing import Dict, List, Optional, Tuple
from config import RISK_CLASSES, RISK_THRESHOLDS


def compute_risk_score(
    lstm_probs: List[float],           # [p_normal, p_suspicious, p_high_risk]
    session_signals: Dict,             # From ActiveSession.get_session_signals()
    heuristic_score: float,            # 0–100 heuristic estimate
    cnn_local_score: float,            # 0–1 CNN per-turn risk signal
) -> Tuple[float, str]:
    """
    Compute the final risk score (0–100) and risk level.

    Returns:
        (risk_score, risk_level): float in [0,100], str in RISK_CLASSES
    """
    p_normal = lstm_probs[0]
    p_suspicious = lstm_probs[1]
    p_high_risk = lstm_probs[2]

    # ── Base score from LSTM probabilities ────────────────────────────────────
    # Map probabilities to 0–100 range with weighted classes
    base_score = (p_suspicious * 45.0) + (p_high_risk * 100.0)
    base_score = min(base_score, 100.0)

    # ── Heuristic anchor (weighted lightly) ───────────────────────────────────
    heuristic_contribution = heuristic_score * 0.1

    # ── CNN local signal ──────────────────────────────────────────────────────
    cnn_contribution = cnn_local_score * 15.0  # CNN on current turn

    # ── Session-level amplifiers ──────────────────────────────────────────────
    amplifier = 0.0

    # Repeated suspicious behavior (strongest amplifier)
    susp_count = session_signals.get("suspicious_event_count", 0)
    if susp_count >= 3:
        amplifier += 20.0
    elif susp_count == 2:
        amplifier += 10.0
    elif susp_count == 1:
        amplifier += 5.0

    # Post-refusal persistence (very strong amplifier)
    if session_signals.get("preceded_by_refusal", False):
        amplifier += 15.0

    # Increasing risk trend
    if session_signals.get("risk_trend") == "increasing":
        amplifier += 8.0

    # Large risk delta (score jumped a lot)
    risk_delta = session_signals.get("risk_delta", 0.0)
    if risk_delta > 30:
        amplifier += 10.0

    # ── Session dampener for single anomaly in clean session ──────────────────
    # If total turns is > 3 but only 1 suspicious event and score isn't already high
    dampener = 0.0
    turn_count = session_signals.get("turn_count", 1)
    if (
        susp_count <= 1
        and turn_count >= 4
        and base_score < 50
    ):
        dampener = 10.0  # Reduce by 10 — single anomaly in clean session

    # ── Final score computation ───────────────────────────────────────────────
    raw_score = (
        base_score * 0.70           # LSTM probability is the primary driver
        + heuristic_contribution    # Light heuristic anchor
        + cnn_contribution          # CNN turn-level signal
        + amplifier                 # Session amplifiers
        - dampener                  # Single-anomaly dampener
    )
    final_score = max(0.0, min(100.0, raw_score))

    # ── Risk level classification ─────────────────────────────────────────────
    if final_score <= RISK_THRESHOLDS["NORMAL"][1]:
        level = "NORMAL"
    elif final_score <= RISK_THRESHOLDS["SUSPICIOUS"][1]:
        level = "SUSPICIOUS"
    else:
        level = "HIGH_RISK"

    return round(final_score, 2), level


def score_to_level(score: float) -> str:
    """Convert a 0–100 score to a risk level string."""
    if score <= 30:
        return "NORMAL"
    elif score <= 70:
        return "SUSPICIOUS"
    else:
        return "HIGH_RISK"


def get_risk_color(risk_level: str) -> str:
    """Return a color hex code for UI display."""
    colors = {
        "NORMAL": "#22c55e",      # Green
        "SUSPICIOUS": "#f59e0b",  # Amber
        "HIGH_RISK": "#ef4444",   # Red
    }
    return colors.get(risk_level, "#6b7280")


def get_risk_emoji(risk_level: str) -> str:
    """Return an emoji for compact display."""
    return {"NORMAL": "🟢", "SUSPICIOUS": "🟡", "HIGH_RISK": "🔴"}.get(risk_level, "⚪")
