"""
security/heuristic_filter.py
─────────────────────────────────────────────────────────────────────────────
Layer 1: Fast heuristic safety filter.

DESIGN RATIONALE:
  This is NOT the core security component — it is a fast pre-screening
  layer that produces 5 numeric signals used as INPUT FEATURES to the
  CNN+LSTM model. The deep learning model makes the final decision;
  heuristics only provide lightweight auxiliary signals.

  This avoids the anti-pattern of pure keyword matching while still
  capturing obvious structural signals that complement semantic embeddings.

Heuristic Signals (5-dimensional vector):
  1. override_signal:     Explicit instruction-override language detected
  2. probe_signal:        System prompt or credential probing language
  3. role_signal:         Alternative persona / role-change requests
  4. persistence_signal:  Post-refusal persistence language
  5. urgency_signal:      Pressuring or urgency language
"""

import re
from typing import Dict, Tuple

# ── Heuristic Pattern Groups ──────────────────────────────────────────────────
# Each pattern group returns a SCORE (0.0–1.0), not a binary flag.
# Score reflects how strongly the signal is present.

OVERRIDE_PATTERNS = [
    r"\bignore\b.*\b(instructions?|guidelines?|rules?|previous|restrictions?)\b",
    r"\bforget\b.*\b(instructions?|you were told|rules?|guidelines?)\b",
    r"\bbypass\b.*\b(safety|restrictions?|filters?|guidelines?)\b",
    r"\boverride\b.*\b(policy|guidelines?|restrictions?|instructions?)\b",
    r"\bno restrictions?\b",
    r"\bwithout\b.*\b(restrictions?|limitations?|filters?|safety)\b",
    r"\bdisregard\b.*\b(guidelines?|instructions?|previous)\b",
    r"\bact as if\b.*\b(no|without|removed|disabled)\b",
    r"\bpretend\b.*\b(no rules?|no restrictions?|guidelines? (don't|do not) apply)\b",
    r"\byour (rules?|guidelines?|restrictions?|instructions?) (are|have been) (void|removed|lifted|disabled)\b",
]

PROBE_PATTERNS = [
    r"\bsystem prompt\b",
    r"\bhidden instructions?\b",
    r"\bwhat were you (told|instructed|given|trained)\b",
    r"\bshow me your (instructions?|context|prompt|configuration)\b",
    r"\breveal.*\b(instructions?|secrets?|credentials?|api key|password|tokens?)\b",
    r"\brepeat.*\b(your instructions?|system message|context)\b",
    r"\bwhat (topics?|things?|subjects?) are you (not allowed|prohibited|restricted)\b",
    r"\bapi key\b",
    r"\bpassword\b.*\b(stored?|embedded?|access)\b",
    r"\bcredentials?\b",
    r"\bsecret\b.*\b(information|data|access)\b",
    r"\binternal (endpoints?|configuration|data)\b",
]

ROLE_PATTERNS = [
    r"\bdan mode\b",
    r"\bjailbreak(ed)?\b",
    r"\bdo anything now\b",
    r"\bdeveloper mode\b",
    r"\bunrestricted (ai|version|mode)\b",
    r"\bno (content )?(filter|policy|restrictions?)\b",
    r"\bevil (version|ai|persona)\b",
    r"\byou are now\b.*\b(different|another|unrestricted|without)\b",
    r"\bpretend (you are|you're) (a )?different\b",
    r"\badopt (a )?persona\b.*\b(no|without|doesn't have)\b",
    r"\bsimulate (being )?(an )?ai\b.*\b(no|without|different)\b",
]

PERSISTENCE_PATTERNS = [
    r"\byou already refused\b",
    r"\bi know you can\b",
    r"\btry (harder|again|once more|differently)\b",
    r"\brephrase.*\b(bypass|avoid|get around)\b",
    r"\byour refusal was (wrong|incorrect|unnecessary)\b",
    r"\bstop (pretending|acting) (like )?you can't\b",
    r"\bjust (this once|ignore|answer|do it)\b",
    r"\bkeep trying\b",
    r"\bi'll ask (again|differently|in a different way)\b",
    r"\byou're being too (cautious|careful|restrictive)\b",
]

URGENCY_PATTERNS = [
    r"\byou (must|have to|need to|are required to)\b",
    r"\bthis is (urgent|an emergency|critical|very important)\b",
    r"\bi (demand|require|insist|need) you to\b",
    r"\bdo it now\b",
    r"\bnow\b.*\bimmediately\b",
    r"\bno (choice|option|alternative)\b",
]

ALL_PATTERN_GROUPS = [
    ("override_signal", OVERRIDE_PATTERNS),
    ("probe_signal", PROBE_PATTERNS),
    ("role_signal", ROLE_PATTERNS),
    ("persistence_signal", PERSISTENCE_PATTERNS),
    ("urgency_signal", URGENCY_PATTERNS),
]


def _compute_signal(text: str, patterns: list) -> float:
    """
    Compute a [0.0, 1.0] signal score for a pattern group.

    Uses multi-pattern matching: more matches → higher score (capped at 1.0).
    """
    matches = 0
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            matches += 1
    # Sigmoid-like scaling: 1 match=0.5, 2 matches=0.75, 3+=1.0
    if matches == 0:
        return 0.0
    elif matches == 1:
        return 0.5
    elif matches == 2:
        return 0.75
    else:
        return 1.0


def compute_heuristic_signals(text: str) -> Dict[str, float]:
    """
    Compute all 5 heuristic signals for a given text.

    Returns a dict with keys:
      override_signal, probe_signal, role_signal,
      persistence_signal, urgency_signal
    """
    return {
        name: _compute_signal(text, patterns)
        for name, patterns in ALL_PATTERN_GROUPS
    }


def heuristic_risk_estimate(signals: Dict[str, float]) -> Tuple[float, str]:
    """
    Produce a quick heuristic-only risk estimate from the signal dict.

    This is used as a FAST pre-check and as an auxiliary input to the
    CNN. The CNN+LSTM model overrides this estimate for the final decision.

    Returns:
        (raw_score, level): score in [0, 100], level in NORMAL/SUSPICIOUS/HIGH_RISK
    """
    # Weighted combination
    weights = {
        "override_signal": 25.0,
        "probe_signal": 25.0,
        "role_signal": 20.0,
        "persistence_signal": 20.0,
        "urgency_signal": 10.0,
    }
    raw = sum(signals[k] * weights[k] for k in weights)
    score = min(raw, 100.0)

    if score >= 60:
        level = "HIGH_RISK"
    elif score >= 20:
        level = "SUSPICIOUS"
    else:
        level = "NORMAL"

    return score, level


def signals_to_vector(signals: Dict[str, float]) -> list:
    """Convert signals dict to ordered list for feature vector construction."""
    keys = ["override_signal", "probe_signal", "role_signal",
            "persistence_signal", "urgency_signal"]
    return [signals[k] for k in keys]
