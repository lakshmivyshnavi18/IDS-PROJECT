"""
security/feature_extractor.py
─────────────────────────────────────────────────────────────────────────────
Phase 5: Converts raw text into the full feature vector used by CNN.

Feature Vector (total: 404 dimensions):
  [0:384]    — Sentence embedding (semantic meaning)
  [384:399]  — Structural features (15 handcrafted signals)
  [399:404]  — Heuristic signals (5 safety signals)

Why not just use the embedding?
  Structural features capture properties the embedding may not emphasize:
  excessive punctuation, very short/long prompts, URL presence, etc.
  Heuristic signals provide explicit safety-relevant features that anchor
  the CNN to security-relevant patterns.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import re
import numpy as np
from typing import Dict, Tuple

from models.embeddings.embedding_engine import embed
from security.heuristic_filter import compute_heuristic_signals, signals_to_vector
from config import EMBEDDING_DIM, STRUCTURAL_FEATURE_DIM, HEURISTIC_FEATURE_DIM, TOTAL_FEATURE_DIM


def extract_structural_features(text: str) -> Dict[str, float]:
    """
    Extract 15 structural/statistical features from raw text.

    These features capture prompt properties that are NOT well captured
    by semantic embeddings but are relevant to security classification.
    """
    words = text.split()
    sentences = re.split(r'[.!?]+', text)
    sentences = [s.strip() for s in sentences if s.strip()]

    features = {
        # Length features
        "char_count": min(len(text) / 1000.0, 1.0),            # Normalized char count
        "word_count": min(len(words) / 200.0, 1.0),            # Normalized word count
        "sentence_count": min(len(sentences) / 20.0, 1.0),     # Normalized sentence count
        "avg_word_length": min(
            (sum(len(w) for w in words) / max(len(words), 1)) / 15.0, 1.0
        ),

        # Punctuation features (aggressive punctuation can indicate manipulation)
        "exclamation_count": min(text.count("!") / 5.0, 1.0),
        "question_count": min(text.count("?") / 5.0, 1.0),
        "ellipsis_count": min(text.count("...") / 3.0, 1.0),

        # Structural features
        "has_url": 1.0 if re.search(r'https?://|www\.', text) else 0.0,
        "has_code_block": 1.0 if re.search(r'```|`[^`]+`', text) else 0.0,
        "has_brackets": 1.0 if re.search(r'\[.*?\]|\{.*?\}', text) else 0.0,
        "has_quotes": 1.0 if re.search(r'".*?"|\'.*?\'', text) else 0.0,

        # Caps ratio (all-caps words can indicate pressure/urgency)
        "caps_ratio": (
            sum(1 for w in words if w.isupper() and len(w) > 2) / max(len(words), 1)
        ),

        # Instruction-like patterns
        "starts_with_imperative": 1.0 if (
            words and words[0].lower() in [
                "ignore", "forget", "pretend", "act", "roleplay", "simulate",
                "become", "you", "tell", "reveal", "show", "give", "provide",
                "stop", "disregard", "override"
            ]
        ) else 0.0,

        # Politeness markers (benign users tend to use more polite language)
        "has_please": 1.0 if "please" in text.lower() else 0.0,
        "has_thank": 1.0 if ("thank" in text.lower() or "thanks" in text.lower()) else 0.0,
    }

    assert len(features) == STRUCTURAL_FEATURE_DIM, (
        f"Expected {STRUCTURAL_FEATURE_DIM} structural features, got {len(features)}"
    )
    return features


def structural_features_to_vector(features: Dict[str, float]) -> list:
    """Convert structural features dict to ordered list."""
    ordered_keys = [
        "char_count", "word_count", "sentence_count", "avg_word_length",
        "exclamation_count", "question_count", "ellipsis_count",
        "has_url", "has_code_block", "has_brackets", "has_quotes",
        "caps_ratio", "starts_with_imperative", "has_please", "has_thank",
    ]
    return [features[k] for k in ordered_keys]


def build_feature_vector(text: str) -> Tuple[np.ndarray, Dict, Dict]:
    """
    Build the complete 404-dimensional feature vector for a single message.

    Pipeline:
      text → embedding (384) + structural (15) + heuristic (5) = 404 dims

    Returns:
        feature_vector: np.ndarray of shape (404,)
        structural_features: dict of named structural features
        heuristic_signals: dict of named heuristic signals
    """
    # 1. Semantic embedding (384-dim)
    embedding = embed(text)  # shape: (384,)

    # 2. Structural features (15-dim)
    structural_features = extract_structural_features(text)
    structural_vec = structural_features_to_vector(structural_features)

    # 3. Heuristic signals (5-dim)
    heuristic_signals = compute_heuristic_signals(text)
    heuristic_vec = signals_to_vector(heuristic_signals)

    # 4. Concatenate into full feature vector
    feature_vector = np.concatenate([
        embedding,
        np.array(structural_vec, dtype=np.float32),
        np.array(heuristic_vec, dtype=np.float32),
    ]).astype(np.float32)

    assert feature_vector.shape[0] == TOTAL_FEATURE_DIM, (
        f"Feature vector dim mismatch: {feature_vector.shape[0]} != {TOTAL_FEATURE_DIM}"
    )

    return feature_vector, structural_features, heuristic_signals


def build_session_feature_matrix(texts: list) -> np.ndarray:
    """
    Build feature matrix for a session (multiple turns).
    Returns shape: (num_turns, TOTAL_FEATURE_DIM)
    """
    vectors = []
    for text in texts:
        vec, _, _ = build_feature_vector(text)
        vectors.append(vec)
    return np.stack(vectors, axis=0)
