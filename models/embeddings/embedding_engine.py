"""
models/embeddings/embedding_engine.py
─────────────────────────────────────────────────────────────────────────────
Singleton wrapper around SentenceTransformer for text embedding.

Uses 'all-MiniLM-L6-v2' (384-dim) — fast, lightweight, and produces
semantically meaningful embeddings suitable for security classification.

The model is loaded ONCE and cached for the life of the process.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import numpy as np
from typing import List, Union
from config import EMBEDDING_MODEL, EMBEDDING_DIM

# Lazy import — loaded on first use to avoid startup delay
_model = None


def _get_model():
    """Lazy-load the embedding model (singleton)."""
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        print(f"  [EmbeddingEngine] Loading model: {EMBEDDING_MODEL} ...")
        _model = SentenceTransformer(EMBEDDING_MODEL)
        print(f"  [EmbeddingEngine] ✓ Loaded. Embedding dim: {EMBEDDING_DIM}")
    return _model


def embed(text: Union[str, List[str]]) -> np.ndarray:
    """
    Embed one or more texts into dense vectors.

    Args:
        text: Single string or list of strings

    Returns:
        numpy array of shape (embedding_dim,) for a single string,
        or (N, embedding_dim) for a list of N strings.
    """
    model = _get_model()
    single = isinstance(text, str)
    texts = [text] if single else text

    embeddings = model.encode(
        texts,
        normalize_embeddings=True,   # L2-normalize for cosine similarity stability
        show_progress_bar=False,
        batch_size=32,
    )

    return embeddings[0] if single else embeddings


def embed_batch(texts: List[str]) -> np.ndarray:
    """Embed a batch of texts. Returns (N, embedding_dim) array."""
    return embed(texts)
