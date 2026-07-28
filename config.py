# ============================================================
# config.py — Central Configuration for LLM Security Monitor
# ============================================================

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Project Paths ────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models" / "cnn_lstm" / "saved"
DB_PATH = BASE_DIR / "database" / "llm_security.db"

# ── Groq LLM Configuration ───────────────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_CHAT_MODEL = "llama-3.3-70b-versatile"        # Main chatbot model
GROQ_EXPLAIN_MODEL = "llama-3.3-70b-versatile"     # Explanation model
GROQ_MAX_TOKENS = 512
GROQ_TEMPERATURE = 0.7

# ── Embedding Configuration ───────────────────────────────────
EMBEDDING_MODEL = "all-MiniLM-L6-v2"   # 384-dim, fast, free
EMBEDDING_DIM = 384

# ── Feature Engineering ───────────────────────────────────────
STRUCTURAL_FEATURE_DIM = 15            # Handcrafted structural features
HEURISTIC_FEATURE_DIM = 5              # Rule-based safety signals
TOTAL_FEATURE_DIM = EMBEDDING_DIM + STRUCTURAL_FEATURE_DIM + HEURISTIC_FEATURE_DIM  # 404

# ── CNN Configuration ─────────────────────────────────────────
CNN_OUTPUT_DIM = 64                    # Output size of CNN feature map

# ── LSTM Configuration ────────────────────────────────────────
LSTM_HIDDEN_DIM = 128
LSTM_NUM_LAYERS = 2
LSTM_DROPOUT = 0.3
SESSION_WINDOW_SIZE = 10               # Max turns kept in session buffer

# ── Risk Classification ───────────────────────────────────────
RISK_CLASSES = ["NORMAL", "SUSPICIOUS", "HIGH_RISK"]
RISK_THRESHOLDS = {
    "NORMAL": (0, 30),
    "SUSPICIOUS": (31, 70),
    "HIGH_RISK": (71, 100),
}

# ── Dataset Configuration ─────────────────────────────────────
DATASET_SEED = 42
TOTAL_SESSIONS = 1800
TRAIN_RATIO = 0.667      # ~1200 sessions
VAL_RATIO = 0.167        # ~300 sessions
TEST_RATIO = 0.167       # ~300 sessions

# ── Model Training ─────────────────────────────────────────────
BATCH_SIZE = 32
LEARNING_RATE = 1e-3
WEIGHT_DECAY = 1e-4
NUM_EPOCHS = 50
EARLY_STOPPING_PATIENCE = 7

# ── API Configuration ─────────────────────────────────────────
API_HOST = "0.0.0.0"
API_PORT = 8000

# ── Dashboard Configuration ───────────────────────────────────
DASHBOARD_PORT = 8501
API_BASE_URL = f"http://localhost:{API_PORT}"

# ── Logging ───────────────────────────────────────────────────
LOG_LEVEL = "INFO"
