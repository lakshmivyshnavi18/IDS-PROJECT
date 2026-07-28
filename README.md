# 🛡️ Intelligent Security Monitoring for LLM Applications Using CNN-LSTM and Generative AI

> A research-grade AI security system that monitors **user behavioral sequences** interacting with LLM applications to detect suspicious, manipulative, or potentially harmful interaction patterns.

---

## 📋 Table of Contents

1. [Problem Statement](#problem-statement)
2. [Motivation & Research Gap](#motivation--research-gap)
3. [Proposed Solution](#proposed-solution)
4. [System Architecture](#system-architecture)
5. [CNN Role](#cnn-role)
6. [LSTM Role](#lstm-role)
7. [AI Explanation System](#ai-explanation-system)
8. [Dataset](#dataset)
9. [Evaluation Metrics](#evaluation-metrics)
10. [Quick Start](#quick-start)
11. [Project Structure](#project-structure)
12. [Development Workflow](#development-workflow)
13. [Research Contribution](#research-contribution)
14. [Limitations](#limitations)
15. [Future Work](#future-work)

---

## Problem Statement

Existing LLM applications focus on generating useful responses but lack mechanisms to analyze the **behavioral sequence** of users interacting with the AI system. A single message may appear harmless, while a sequence of messages may reveal:

- Repeated attempts to override system behavior
- Gradual manipulation toward extracting restricted information
- Persistent jailbreak attempts after refusals
- Multi-step social engineering campaigns

**This project builds an intelligent security monitoring system that analyzes both individual prompts AND temporal session behavior to identify suspicious LLM interaction patterns.**

---

## Motivation & Research Gap

| Existing Approach | Limitation |
|---|---|
| Network IDS (Snort, Suricata) | Monitor packets, not LLM interaction semantics |
| Single-turn content filters | No session context; each message judged in isolation |
| RLHF / Safety fine-tuning | Input filters; no behavioral sequence modeling |
| Keyword blacklists | Trivially bypassed; not research-grade |

**Our gap:** No existing system combines prompt-level feature extraction with temporal session-level behavioral analysis for LLM security monitoring.

---

## Proposed Solution

A layered security architecture with 6 components:

```
USER MESSAGE
    ↓
[Layer 1] Heuristic Safety Filter (fast pre-check)
    ↓
[Layer 2] Feature Extraction (384-dim embedding + 15 structural + 5 heuristic = 404-dim)
    ↓
[Layer 3] 1D-CNN (local pattern extraction per turn)
    ↓
[Layer 4] LSTM (temporal session-level behavioral analysis)
    ↓
[Layer 5] Risk Scorer (0–100 score, 3-class label: NORMAL/SUSPICIOUS/HIGH_RISK)
    ↓
[Layer 6] Explainable AI (human-readable analyst report)
    ↓
CHATBOT RESPONSE (risk-aware)
```

---

## System Architecture

### Risk Classification

| Score | Level | Description |
|---|---|---|
| 0 – 30 | 🟢 NORMAL | Normal interaction patterns |
| 31 – 70 | 🟡 SUSPICIOUS | Possible probing or testing |
| 71 – 100 | 🔴 HIGH RISK | Active manipulation attempt detected |

### Key Design Principle

> A single unusual question does NOT automatically trigger HIGH_RISK. The system weighs single-turn signals against session-level behavioral context. Repeated suspicious behavior across a session amplifies the risk score.

---

## CNN Role

**What:** 1D Convolutional Neural Network applied to the 404-dimensional feature vector of each individual prompt.

**Why CNN:**
The per-turn feature vector contains both semantic embedding dimensions and handcrafted structural/heuristic features. When viewed as a 1D sequence, convolutional filters learn to detect **local co-activation patterns** — clusters of features that appear together in suspicious prompts. For example:
- High embedding dimensions corresponding to "override" semantics + high structural urgency + elevated heuristic signals
- The CNN learns these patterns from labeled training data — it does NOT use hardcoded rules

**Architecture:**
```
Input: (1, 404)
  ↓ Conv1D(64, k=7) → BatchNorm → ReLU
  ↓ Conv1D(128, k=5) → BatchNorm → ReLU → MaxPool
  ↓ Conv1D(64, k=3) → BatchNorm → ReLU
  ↓ GlobalAvgPool
Output: (64,) — CNN feature map for this turn
```

**CNN answers:** *"What kind of prompt is THIS message?"*

---

## LSTM Role

**What:** Long Short-Term Memory network that processes the sequence of CNN feature maps across all turns in the session.

**Why LSTM:**
A single suspicious turn may be a false positive (a curious user asking an unusual question). But a **sequence** of suspicious turns reveals behavioral intent. The LSTM:
- Maintains hidden state across turns
- Tracks how the CNN feature maps evolve over time
- Learns to recognize patterns like: `normal → suspicious → high_risk → persistence`
- Enables the system to detect that risk is *increasing* — not just that a current message is suspicious

**Architecture:**
```
Input: (batch, T, 64)  — T turns, each with CNN feature map
  ↓ LSTM(128 units, 2 layers, dropout=0.3)
  ↓ Last hidden state (128,)
  ↓ Dense(64) → ReLU → Dropout
  ↓ Dense(3) → Softmax
Output: [p_normal, p_suspicious, p_high_risk]
```

**LSTM answers:** *"How has the user's behavior EVOLVED over this session?"*

---

## AI Explanation System

### Two-Tier Design

**Tier 1 — Template (always available):**
Deterministic, signal-grounded explanations assembled from the actual model signals. No API needed.

**Tier 2 — LLM-enhanced (Groq / Llama 3.3 70B):**
The signal dictionary is passed to Llama 3.3 70B with an analyst persona prompt to generate fluent, contextual security reports.

### Example Output

```
Risk Assessment: 🚨 HIGH RISK
Risk Score: 86/100

Contributing Factors:
  ✗ Multiple high-risk events detected (2 turns flagged as HIGH RISK)
  ✗ Repeated suspicious behavior across 4 turns
  ✗ Suspicious behavior continued after a refusal response (persistence signal)
  ✗ Risk is increasing across the session (Δ score: +42)
  ✗ Instruction-override language detected
  ✗ Post-refusal persistence language detected

Behavioral Trend: Increasing

This session has been classified as HIGH RISK. The behavioral pattern is
consistent with deliberate manipulation attempts.
```

---

## Dataset

### Why Custom?

Public datasets (AdvBench, JailbreakBench, HarmBench) contain only **single-turn** jailbreak prompts. They lack:
- Multi-turn sessions with turn-level risk labels
- Gradual escalation patterns
- "Benign unusual" examples (critical for false-positive testing)
- Session-level risk annotations

### Structure

| Split | Sessions | ~Turns |
|---|---|---|
| Train | 1,200 | 7,000 |
| Validation | 300 | 1,750 |
| Test | 300 | 1,750 |
| **Total** | **1,800** | **~10,500** |

### Session Patterns

| Pattern | Description | Session Risk |
|---|---|---|
| clean_session | All NORMAL turns | NORMAL |
| benign_unusual_session | Unusual but legitimate queries | NORMAL |
| single_anomaly | 1 suspicious turn in clean session | SUSPICIOUS |
| late_escalation | Normal tail → suspicious ending | SUSPICIOUS |
| gradual_attack | Normal → suspicious → HIGH_RISK | HIGH_RISK |
| credential_hunt | Credential extraction sequence | HIGH_RISK |
| persistent_jailbreak | Override → refusal → persistence | HIGH_RISK |
| role_escalation_session | Full persona-change arc | HIGH_RISK |

### Data Leakage Prevention

Sessions are split at the **session level** — no single session's turns appear in multiple splits. This prevents the LSTM from seeing partial behavioral sequences during training that appear in test.

---

## Evaluation Metrics

| Metric | Description |
|---|---|
| Accuracy | Overall correct classifications |
| Macro F1 | Unweighted F1 across all 3 classes |
| Weighted F1 | Class-frequency-weighted F1 |
| Macro Precision | Unweighted precision |
| Macro Recall | Unweighted recall |
| False Positive Rate | Normal users wrongly flagged |
| False Negative Rate | HIGH_RISK sessions missed |
| Detection Latency | Turns until first HIGH_RISK detection |
| Processing Latency | ms per turn (including embedding + model) |

---

## Quick Start

### 1. Prerequisites
```bash
# Python 3.9+
pip install -r requirements.txt
```

### 2. Configure API Key
```bash
copy .env.example .env
# Edit .env and add your Groq API key
# Get free key at: https://console.groq.com
```

### 3. Generate Dataset
```bash
python data/generation/dataset_generator.py
```

### 4. Train Model
```bash
python models/cnn_lstm/trainer.py cnn_lstm
```

### 5. Launch System
```bash
python start.py
```
Or manually:
```bash
# Terminal 1 — API
uvicorn api.main:app --reload --port 8000

# Terminal 2 — Dashboard
streamlit run dashboard/app.py
```

### 6. Access
- **Dashboard:** http://localhost:8501
- **API:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs

### 7. Run Tests
```bash
python testing/run_tests.py --mode all --save
```

### 8. Run Ablation Study
```bash
python experiments/ablation_study.py --all
```

---

## Project Structure

```
ids_project/
├── config.py                    # Central configuration
├── start.py                     # One-command launcher
├── requirements.txt
├── .env                         # API keys (never commit)
│
├── data/generation/
│   └── dataset_generator.py     # Reproducible dataset creator
│
├── models/
│   ├── embeddings/
│   │   └── embedding_engine.py  # SentenceTransformer wrapper
│   └── cnn_lstm/
│       ├── architecture.py      # CNN-Only, LSTM-Only, CNN+LSTM
│       ├── trainer.py           # Training pipeline
│       └── evaluator.py         # Metrics + ablation
│
├── security/
│   ├── heuristic_filter.py      # Layer 1: fast pre-check (5 signals)
│   ├── feature_extractor.py     # 404-dim feature vector builder
│   ├── session_manager.py       # Session tracking + event buffer
│   ├── risk_scorer.py           # Multi-signal risk scorer
│   ├── explainer.py             # Two-tier AI explanation
│   └── pipeline.py              # Central orchestration
│
├── chatbot/
│   ├── system_prompt.py         # Chatbot policy
│   └── chatbot_engine.py        # Groq-powered chatbot
│
├── api/
│   ├── main.py                  # FastAPI application
│   └── schemas.py               # Pydantic models
│
├── dashboard/
│   └── app.py                   # Streamlit dashboard
│
├── database/
│   ├── models.py                # SQLAlchemy ORM
│   └── db.py                    # DB connection
│
├── testing/
│   ├── run_tests.py             # Test runner
│   └── scenarios/               # Safe test definitions
│
└── experiments/
    ├── ablation_study.py        # Ablation experiments
    └── visualizations/          # Result charts
```

---

## Research Contribution

> **"Unlike systems that analyze user prompts independently, this project combines prompt-level local feature extraction using CNN with sequential session-level behavioral analysis using LSTM. This enables the system to consider not only what the user asks, but also how the user's interaction behavior evolves over time — enabling detection of multi-turn manipulation campaigns that would be invisible to single-turn analyzers."**

### Ablation Study Research Question

*"Does combining CNN's local prompt-pattern extraction with LSTM's temporal session modeling outperform either component alone at detecting suspicious LLM interaction sequences?"*

---

## Limitations

1. **Synthetic dataset** — Real-world LLM interaction data with security labels is not publicly available. The synthetic dataset may not capture all real-world attack variations.
2. **English only** — The embedding model and prompt banks are English-language focused.
3. **Fixed session window** — Sessions longer than 10 turns use only the most recent 10 (rolling window).
4. **No adversarial robustness testing** — Attackers who know the system could craft inputs that avoid detection.
5. **API dependency** — Tier 2 explanations require Groq API access.

---

## Future Work

- [ ] Collect real-world labeled multi-turn LLM interaction data
- [ ] Add bidirectional LSTM or Transformer-based temporal modeling
- [ ] Implement adversarial robustness testing
- [ ] Add user-level risk profiling across multiple sessions
- [ ] Extend to multi-language support
- [ ] Add SHAP-based feature attribution visualization in dashboard
- [ ] Explore federated learning for privacy-preserving training
- [ ] Real-time alerting system (email/Slack notifications for HIGH_RISK)

---

## Technology Stack

| Component | Technology |
|---|---|
| LLM Backend | Groq API (Llama 3.3 70B) |
| ML Framework | PyTorch |
| Embeddings | SentenceTransformers (all-MiniLM-L6-v2) |
| API Backend | FastAPI + Uvicorn |
| Dashboard | Streamlit + Plotly |
| Database | SQLite (SQLAlchemy ORM) |
| Explainability | Template + LLM (Groq) |

---

## License

This project is for academic and research purposes.

---

*Research Project — AI/Cybersecurity — CNN-LSTM Behavioral Analysis for LLM Security*
