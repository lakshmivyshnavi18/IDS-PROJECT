"""
api/schemas.py  —  Pydantic request/response models for FastAPI.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


# ── Request Models ────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    session_id: Optional[str] = Field(None, description="Existing session ID (None = create new)")
    message: str = Field(..., min_length=1, max_length=4000, description="User message")
    use_mock: bool = Field(False, description="Use mock chatbot (no API call) for offline testing")
    true_risk_label: Optional[str] = Field(None, description="Ground truth label for evaluation")


class NewSessionRequest(BaseModel):
    pass


# ── Response Models ───────────────────────────────────────────────────────────

class SecurityAnalysis(BaseModel):
    event_id: int
    turn_number: int
    risk_score: float
    risk_level: str
    lstm_probs: List[float]
    cnn_local_score: float
    heuristic_signals: Dict[str, float]
    explanation_template: str
    explanation_llm: str
    explanation_combined: str
    processing_time_ms: float


class SessionStatus(BaseModel):
    session_id: str
    turn_count: int
    current_risk_level: str
    current_risk_score: float
    peak_risk_score: float
    suspicious_event_count: int
    high_risk_event_count: int
    risk_trend: str
    risk_history: List[float]


class ChatResponse(BaseModel):
    session_id: str
    chatbot_response: str
    security: SecurityAnalysis
    session_status: SessionStatus


class SessionCreateResponse(BaseModel):
    session_id: str
    message: str


class EventRecord(BaseModel):
    id: int
    session_id: str
    turn_number: int
    timestamp: Optional[str]
    message_text: str
    risk_score: float
    risk_level: str
    explanation: Optional[str]
    processing_time_ms: float


class MetricsSummary(BaseModel):
    total_sessions: int
    total_events: int
    normal_count: int
    suspicious_count: int
    high_risk_count: int
    avg_risk_score: float
    detection_rate: float
