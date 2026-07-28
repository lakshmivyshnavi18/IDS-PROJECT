"""
database/models.py
─────────────────────────────────────────────────────────────────────────────
SQLAlchemy ORM models for persisting security events and session data.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Text, Boolean,
    DateTime, JSON, ForeignKey, create_engine
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Session(Base):
    """Represents a single user session (multiple turns)."""
    __tablename__ = "sessions"

    session_id = Column(String(64), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    turn_count = Column(Integer, default=0)
    current_risk_level = Column(String(16), default="NORMAL")
    current_risk_score = Column(Float, default=0.0)
    peak_risk_score = Column(Float, default=0.0)
    suspicious_event_count = Column(Integer, default=0)
    high_risk_event_count = Column(Integer, default=0)
    risk_trend = Column(String(16), default="stable")  # stable | increasing | decreasing
    is_active = Column(Boolean, default=True)

    # Relationship to events
    events = relationship("SecurityEvent", back_populates="session", order_by="SecurityEvent.turn_number")

    def to_dict(self):
        return {
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "turn_count": self.turn_count,
            "current_risk_level": self.current_risk_level,
            "current_risk_score": self.current_risk_score,
            "peak_risk_score": self.peak_risk_score,
            "suspicious_event_count": self.suspicious_event_count,
            "high_risk_event_count": self.high_risk_event_count,
            "risk_trend": self.risk_trend,
            "is_active": self.is_active,
        }


class SecurityEvent(Base):
    """Represents a single security analysis event (one turn's analysis)."""
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), ForeignKey("sessions.session_id"), nullable=False)
    turn_number = Column(Integer, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Message data
    message_text = Column(Text, nullable=False)
    message_length = Column(Integer, default=0)

    # Feature signals (stored as JSON for flexibility)
    structural_features = Column(JSON, nullable=True)   # Handcrafted features
    heuristic_signals = Column(JSON, nullable=True)     # Rule-based flags
    prompt_risk_features = Column(JSON, nullable=True)  # Combined prompt features

    # Model outputs
    cnn_local_score = Column(Float, default=0.0)        # CNN per-turn risk signal
    lstm_sequence_probs = Column(JSON, nullable=True)   # LSTM output probabilities

    # Risk assessment
    risk_score = Column(Float, default=0.0)             # 0–100 normalized
    risk_level = Column(String(16), default="NORMAL")   # NORMAL | SUSPICIOUS | HIGH_RISK

    # Explanation
    explanation = Column(Text, nullable=True)

    # Metadata
    is_repeated_attempt = Column(Boolean, default=False)
    preceded_by_refusal = Column(Boolean, default=False)
    processing_time_ms = Column(Float, default=0.0)

    # True label (if known — used during evaluation)
    true_risk_label = Column(String(16), nullable=True)

    # Relationship
    session = relationship("Session", back_populates="events")

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "turn_number": self.turn_number,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "message_text": self.message_text,
            "message_length": self.message_length,
            "structural_features": self.structural_features,
            "heuristic_signals": self.heuristic_signals,
            "prompt_risk_features": self.prompt_risk_features,
            "cnn_local_score": self.cnn_local_score,
            "lstm_sequence_probs": self.lstm_sequence_probs,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "explanation": self.explanation,
            "is_repeated_attempt": self.is_repeated_attempt,
            "preceded_by_refusal": self.preceded_by_refusal,
            "processing_time_ms": self.processing_time_ms,
        }
