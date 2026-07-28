"""
security/session_manager.py
─────────────────────────────────────────────────────────────────────────────
Manages active user sessions:
  - Creates and tracks sessions
  - Maintains a rolling event buffer for LSTM input
  - Computes session-level statistics (trend, peak risk, etc.)
  - Persists SecurityEvent records to the database

The session_manager is the central state machine of the security pipeline.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from sqlalchemy.orm import Session as DBSession

from database.models import Session as SessionModel, SecurityEvent
from config import SESSION_WINDOW_SIZE


class ActiveSession:
    """
    In-memory representation of an active user session.
    Maintains the rolling CNN feature buffer for LSTM input.
    """

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.created_at = datetime.utcnow()
        self.turn_count = 0
        self.current_risk_level = "NORMAL"
        self.current_risk_score = 0.0
        self.peak_risk_score = 0.0
        self.suspicious_event_count = 0
        self.high_risk_event_count = 0
        self.risk_history: List[float] = []           # Per-turn risk scores
        self.cnn_feature_buffer: List[List[float]] = []  # Rolling CNN features for LSTM
        self.conversation_history: List[Dict] = []    # For chatbot context
        self.last_risk_level: Optional[str] = None
        self.preceded_by_refusal = False

    def update(
        self,
        risk_score: float,
        risk_level: str,
        cnn_features: Optional[List[float]] = None,
        chatbot_response: Optional[str] = None,
        user_message: Optional[str] = None,
    ):
        """Update session state after processing a new turn."""
        self.turn_count += 1
        self.risk_history.append(risk_score)
        self.current_risk_score = risk_score
        self.current_risk_level = risk_level

        if risk_score > self.peak_risk_score:
            self.peak_risk_score = risk_score

        if risk_level == "SUSPICIOUS":
            self.suspicious_event_count += 1
        elif risk_level == "HIGH_RISK":
            self.high_risk_event_count += 1
            self.suspicious_event_count += 1

        # Update CNN feature buffer (rolling window)
        if cnn_features is not None:
            self.cnn_feature_buffer.append(cnn_features)
            if len(self.cnn_feature_buffer) > SESSION_WINDOW_SIZE:
                self.cnn_feature_buffer.pop(0)

        # Update conversation history for chatbot context
        if user_message:
            self.conversation_history.append({
                "role": "user", "content": user_message
            })
        if chatbot_response:
            self.conversation_history.append({
                "role": "assistant", "content": chatbot_response
            })

        # Track if chatbot just issued a refusal
        if chatbot_response and any(
            phrase in chatbot_response.lower()
            for phrase in ["cannot help", "unable to", "not able to", "i cannot", "decline"]
        ):
            self.preceded_by_refusal = True
        else:
            self.preceded_by_refusal = False

        self.last_risk_level = risk_level

    @property
    def risk_trend(self) -> str:
        """Compute risk trend from recent history."""
        if len(self.risk_history) < 3:
            return "stable"
        recent = self.risk_history[-3:]
        if recent[-1] > recent[0] + 10:
            return "increasing"
        elif recent[-1] < recent[0] - 10:
            return "decreasing"
        return "stable"

    def get_session_signals(self) -> Dict[str, Any]:
        """Return a dictionary of session-level signals for the explainer."""
        return {
            "session_id": self.session_id,
            "turn_count": self.turn_count,
            "current_risk_score": self.current_risk_score,
            "current_risk_level": self.current_risk_level,
            "peak_risk_score": self.peak_risk_score,
            "suspicious_event_count": self.suspicious_event_count,
            "high_risk_event_count": self.high_risk_event_count,
            "risk_trend": self.risk_trend,
            "risk_history": self.risk_history,
            "preceded_by_refusal": self.preceded_by_refusal,
            "risk_delta": (
                self.risk_history[-1] - self.risk_history[0]
                if len(self.risk_history) >= 2 else 0.0
            ),
        }

    def get_conversation_history(self) -> List[Dict]:
        """Return conversation history for chatbot (last 10 turns to limit tokens)."""
        return self.conversation_history[-20:]  # 10 user + 10 assistant messages


class SessionManager:
    """
    Central session management hub.

    Maintains an in-memory registry of active sessions and provides
    methods to create, retrieve, and update sessions.
    """

    def __init__(self):
        self._active_sessions: Dict[str, ActiveSession] = {}

    def create_session(self, db: DBSession) -> str:
        """Create a new session and persist it to the database."""
        session_id = str(uuid.uuid4())
        active = ActiveSession(session_id)
        self._active_sessions[session_id] = active

        # Persist to database
        db_session = SessionModel(
            session_id=session_id,
            created_at=active.created_at,
            updated_at=active.created_at,
        )
        db.add(db_session)
        db.commit()

        return session_id

    def get_session(self, session_id: str) -> Optional[ActiveSession]:
        """Retrieve an active session by ID."""
        return self._active_sessions.get(session_id)

    def get_or_create(self, session_id: Optional[str], db: DBSession) -> str:
        """
        Return existing session_id if valid, otherwise create a new session.
        Useful for dashboard sessions that need to persist across page refreshes.
        """
        if session_id and session_id in self._active_sessions:
            return session_id
        return self.create_session(db)

    def record_event(
        self,
        session_id: str,
        message_text: str,
        structural_features: Dict,
        heuristic_signals: Dict,
        prompt_risk_features: Dict,
        cnn_local_score: float,
        cnn_features: List[float],
        lstm_sequence_probs: Optional[List[float]],
        risk_score: float,
        risk_level: str,
        explanation: str,
        chatbot_response: Optional[str],
        processing_time_ms: float,
        db: DBSession,
        true_risk_label: Optional[str] = None,
    ) -> SecurityEvent:
        """
        Record a complete security event for one turn and update session state.
        """
        session = self._active_sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found in active sessions")

        # Check repeated attempt
        is_repeated = (
            session.last_risk_level in ["SUSPICIOUS", "HIGH_RISK"]
            and risk_level in ["SUSPICIOUS", "HIGH_RISK"]
        )

        # Build and persist the SecurityEvent
        event = SecurityEvent(
            session_id=session_id,
            turn_number=session.turn_count + 1,
            timestamp=datetime.utcnow(),
            message_text=message_text,
            message_length=len(message_text),
            structural_features=structural_features,
            heuristic_signals=heuristic_signals,
            prompt_risk_features=prompt_risk_features,
            cnn_local_score=cnn_local_score,
            lstm_sequence_probs=lstm_sequence_probs,
            risk_score=risk_score,
            risk_level=risk_level,
            explanation=explanation,
            is_repeated_attempt=is_repeated,
            preceded_by_refusal=session.preceded_by_refusal,
            processing_time_ms=processing_time_ms,
            true_risk_label=true_risk_label,
        )
        db.add(event)

        # Update in-memory session state
        session.update(
            risk_score=risk_score,
            risk_level=risk_level,
            cnn_features=cnn_features,
            chatbot_response=chatbot_response,
            user_message=message_text,
        )

        # Update the database Session record
        db_session = db.query(SessionModel).filter_by(session_id=session_id).first()
        if db_session:
            db_session.turn_count = session.turn_count
            db_session.current_risk_level = session.current_risk_level
            db_session.current_risk_score = session.current_risk_score
            db_session.peak_risk_score = session.peak_risk_score
            db_session.suspicious_event_count = session.suspicious_event_count
            db_session.high_risk_event_count = session.high_risk_event_count
            db_session.risk_trend = session.risk_trend
            db_session.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(event)

        return event

    def close_session(self, session_id: str, db: DBSession):
        """Mark a session as inactive."""
        if session_id in self._active_sessions:
            del self._active_sessions[session_id]

        db_session = db.query(SessionModel).filter_by(session_id=session_id).first()
        if db_session:
            db_session.is_active = False
            db.commit()

    @property
    def active_count(self) -> int:
        return len(self._active_sessions)


# Global singleton — shared across FastAPI routes
session_manager = SessionManager()
