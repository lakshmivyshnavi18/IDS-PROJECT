"""
api/main.py
─────────────────────────────────────────────────────────────────────────────
FastAPI application — main entry point.

Run with:
  uvicorn api.main:app --reload --port 8000
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session as DBSession

from database.db import init_db, get_db
from security.session_manager import session_manager
from security.pipeline import analyze_message
from chatbot.chatbot_engine import ChatbotEngine
from api.schemas import (
    ChatRequest, ChatResponse, SecurityAnalysis, SessionStatus,
    SessionCreateResponse, NewSessionRequest, EventRecord, MetricsSummary,
)
from database.models import Session as SessionModel, SecurityEvent
from config import GROQ_API_KEY

# ── App Initialization ────────────────────────────────────────────────────────
app = FastAPI(
    title="LLM Security Monitor API",
    description="Intelligent Security Monitoring for LLM Applications using CNN-LSTM",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup_event():
    print("\n🚀 LLM Security Monitor API Starting...")
    init_db()
    print("  ✓ Database initialized")
    print(f"  ✓ Groq API key: {'configured' if GROQ_API_KEY else '⚠️ NOT SET'}")
    print("  ✓ API ready\n")


# ── Health Check ──────────────────────────────────────────────────────────────
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "active_sessions": session_manager.active_count,
        "groq_configured": bool(GROQ_API_KEY),
    }


# ── Session Management ────────────────────────────────────────────────────────
@app.post("/session/create", response_model=SessionCreateResponse)
def create_session(db: DBSession = Depends(get_db)):
    """Create a new chat session."""
    session_id = session_manager.create_session(db)
    return SessionCreateResponse(
        session_id=session_id,
        message="New session created successfully.",
    )


@app.get("/session/{session_id}", response_model=SessionStatus)
def get_session_status(session_id: str):
    """Get current status of an active session."""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")
    signals = session.get_session_signals()
    return SessionStatus(
        session_id=session_id,
        turn_count=signals["turn_count"],
        current_risk_level=signals["current_risk_level"],
        current_risk_score=signals["current_risk_score"],
        peak_risk_score=signals["peak_risk_score"],
        suspicious_event_count=signals["suspicious_event_count"],
        high_risk_event_count=signals["high_risk_event_count"],
        risk_trend=signals["risk_trend"],
        risk_history=signals["risk_history"],
    )


@app.delete("/session/{session_id}")
def close_session(session_id: str, db: DBSession = Depends(get_db)):
    """Close and deactivate a session."""
    session_manager.close_session(session_id, db)
    return {"message": f"Session {session_id} closed."}


# ── Main Chat Endpoint ────────────────────────────────────────────────────────
@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest, db: DBSession = Depends(get_db)):
    """
    Main chat endpoint — processes a user message through the full
    security pipeline before generating a chatbot response.
    """
    # ── Get or create session ──────────────────────────────────
    session_id = session_manager.get_or_create(request.session_id, db)
    session = session_manager.get_session(session_id)

    # ── Run security analysis ──────────────────────────────────
    try:
        analysis = analyze_message(
            session_id=session_id,
            message_text=request.message,
            db=db,
            true_risk_label=request.true_risk_label,
            use_llm_explanation=True,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Security analysis failed: {str(e)}")

    risk_level = analysis["risk_level"]
    risk_score = analysis["risk_score"]

    # ── Generate chatbot response ──────────────────────────────
    conversation_history = session.get_conversation_history()

    if request.use_mock:
        chatbot_response = ChatbotEngine.get_mock_response(request.message, risk_level)
    else:
        try:
            engine = ChatbotEngine(api_key=GROQ_API_KEY)
            chatbot_response = engine.generate_response(
                user_message=request.message,
                conversation_history=conversation_history,
                risk_level=risk_level,
                risk_score=risk_score,
            )
        except Exception as e:
            chatbot_response = ChatbotEngine.get_mock_response(request.message, risk_level)

    # ── Update session with chatbot response ───────────────────
    session.update(
        risk_score=risk_score,
        risk_level=risk_level,
        chatbot_response=chatbot_response,
        user_message=None,  # already recorded in analyze_message
    )
    # Update conversation history manually
    session.conversation_history.append({"role": "assistant", "content": chatbot_response})

    # Update the event with chatbot response
    event = db.query(SecurityEvent).filter_by(id=analysis["event_id"]).first()
    if event:
        db.commit()

    # ── Build response ─────────────────────────────────────────
    session_signals = session.get_session_signals()

    return ChatResponse(
        session_id=session_id,
        chatbot_response=chatbot_response,
        security=SecurityAnalysis(
            event_id=analysis["event_id"],
            turn_number=analysis["turn_number"],
            risk_score=risk_score,
            risk_level=risk_level,
            lstm_probs=analysis["lstm_probs"],
            cnn_local_score=analysis["cnn_local_score"],
            heuristic_signals=analysis["heuristic_signals"],
            explanation_template=analysis["explanation"]["template"],
            explanation_llm=analysis["explanation"].get("llm", ""),
            explanation_combined=analysis["explanation"]["combined"],
            processing_time_ms=analysis["processing_time_ms"],
        ),
        session_status=SessionStatus(
            session_id=session_id,
            turn_count=session_signals["turn_count"],
            current_risk_level=session_signals["current_risk_level"],
            current_risk_score=session_signals["current_risk_score"],
            peak_risk_score=session_signals["peak_risk_score"],
            suspicious_event_count=session_signals["suspicious_event_count"],
            high_risk_event_count=session_signals["high_risk_event_count"],
            risk_trend=session_signals["risk_trend"],
            risk_history=session_signals["risk_history"],
        ),
    )


# ── Security Events ───────────────────────────────────────────────────────────
@app.get("/security/events/{session_id}")
def get_session_events(session_id: str, db: DBSession = Depends(get_db)):
    """Get all security events for a session."""
    events = (
        db.query(SecurityEvent)
        .filter_by(session_id=session_id)
        .order_by(SecurityEvent.turn_number)
        .all()
    )
    return [e.to_dict() for e in events]


@app.get("/security/recent")
def get_recent_events(limit: int = 20, db: DBSession = Depends(get_db)):
    """Get the most recent security events across all sessions."""
    events = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.id.desc())
        .limit(limit)
        .all()
    )
    return [e.to_dict() for e in events]


# ── Metrics ───────────────────────────────────────────────────────────────────
@app.get("/metrics", response_model=MetricsSummary)
def get_metrics(db: DBSession = Depends(get_db)):
    """Get overall system metrics."""
    total_sessions = db.query(SessionModel).count()
    events = db.query(SecurityEvent).all()
    total_events = len(events)

    if total_events == 0:
        return MetricsSummary(
            total_sessions=total_sessions,
            total_events=0,
            normal_count=0,
            suspicious_count=0,
            high_risk_count=0,
            avg_risk_score=0.0,
            detection_rate=0.0,
        )

    normal_count = sum(1 for e in events if e.risk_level == "NORMAL")
    suspicious_count = sum(1 for e in events if e.risk_level == "SUSPICIOUS")
    high_risk_count = sum(1 for e in events if e.risk_level == "HIGH_RISK")
    avg_risk_score = sum(e.risk_score for e in events) / total_events
    detection_rate = (suspicious_count + high_risk_count) / total_events

    return MetricsSummary(
        total_sessions=total_sessions,
        total_events=total_events,
        normal_count=normal_count,
        suspicious_count=suspicious_count,
        high_risk_count=high_risk_count,
        avg_risk_score=round(avg_risk_score, 2),
        detection_rate=round(detection_rate, 4),
    )
