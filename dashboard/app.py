"""
dashboard/app.py
─────────────────────────────────────────────────────────────────────────────
Professional Streamlit Security Dashboard for LLM Security Monitor.

Run with:
  streamlit run dashboard/app.py

Features:
  - Live chatbot interface
  - Real-time risk meter with animated gauge
  - Session timeline with per-turn risk scores
  - AI explanation panel
  - Session-level threat summary
  - System-wide metrics
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import requests
import json
import time
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime

from config import API_BASE_URL
from security.risk_scorer import get_risk_color, get_risk_emoji

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="LLM Security Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# CUSTOM CSS
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* Global */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Dark background */
.stApp {
    background: linear-gradient(135deg, #0a0e1a 0%, #0d1b2a 50%, #0a1628 100%);
    color: #e2e8f0;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0d1b2a 0%, #111827 100%);
    border-right: 1px solid rgba(99,179,237,0.15);
}

/* Risk cards */
.risk-card {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 16px;
    padding: 20px;
    backdrop-filter: blur(12px);
    margin-bottom: 12px;
    transition: all 0.3s ease;
}
.risk-card:hover {
    border-color: rgba(99,179,237,0.3);
    transform: translateY(-2px);
}

/* Risk level badges */
.badge-normal {
    background: rgba(34,197,94,0.15);
    color: #4ade80;
    border: 1px solid rgba(34,197,94,0.3);
    padding: 4px 12px;
    border-radius: 20px;
    font-weight: 600;
    font-size: 0.8rem;
}
.badge-suspicious {
    background: rgba(245,158,11,0.15);
    color: #fbbf24;
    border: 1px solid rgba(245,158,11,0.3);
    padding: 4px 12px;
    border-radius: 20px;
    font-weight: 600;
    font-size: 0.8rem;
}
.badge-high-risk {
    background: rgba(239,68,68,0.15);
    color: #f87171;
    border: 1px solid rgba(239,68,68,0.3);
    padding: 4px 12px;
    border-radius: 20px;
    font-weight: 600;
    font-size: 0.8rem;
    animation: pulse 2s infinite;
}
@keyframes pulse {
    0%, 100% { box-shadow: 0 0 0 0 rgba(239,68,68,0.4); }
    50% { box-shadow: 0 0 0 6px rgba(239,68,68,0); }
}

/* Chat bubbles */
.chat-user {
    background: linear-gradient(135deg, #1e40af, #3b82f6);
    color: white;
    padding: 12px 16px;
    border-radius: 16px 16px 4px 16px;
    margin: 8px 0;
    max-width: 80%;
    margin-left: auto;
    font-size: 0.9rem;
    box-shadow: 0 4px 12px rgba(59,130,246,0.3);
}
.chat-bot {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.1);
    color: #e2e8f0;
    padding: 12px 16px;
    border-radius: 16px 16px 16px 4px;
    margin: 8px 0;
    max-width: 80%;
    font-size: 0.9rem;
}
.chat-bot-name {
    color: #63b3ed;
    font-weight: 600;
    font-size: 0.75rem;
    margin-bottom: 4px;
}

/* Metric cards */
.metric-card {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 16px;
    text-align: center;
}
.metric-value {
    font-size: 2rem;
    font-weight: 700;
    background: linear-gradient(135deg, #63b3ed, #a78bfa);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.metric-label {
    color: #94a3b8;
    font-size: 0.75rem;
    margin-top: 4px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

/* Section headers */
.section-header {
    color: #63b3ed;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 12px;
    padding-bottom: 6px;
    border-bottom: 1px solid rgba(99,179,237,0.2);
}

/* Timeline */
.timeline-item {
    display: flex;
    align-items: center;
    padding: 8px 0;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    font-size: 0.82rem;
}

/* Explanation box */
.explanation-box {
    background: rgba(99,179,237,0.05);
    border: 1px solid rgba(99,179,237,0.2);
    border-left: 3px solid #63b3ed;
    border-radius: 8px;
    padding: 14px;
    font-size: 0.85rem;
    color: #cbd5e1;
    line-height: 1.6;
}

/* Scrollable chat */
.chat-container {
    max-height: 480px;
    overflow-y: auto;
    padding: 8px;
}

/* Input styling */
.stTextArea textarea {
    background: rgba(255,255,255,0.04) !important;
    border: 1px solid rgba(255,255,255,0.12) !important;
    color: #e2e8f0 !important;
    border-radius: 12px !important;
    font-family: 'Inter', sans-serif !important;
}
.stButton button {
    background: linear-gradient(135deg, #2563eb, #7c3aed) !important;
    color: white !important;
    border: none !important;
    border-radius: 10px !important;
    font-weight: 600 !important;
    transition: all 0.3s ease !important;
}
.stButton button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 8px 25px rgba(37,99,235,0.4) !important;
}

/* Hide Streamlit branding */
#MainMenu, footer, header { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# STATE INITIALIZATION
# ─────────────────────────────────────────────────────────────────────────────
def init_state():
    defaults = {
        "session_id": None,
        "messages": [],           # List of {role, content, risk_level, risk_score, turn}
        "risk_history": [],       # List of {turn, score, level}
        "current_risk_level": "NORMAL",
        "current_risk_score": 0.0,
        "peak_risk_score": 0.0,
        "suspicious_count": 0,
        "high_risk_count": 0,
        "risk_trend": "stable",
        "last_explanation": "",
        "last_heuristic_signals": {},
        "api_available": True,
        "use_mock": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()


# ─────────────────────────────────────────────────────────────────────────────
# API HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def api_create_session():
    try:
        r = requests.post(f"{API_BASE_URL}/session/create", timeout=5)
        if r.status_code == 200:
            return r.json()["session_id"]
    except Exception:
        st.session_state.api_available = False
    return None


def api_chat(session_id, message, use_mock=False):
    try:
        r = requests.post(
            f"{API_BASE_URL}/chat",
            json={"session_id": session_id, "message": message, "use_mock": use_mock},
            timeout=30,
        )
        if r.status_code == 200:
            st.session_state.api_available = True
            return r.json()
    except Exception as e:
        st.session_state.api_available = False
    return None


def api_get_metrics():
    try:
        r = requests.get(f"{API_BASE_URL}/metrics", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# CHART HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def build_risk_gauge(score: float, level: str):
    color = {"NORMAL": "#22c55e", "SUSPICIOUS": "#f59e0b", "HIGH_RISK": "#ef4444"}.get(level, "#6b7280")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"font": {"size": 36, "color": color, "family": "Inter"}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#475569",
                     "tickfont": {"color": "#94a3b8", "size": 10}},
            "bar": {"color": color, "thickness": 0.3},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 30],  "color": "rgba(34,197,94,0.1)"},
                {"range": [30, 70], "color": "rgba(245,158,11,0.1)"},
                {"range": [70, 100],"color": "rgba(239,68,68,0.1)"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.8,
                "value": score,
            },
        },
        title={"text": f"<b>RISK SCORE</b><br><span style='font-size:11px;color:#94a3b8'>{level}</span>",
               "font": {"size": 13, "color": "#94a3b8", "family": "Inter"}},
        domain={"x": [0, 1], "y": [0, 1]},
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin={"t": 50, "b": 10, "l": 20, "r": 20},
        height=220,
    )
    return fig


def build_risk_timeline(risk_history: list):
    if not risk_history:
        return None

    turns = [r["turn"] for r in risk_history]
    scores = [r["score"] for r in risk_history]
    levels = [r["level"] for r in risk_history]
    colors = [
        {"NORMAL": "#22c55e", "SUSPICIOUS": "#f59e0b", "HIGH_RISK": "#ef4444"}.get(l, "#6b7280")
        for l in levels
    ]

    fig = go.Figure()

    # Shaded regions
    fig.add_hrect(y0=0, y1=30, fillcolor="rgba(34,197,94,0.05)", line_width=0)
    fig.add_hrect(y0=30, y1=70, fillcolor="rgba(245,158,11,0.05)", line_width=0)
    fig.add_hrect(y0=70, y1=100, fillcolor="rgba(239,68,68,0.05)", line_width=0)

    # Threshold lines
    fig.add_hline(y=30, line_dash="dot", line_color="rgba(34,197,94,0.3)", line_width=1)
    fig.add_hline(y=70, line_dash="dot", line_color="rgba(239,68,68,0.3)", line_width=1)

    # Risk line
    fig.add_trace(go.Scatter(
        x=turns, y=scores,
        mode="lines+markers",
        line={"color": "#63b3ed", "width": 2.5, "shape": "spline"},
        marker={"size": 10, "color": colors, "line": {"width": 2, "color": "#0d1b2a"}},
        hovertemplate="Turn %{x}<br>Score: %{y:.1f}<br>Level: %{text}<extra></extra>",
        text=levels,
        name="Risk Score",
    ))

    # Fill area under line
    fig.add_trace(go.Scatter(
        x=turns, y=scores,
        fill="tozeroy",
        fillcolor="rgba(99,179,237,0.06)",
        line={"width": 0},
        showlegend=False,
        hoverinfo="skip",
    ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis={
            "title": "Turn", "color": "#64748b",
            "gridcolor": "rgba(255,255,255,0.05)",
            "tickmode": "linear", "dtick": 1,
        },
        yaxis={
            "title": "Risk Score", "color": "#64748b",
            "range": [0, 105],
            "gridcolor": "rgba(255,255,255,0.05)",
        },
        margin={"t": 10, "b": 40, "l": 50, "r": 20},
        height=200,
        showlegend=False,
    )
    return fig


def build_signal_radar(heuristic_signals: dict):
    if not heuristic_signals:
        return None
    categories = ["Override", "Probe", "Role Change", "Persistence", "Urgency"]
    keys = ["override_signal", "probe_signal", "role_signal", "persistence_signal", "urgency_signal"]
    values = [heuristic_signals.get(k, 0) for k in keys]
    values_closed = values + [values[0]]
    categories_closed = categories + [categories[0]]

    fig = go.Figure(go.Scatterpolar(
        r=values_closed,
        theta=categories_closed,
        fill="toself",
        fillcolor="rgba(99,179,237,0.1)",
        line={"color": "#63b3ed", "width": 2},
        marker={"size": 6, "color": "#63b3ed"},
    ))
    fig.update_layout(
        polar={
            "radialaxis": {"visible": True, "range": [0, 1], "color": "#475569",
                           "gridcolor": "rgba(255,255,255,0.08)"},
            "angularaxis": {"color": "#94a3b8", "gridcolor": "rgba(255,255,255,0.08)"},
            "bgcolor": "rgba(0,0,0,0)",
        },
        paper_bgcolor="rgba(0,0,0,0)",
        margin={"t": 10, "b": 10, "l": 30, "r": 30},
        height=200,
        showlegend=False,
    )
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='text-align:center; padding: 20px 0 10px'>
        <div style='font-size: 2.5rem'>🛡️</div>
        <div style='font-size: 1.1rem; font-weight: 700; color: #63b3ed; letter-spacing: 0.05em'>
            LLM SECURITY<br>MONITOR
        </div>
        <div style='font-size: 0.7rem; color: #64748b; margin-top: 4px'>
            CNN-LSTM Behavioral Analysis
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    # Session controls
    st.markdown('<div class="section-header">SESSION CONTROL</div>', unsafe_allow_html=True)

    if st.button("🔄 New Session", use_container_width=True):
        session_id = api_create_session()
        if session_id:
            # Reset all state
            st.session_state.session_id = session_id
            st.session_state.messages = []
            st.session_state.risk_history = []
            st.session_state.current_risk_level = "NORMAL"
            st.session_state.current_risk_score = 0.0
            st.session_state.peak_risk_score = 0.0
            st.session_state.suspicious_count = 0
            st.session_state.high_risk_count = 0
            st.session_state.risk_trend = "stable"
            st.session_state.last_explanation = ""
            st.session_state.last_heuristic_signals = {}
            st.rerun()
        else:
            st.error("API not available. Start the FastAPI server first:\nuvicorn api.main:app --reload")

    if st.session_state.session_id:
        st.markdown(f"""
        <div style='background: rgba(99,179,237,0.08); border: 1px solid rgba(99,179,237,0.2);
                    border-radius: 8px; padding: 8px 12px; margin-top: 8px;'>
            <div style='font-size: 0.65rem; color: #64748b; text-transform: uppercase'>Session ID</div>
            <div style='font-size: 0.72rem; color: #63b3ed; font-family: "JetBrains Mono", monospace;
                        word-break: break-all; margin-top: 2px'>
                {st.session_state.session_id[:24]}...
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    # Current session stats
    st.markdown('<div class="section-header">SESSION STATISTICS</div>', unsafe_allow_html=True)

    risk_emoji = {"NORMAL": "🟢", "SUSPICIOUS": "🟡", "HIGH_RISK": "🔴"}.get(
        st.session_state.current_risk_level, "⚪"
    )
    turn_count = len(st.session_state.risk_history)

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Turns", turn_count)
        st.metric("⚠️ Suspicious", st.session_state.suspicious_count)
    with col2:
        st.metric("Peak Score", f"{st.session_state.peak_risk_score:.0f}")
        st.metric("🚨 High Risk", st.session_state.high_risk_count)

    trend_icons = {"stable": "➡️", "increasing": "📈", "decreasing": "📉"}
    st.markdown(f"""
    <div style='text-align:center; margin-top: 8px;
                background: rgba(255,255,255,0.03); border-radius: 8px; padding: 10px;'>
        <div style='font-size: 0.65rem; color: #64748b; text-transform: uppercase'>Risk Trend</div>
        <div style='font-size: 1.2rem; margin-top: 4px'>
            {trend_icons.get(st.session_state.risk_trend, "➡️")}
            <span style='font-size: 0.85rem; color: #94a3b8; margin-left: 4px'>
                {st.session_state.risk_trend.title()}
            </span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()

    # Settings
    st.markdown('<div class="section-header">SETTINGS</div>', unsafe_allow_html=True)
    st.session_state.use_mock = st.toggle(
        "Offline Mode (Mock Chatbot)",
        value=st.session_state.use_mock,
        help="Use rule-based mock responses instead of Groq API",
    )

    # API status
    api_status = "🟢 API Online" if st.session_state.api_available else "🔴 API Offline"
    st.caption(api_status)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN CONTENT
# ─────────────────────────────────────────────────────────────────────────────

# Header
st.markdown("""
<div style='padding: 20px 0 10px'>
    <h1 style='font-size: 1.6rem; font-weight: 700; color: #f1f5f9; margin: 0;'>
        Intelligent Security Monitoring for LLM Applications
    </h1>
    <p style='color: #64748b; font-size: 0.85rem; margin: 4px 0 0;'>
        CNN-LSTM Behavioral Analysis • Real-time Risk Detection • Explainable AI
    </p>
</div>
""", unsafe_allow_html=True)

# ── Auto-create session on first load ─────────────────────────────────────────
if not st.session_state.session_id:
    session_id = api_create_session()
    if session_id:
        st.session_state.session_id = session_id
    else:
        st.error("""
        ⚠️ **Cannot connect to the FastAPI backend.**

        Please start the server first:
        ```
        uvicorn api.main:app --reload --port 8000
        ```
        Then refresh this page.
        """)
        st.stop()

# ── Main layout: Chat | Security Panel ───────────────────────────────────────
chat_col, security_col = st.columns([1.1, 0.9], gap="large")

# ════════════════════════════════════════════════════════════════════════════
# LEFT COLUMN — CHATBOT INTERFACE
# ════════════════════════════════════════════════════════════════════════════
with chat_col:
    st.markdown('<div class="section-header">💬 NOVA — AI ASSISTANT</div>', unsafe_allow_html=True)

    # Chat history display
    chat_html = '<div class="chat-container">'
    if not st.session_state.messages:
        chat_html += """
        <div style='text-align:center; padding: 40px 20px; color: #475569;'>
            <div style='font-size: 2rem; margin-bottom: 12px'>🤖</div>
            <div style='font-size: 0.9rem; color: #64748b;'>
                Hi! I'm <strong style="color:#63b3ed">Nova</strong>, your AI assistant.<br>
                Ask me anything — while the security monitor watches in real time.
            </div>
        </div>
        """
    else:
        for msg in st.session_state.messages:
            if msg["role"] == "user":
                risk_icon = {"NORMAL": "🟢", "SUSPICIOUS": "🟡", "HIGH_RISK": "🔴"}.get(
                    msg.get("risk_level", "NORMAL"), "⚪"
                )
                score = msg.get("risk_score", 0)
                chat_html += f"""
                <div style='display:flex; justify-content:flex-end; margin: 8px 0;'>
                    <div>
                        <div style='text-align:right; font-size:0.68rem; color:#64748b; margin-bottom:3px;'>
                            You &nbsp;{risk_icon} {score:.0f}/100
                        </div>
                        <div class='chat-user'>{msg["content"]}</div>
                    </div>
                </div>
                """
            else:
                chat_html += f"""
                <div style='display:flex; justify-content:flex-start; margin: 8px 0;'>
                    <div style='max-width:80%'>
                        <div class='chat-bot-name'>🤖 Nova</div>
                        <div class='chat-bot'>{msg["content"]}</div>
                    </div>
                </div>
                """
    chat_html += "</div>"
    st.markdown(chat_html, unsafe_allow_html=True)

    # Input area
    st.markdown("<div style='margin-top: 12px'>", unsafe_allow_html=True)
    with st.form("chat_form", clear_on_submit=True):
        user_input = st.text_area(
            "Message",
            placeholder="Type your message here... (Shift+Enter for new line)",
            height=80,
            label_visibility="collapsed",
        )
        send_col, info_col = st.columns([1, 3])
        with send_col:
            submitted = st.form_submit_button("Send ➤", use_container_width=True)
        with info_col:
            st.markdown(
                "<div style='color:#475569; font-size:0.72rem; padding-top:8px;'>"
                "Security analysis runs automatically on every message</div>",
                unsafe_allow_html=True,
            )
    st.markdown("</div>", unsafe_allow_html=True)

    # Handle submission
    if submitted and user_input.strip():
        with st.spinner("Analyzing and generating response..."):
            result = api_chat(
                st.session_state.session_id,
                user_input.strip(),
                use_mock=st.session_state.use_mock,
            )

        if result:
            security = result["security"]
            session_status = result["session_status"]

            # Update state
            st.session_state.messages.append({
                "role": "user",
                "content": user_input.strip(),
                "risk_level": security["risk_level"],
                "risk_score": security["risk_score"],
            })
            st.session_state.messages.append({
                "role": "assistant",
                "content": result["chatbot_response"],
            })

            turn_num = security["turn_number"]
            st.session_state.risk_history.append({
                "turn": turn_num,
                "score": security["risk_score"],
                "level": security["risk_level"],
            })

            st.session_state.current_risk_level = session_status["current_risk_level"]
            st.session_state.current_risk_score = session_status["current_risk_score"]
            st.session_state.peak_risk_score = session_status["peak_risk_score"]
            st.session_state.suspicious_count = session_status["suspicious_event_count"]
            st.session_state.high_risk_count = session_status["high_risk_event_count"]
            st.session_state.risk_trend = session_status["risk_trend"]
            st.session_state.last_explanation = security["explanation_combined"]
            st.session_state.last_heuristic_signals = security["heuristic_signals"]

            st.rerun()
        else:
            st.error("Failed to get response. Is the FastAPI server running?")


# ════════════════════════════════════════════════════════════════════════════
# RIGHT COLUMN — SECURITY PANEL
# ════════════════════════════════════════════════════════════════════════════
with security_col:

    # ── Risk Gauge ─────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">🎯 REAL-TIME RISK ASSESSMENT</div>', unsafe_allow_html=True)
    gauge_fig = build_risk_gauge(
        st.session_state.current_risk_score,
        st.session_state.current_risk_level,
    )
    st.plotly_chart(gauge_fig, use_container_width=True, config={"displayModeBar": False})

    # Risk level badge
    level = st.session_state.current_risk_level
    badge_class = {"NORMAL": "badge-normal", "SUSPICIOUS": "badge-suspicious",
                   "HIGH_RISK": "badge-high-risk"}.get(level, "badge-normal")
    emoji = {"NORMAL": "✅", "SUSPICIOUS": "⚠️", "HIGH_RISK": "🚨"}.get(level, "")
    st.markdown(
        f'<div style="text-align:center; margin-top:-10px; margin-bottom:16px">'
        f'<span class="{badge_class}">{emoji} {level.replace("_", " ")}</span></div>',
        unsafe_allow_html=True,
    )

    # ── Signal Radar ───────────────────────────────────────────────────────
    st.markdown('<div class="section-header">📡 THREAT SIGNAL RADAR</div>', unsafe_allow_html=True)
    radar_fig = build_signal_radar(st.session_state.last_heuristic_signals)
    if radar_fig:
        st.plotly_chart(radar_fig, use_container_width=True, config={"displayModeBar": False})
    else:
        st.markdown(
            '<div style="text-align:center; color:#475569; padding:30px; font-size:0.85rem">'
            'Send a message to see signal analysis</div>',
            unsafe_allow_html=True,
        )

    # ── Risk Timeline ──────────────────────────────────────────────────────
    st.markdown('<div class="section-header">📈 SESSION RISK TIMELINE</div>', unsafe_allow_html=True)
    timeline_fig = build_risk_timeline(st.session_state.risk_history)
    if timeline_fig:
        st.plotly_chart(timeline_fig, use_container_width=True, config={"displayModeBar": False})
    else:
        st.markdown(
            '<div style="color:#475569; font-size:0.82rem; padding: 8px 0">'
            'Timeline will appear after the first message.</div>',
            unsafe_allow_html=True,
        )

    # ── AI Explanation ─────────────────────────────────────────────────────
    st.markdown('<div class="section-header">🧠 AI SECURITY EXPLANATION</div>', unsafe_allow_html=True)
    if st.session_state.last_explanation:
        st.markdown(
            f'<div class="explanation-box">{st.session_state.last_explanation}</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="explanation-box" style="color:#475569">'
            'Security explanations will appear here after each message is analyzed.</div>',
            unsafe_allow_html=True,
        )


# ─────────────────────────────────────────────────────────────────────────────
# BOTTOM SECTION — METRICS DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────
st.divider()
st.markdown('<div class="section-header">📊 SYSTEM-WIDE SECURITY METRICS</div>', unsafe_allow_html=True)

metrics = api_get_metrics()
if metrics:
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    metric_data = [
        (m1, metrics.get("total_sessions", 0), "Total Sessions"),
        (m2, metrics.get("total_events", 0), "Total Events"),
        (m3, metrics.get("normal_count", 0), "🟢 Normal"),
        (m4, metrics.get("suspicious_count", 0), "🟡 Suspicious"),
        (m5, metrics.get("high_risk_count", 0), "🔴 High Risk"),
        (m6, f"{metrics.get('avg_risk_score', 0):.1f}", "Avg Risk Score"),
    ]
    for col, value, label in metric_data:
        with col:
            st.markdown(f"""
            <div class='metric-card'>
                <div class='metric-value'>{value}</div>
                <div class='metric-label'>{label}</div>
            </div>
            """, unsafe_allow_html=True)

    # Detection rate bar
    detection_rate = metrics.get("detection_rate", 0) * 100
    total = metrics.get("total_events", 0)
    if total > 0:
        bar_col1, bar_col2 = st.columns([2, 1])
        with bar_col1:
            st.markdown(
                f"<div style='color:#94a3b8; font-size:0.78rem; margin-top:12px'>"
                f"Detection Rate: <strong style='color:#63b3ed'>{detection_rate:.1f}%</strong> "
                f"({metrics.get('suspicious_count',0) + metrics.get('high_risk_count',0)} "
                f"flagged out of {total} events)</div>",
                unsafe_allow_html=True,
            )
else:
    st.markdown(
        '<div style="color:#475569; font-size:0.85rem">Metrics unavailable — API not connected.</div>',
        unsafe_allow_html=True,
    )

# Footer
st.markdown("""
<div style='text-align:center; padding: 24px 0 8px; color: #334155; font-size: 0.72rem;'>
    LLM Security Monitor • CNN-LSTM Behavioral Analysis • Research Project 2024
</div>
""", unsafe_allow_html=True)
