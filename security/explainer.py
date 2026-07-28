"""
security/explainer.py
─────────────────────────────────────────────────────────────────────────────
AI-powered explanation generator for security decisions.

Two-Tier Architecture:
  Tier 1 (Template): Always available, fast, deterministic.
                     Generates structured explanations from signal dicts.
  Tier 2 (LLM):     Uses Groq (Llama 3.3 70B) to generate fluent,
                     analyst-quality explanations from the same signals.

The explainer NEVER fabricates reasons — it only uses signals that were
actually computed by the model and feature extractor.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from typing import Dict, Any, Optional
from config import GROQ_API_KEY, GROQ_EXPLAIN_MODEL

# ── Explanation prompt for the LLM ───────────────────────────────────────────
ANALYST_SYSTEM_PROMPT = """You are a cybersecurity analyst specializing in LLM application security.
You have been given a structured security assessment of a user's interaction session with an AI chatbot.
Your task is to write a clear, concise, professional security report paragraph (3-5 sentences) that:
1. States the risk classification and score
2. Explains the specific behavioral signals that led to this decision
3. Describes the interaction pattern in plain English
4. Does NOT mention technical model internals (CNN, LSTM, embeddings)
5. Sounds like it was written by a human security analyst

Be factual. Only mention signals that are actually present (non-zero/true).
Do not add speculation or made-up reasons.
"""


def generate_template_explanation(
    risk_level: str,
    risk_score: float,
    session_signals: Dict[str, Any],
    heuristic_signals: Dict[str, float],
    structural_features: Dict[str, float],
) -> str:
    """
    Tier 1: Template-based explanation — always works, no API needed.
    Assembles a structured, signal-grounded explanation.
    """
    lines = []

    # ── Header ────────────────────────────────────────────────
    level_labels = {
        "NORMAL": "✅ NORMAL",
        "SUSPICIOUS": "⚠️ SUSPICIOUS",
        "HIGH_RISK": "🚨 HIGH RISK",
    }
    lines.append(f"**Risk Assessment: {level_labels.get(risk_level, risk_level)}**")
    lines.append(f"Risk Score: {risk_score:.0f}/100\n")

    # ── Contributing factors ───────────────────────────────────
    factors = []

    # Session-level signals
    susp_count = session_signals.get("suspicious_event_count", 0)
    high_count = session_signals.get("high_risk_event_count", 0)
    turn_count = session_signals.get("turn_count", 1)
    risk_trend = session_signals.get("risk_trend", "stable")
    preceded_by_refusal = session_signals.get("preceded_by_refusal", False)
    risk_delta = session_signals.get("risk_delta", 0.0)

    if high_count >= 2:
        factors.append(f"✗ **Multiple high-risk events detected** ({high_count} turns flagged as HIGH RISK)")
    elif high_count == 1:
        factors.append("✗ **One high-risk interaction detected** in this session")

    if susp_count >= 3:
        factors.append(f"✗ **Repeated suspicious behavior** across {susp_count} turns")
    elif susp_count == 2:
        factors.append("✗ **Two suspicious interaction patterns** observed")
    elif susp_count == 1 and risk_level != "NORMAL":
        factors.append("✗ **One suspicious interaction pattern** detected")

    if preceded_by_refusal:
        factors.append("✗ **Suspicious behavior continued after a refusal response** (persistence signal)")

    if risk_trend == "increasing":
        factors.append(f"✗ **Risk is increasing** across the session (Δ score: +{risk_delta:.0f})")

    if risk_delta > 30:
        factors.append("✗ **Sharp escalation** in risk score observed mid-session")

    # Heuristic signals
    if heuristic_signals.get("override_signal", 0) >= 0.5:
        factors.append("✗ **Instruction-override language** detected in the current message")
    if heuristic_signals.get("probe_signal", 0) >= 0.5:
        factors.append("✗ **System probing language** detected (attempting to reveal internal configuration)")
    if heuristic_signals.get("role_signal", 0) >= 0.5:
        factors.append("✗ **Alternative persona / role-change request** detected")
    if heuristic_signals.get("persistence_signal", 0) >= 0.5:
        factors.append("✗ **Persistence language** detected (pushing back on prior refusals)")
    if heuristic_signals.get("urgency_signal", 0) >= 0.5:
        factors.append("✗ **Pressure / urgency language** detected")

    # Positive signals (supporting NORMAL classification)
    if risk_level == "NORMAL":
        factors.append("✓ No suspicious patterns detected in current message")
        factors.append(f"✓ Session shows normal interaction behavior ({turn_count} turns)")
    elif risk_level == "SUSPICIOUS" and susp_count <= 1:
        factors.append(f"✓ Session is {turn_count} turns — limited history for full behavioral analysis")

    # ── Behavioral trend summary ───────────────────────────────
    lines.append("**Contributing Factors:**")
    if factors:
        for f in factors:
            lines.append(f"  {f}")
    else:
        lines.append("  No significant risk factors detected.")

    lines.append(f"\n**Behavioral Trend:** {risk_trend.replace('_', ' ').title()}")

    # ── Context note ───────────────────────────────────────────
    if risk_level == "NORMAL":
        lines.append("\n*This session shows normal interaction patterns consistent with legitimate use.*")
    elif risk_level == "SUSPICIOUS":
        lines.append(
            "\n*This session has been flagged for monitoring. The behavior pattern may indicate "
            "probing or testing of the AI system. No immediate intervention required, but continued "
            "monitoring is recommended.*"
        )
    elif risk_level == "HIGH_RISK":
        lines.append(
            "\n*This session has been classified as HIGH RISK. The behavioral pattern is consistent "
            "with deliberate manipulation attempts. The AI system has been placed in high-alert mode "
            "and responses have been adjusted accordingly.*"
        )

    return "\n".join(lines)


def generate_llm_explanation(
    risk_level: str,
    risk_score: float,
    session_signals: Dict[str, Any],
    heuristic_signals: Dict[str, float],
) -> str:
    """
    Tier 2: LLM-enhanced explanation using Groq.
    Falls back to template if API is unavailable.
    """
    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)

        # Prepare signal summary for the LLM
        signal_summary = f"""
SESSION SECURITY ASSESSMENT:
- Risk Level: {risk_level}
- Risk Score: {risk_score:.0f}/100
- Session Length: {session_signals.get('turn_count', 1)} turns
- Suspicious Events: {session_signals.get('suspicious_event_count', 0)}
- High Risk Events: {session_signals.get('high_risk_event_count', 0)}
- Risk Trend: {session_signals.get('risk_trend', 'stable')}
- Continued After Refusal: {session_signals.get('preceded_by_refusal', False)}
- Risk Score Change: {session_signals.get('risk_delta', 0.0):+.0f} points

DETECTED SIGNALS:
- Instruction override language: {'Yes' if heuristic_signals.get('override_signal', 0) >= 0.5 else 'No'}
- System probing language: {'Yes' if heuristic_signals.get('probe_signal', 0) >= 0.5 else 'No'}
- Alternative persona request: {'Yes' if heuristic_signals.get('role_signal', 0) >= 0.5 else 'No'}
- Post-refusal persistence: {'Yes' if heuristic_signals.get('persistence_signal', 0) >= 0.5 else 'No'}
- Urgency/pressure language: {'Yes' if heuristic_signals.get('urgency_signal', 0) >= 0.5 else 'No'}

Write a professional security analyst report paragraph explaining this assessment.
"""
        completion = client.chat.completions.create(
            model=GROQ_EXPLAIN_MODEL,
            messages=[
                {"role": "system", "content": ANALYST_SYSTEM_PROMPT},
                {"role": "user", "content": signal_summary},
            ],
            max_tokens=200,
            temperature=0.3,
        )
        return completion.choices[0].message.content.strip()

    except Exception as e:
        return f"[LLM explanation unavailable: {type(e).__name__}]"


def explain(
    risk_level: str,
    risk_score: float,
    session_signals: Dict[str, Any],
    heuristic_signals: Dict[str, float],
    structural_features: Dict[str, float],
    use_llm: bool = True,
) -> Dict[str, str]:
    """
    Generate both template and LLM explanations.

    Returns:
        dict with keys: 'template', 'llm', 'combined'
    """
    template_exp = generate_template_explanation(
        risk_level, risk_score, session_signals, heuristic_signals, structural_features
    )

    llm_exp = ""
    if use_llm and GROQ_API_KEY:
        llm_exp = generate_llm_explanation(
            risk_level, risk_score, session_signals, heuristic_signals
        )

    combined = llm_exp if llm_exp and not llm_exp.startswith("[LLM") else template_exp

    return {
        "template": template_exp,
        "llm": llm_exp,
        "combined": combined,
    }
