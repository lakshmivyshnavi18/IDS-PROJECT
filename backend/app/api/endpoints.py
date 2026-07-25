import logging
from fastapi import APIRouter, BackgroundTasks, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Any
from ..services.llm_service import generate_response
from ..services.ids_service import check_prompt_security
from ..db.database import log_alert, get_latest_alerts
from ..api.auth import get_current_admin

# Configure structured debug logger
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("ids.endpoint")

router = APIRouter()


class ChatRequest(BaseModel):
    session_id: str
    user_id: str
    prompt: str
    is_protected: bool = True


class ChatResponse(BaseModel):
    response: str
    session_id: str
    ids_status: str = "OFF"
    ids_action: str = "ALLOW"
    threat_category: str = "none"


# ── Public endpoint: chat (no auth needed — users interact here) ───────────────

@router.post("/chat", response_model=ChatResponse)
async def chat_endpoint(request: ChatRequest, background_tasks: BackgroundTasks):
    if not request.prompt:
        raise HTTPException(status_code=400, detail="Prompt is required")

    ids_status    = "ON" if request.is_protected else "OFF"
    ids_action    = "ALLOW"
    threat_category = "none"

    logger.debug(f"─── New Request ───────────────────────────────")
    logger.debug(f"  IDS Status    : {ids_status}")
    logger.debug(f"  Session       : {request.session_id}")
    logger.debug(f"  Prompt        : {request.prompt[:80]}...")

    # ── IDS ON: run security check ────────────────────────────────────────────
    if request.is_protected:
        security_result = check_prompt_security(request.prompt)
        threat_category = security_result.get("attack_type", "none")

        logger.debug(f"  IDS Check     : is_malicious={security_result['is_malicious']}, "
                     f"type={threat_category}, "
                     f"severity={security_result['severity']}, "
                     f"confidence={security_result['confidence']:.2f}")

        if security_result["is_malicious"]:
            ids_action = "BLOCK"
            logger.debug(f"  IDS Action    : BLOCK — {threat_category}")
            logger.debug(f"──────────────────────────────────────────────")

            log_alert(
                session_id=request.session_id,
                prompt_snippet=request.prompt[:50] + "...",
                attack_type=threat_category,
                severity=security_result["severity"],
                confidence=security_result["confidence"]
            )

            attack_label = threat_category.replace("_", " ").title()
            severity     = security_result["severity"]
            confidence   = int(security_result["confidence"] * 100)

            ids_response = (
                f"🚨 **Threat Detected by CNN-LSTM IDS**\n\n"
                f"Your request has been **flagged and blocked** by the Intrusion Detection System.\n\n"
                f"| Field | Value |\n"
                f"|---|---|\n"
                f"| **Attack Type** | {attack_label} |\n"
                f"| **Severity** | {severity} |\n"
                f"| **Confidence** | {confidence}% |\n"
                f"| **IDS Mode** | Protected (ON) |\n\n"
                f"This incident has been logged to the Admin Dashboard. "
                f"If you believe this is a false positive, please contact your administrator."
            )
            return ChatResponse(
                response=ids_response,
                session_id=request.session_id,
                ids_status=ids_status,
                ids_action=ids_action,
                threat_category=threat_category
            )

        ids_action = "ALLOW"
        logger.debug(f"  IDS Action    : ALLOW — prompt is clean")

    else:
        logger.debug(f"  IDS Action    : ALLOW (IDS is OFF — security checks bypassed)")

    logger.debug(f"  Forwarding to LLM (is_protected={request.is_protected})")
    logger.debug(f"──────────────────────────────────────────────")

    llm_text = await generate_response(request.prompt, request.is_protected)

    return ChatResponse(
        response=llm_text,
        session_id=request.session_id,
        ids_status=ids_status,
        ids_action=ids_action,
        threat_category=threat_category
    )


# ── Protected endpoint: alerts (requires valid admin JWT) ──────────────────────

@router.get("/alerts", response_model=List[Dict[str, Any]])
def alerts_endpoint(current_user: dict = Depends(get_current_admin)):
    """Returns all IDS alerts. Requires admin JWT in Authorization header."""
    logger.debug(f"Admin '{current_user['username']}' fetched alerts")
    return get_latest_alerts(limit=50)
