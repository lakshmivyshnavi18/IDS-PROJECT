"""
Authentication API endpoints.

POST /api/v1/auth/login   → returns JWT access token
GET  /api/v1/auth/me      → returns current user info (requires token)
POST /api/v1/auth/logout  → client-side; server returns confirmation
"""
import logging
from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel

from ..core.security import (
    verify_password,
    create_access_token,
    decode_access_token,
)
from ..db.database import get_admin_user, get_admin_by_email

logger = logging.getLogger("ids.auth")

router = APIRouter(prefix="/auth", tags=["auth"])

# OAuth2 scheme — token extracted from Authorization: Bearer <token>
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str       # accepts username OR email
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class UserInfo(BaseModel):
    username: str
    email: str
    role: str


# ── Dependency: verify JWT and return current user ─────────────────────────────

async def get_current_admin(token: str = Depends(oauth2_scheme)) -> dict:
    """
    FastAPI dependency.  Raises 401 if the token is missing, expired, or invalid.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token. Please log in again.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_access_token(token)
    if payload is None:
        logger.warning("Token verification failed — invalid or expired")
        raise credentials_exception

    username: str = payload.get("sub")
    if not username:
        raise credentials_exception

    user = get_admin_user(username)
    if user is None:
        raise credentials_exception

    logger.debug(f"Authenticated admin: {username}")
    return user


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(form: LoginRequest):
    """
    Accepts username OR email + password.
    Returns a signed JWT on success.
    """
    logger.debug(f"Login attempt for identifier: {form.username}")

    # Try username first, then email
    user = get_admin_user(form.username) or get_admin_by_email(form.username)

    if user is None or not verify_password(form.password, user["password_hash"]):
        logger.warning(f"Failed login for: {form.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password.",
        )

    token = create_access_token(data={"sub": user["username"], "role": user["role"]})
    logger.info(f"Admin '{user['username']}' logged in successfully")

    return TokenResponse(
        access_token=token,
        username=user["username"],
        role=user["role"],
    )


@router.get("/me", response_model=UserInfo)
async def get_me(current_user: dict = Depends(get_current_admin)):
    """Returns the authenticated admin's profile."""
    return UserInfo(
        username=current_user["username"],
        email=current_user["email"],
        role=current_user["role"],
    )


@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_admin)):
    """
    JWT is stateless — the client deletes its stored token.
    This endpoint confirms the action server-side.
    """
    logger.info(f"Admin '{current_user['username']}' logged out")
    return {"message": f"Admin '{current_user['username']}' logged out successfully."}
