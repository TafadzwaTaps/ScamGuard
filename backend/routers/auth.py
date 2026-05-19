from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from database import get_supabase
from utils.logger import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class AuthPayload(BaseModel):
    email: str
    password: str


def _clean_supabase_error(exc: Exception) -> str:
    """
    Convert Supabase/GoTrue exceptions to clean user-facing messages.
    Supabase errors arrive as AuthApiError with a .message attribute,
    or as plain strings inside other exception types.
    """
    msg = ""

    # GoTrue AuthApiError has .message
    if hasattr(exc, "message"):
        msg = str(exc.message)
    else:
        msg = str(exc)

    # Map internal Supabase messages to friendly text
    lower = msg.lower()
    if "email not confirmed" in lower or "email_not_confirmed" in lower:
        return (
            "Email not confirmed. Please check your inbox (and spam folder) "
            "for a confirmation link from Supabase, then try again."
        )
    if "invalid login credentials" in lower or "invalid_credentials" in lower:
        return "Invalid email or password. Please check your details and try again."
    if "user already registered" in lower or "already registered" in lower:
        return "An account with this email already exists. Please log in instead."
    if "password should be at least" in lower or "password is too short" in lower:
        return "Password must be at least 6 characters."
    if "unable to validate email" in lower or "invalid email" in lower:
        return "Please enter a valid email address."
    if "rate limit" in lower or "too many requests" in lower:
        return "Too many attempts. Please wait a moment and try again."
    if "network" in lower or "connection" in lower:
        return "Could not connect to authentication service. Please try again."

    # Return original message if no mapping matched (strip internal noise)
    return msg.split("(")[0].strip() or "Authentication failed. Please try again."


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(payload: AuthPayload):
    if not payload.email or "@" not in payload.email:
        raise HTTPException(status_code=400, detail="Please enter a valid email address.")
    if not payload.password or len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")

    db = get_supabase()
    try:
        res = db.auth.sign_up({
            "email": payload.email.strip().lower(),
            "password": payload.password,
        })
        # Supabase returns user=None when email is already registered (some versions)
        if res.user is None:
            # Could be duplicate — try to give a helpful message
            raise HTTPException(
                status_code=400,
                detail="Registration failed. This email may already be registered. Try logging in instead."
            )
        log.info(f"New user registered: {payload.email}")
        return {
            "message": (
                "Account created! Please check your email inbox (and spam folder) "
                "for a confirmation link. Click it to activate your account, then log in."
            )
        }
    except HTTPException:
        raise
    except Exception as exc:
        clean = _clean_supabase_error(exc)
        log.warning(f"Register failed for {payload.email}: {exc}")
        raise HTTPException(status_code=400, detail=clean)


@router.post("/login")
async def login(payload: AuthPayload):
    if not payload.email or "@" not in payload.email:
        raise HTTPException(status_code=400, detail="Please enter a valid email address.")
    if not payload.password:
        raise HTTPException(status_code=400, detail="Password is required.")

    db = get_supabase()
    try:
        res = db.auth.sign_in_with_password({
            "email": payload.email.strip().lower(),
            "password": payload.password,
        })
        if res.session is None:
            raise HTTPException(status_code=401, detail="Invalid email or password.")

        log.info(f"User logged in: {payload.email}")
        return {
            "access_token": res.session.access_token,
            "token_type": "bearer",
            "user_id": res.user.id,
            "email": res.user.email,
        }
    except HTTPException:
        raise
    except Exception as exc:
        clean = _clean_supabase_error(exc)
        log.warning(f"Login failed for {payload.email}: {exc}")
        # Use 401 for credential errors, 400 for everything else
        lower = clean.lower()
        code = 401 if any(w in lower for w in ["password", "credential", "invalid", "confirmed"]) else 400
        raise HTTPException(status_code=code, detail=clean)


@router.post("/logout")
async def logout():
    return {"message": "Logged out successfully."}
