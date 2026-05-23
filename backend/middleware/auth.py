"""
ScamGuard — JWT Authentication Middleware (v2.1 — Stabilized)
=============================================================
Supports BOTH token types that Supabase issues:

  HS256 — session tokens from sign_in_with_password()
           Verified with SUPABASE_JWT_SECRET (symmetric)

  ES256 — confirmation/magic-link tokens
           Verified via Supabase JWKS endpoint (asymmetric)
           Public keys are cached in memory (TTL 1 hour)

Fix history:
  v2.0 — Added ES256 / JWKS support (root cause of "Session expired" bug)
  v2.1 — Cleaner error messages; hardened sub-claim validation;
          get_optional_user now also validates expiry before returning payload
"""
from __future__ import annotations
import os
import time
import httpx
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError, ExpiredSignatureError

from config import SUPABASE_URL, SUPABASE_JWT_SECRET
from utils.logger import get_logger

log = get_logger(__name__)
_bearer = HTTPBearer(auto_error=False)

# ── JWKS cache ──────────────────────────────────────────────────────────────
_jwks_cache: dict = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600  # re-fetch every hour


def _get_jwks() -> dict:
    """Fetch and cache Supabase JWKS (public keys for ES256 tokens)."""
    global _jwks_cache, _jwks_fetched_at
    now = time.monotonic()
    if _jwks_cache and (now - _jwks_fetched_at) < _JWKS_TTL:
        return _jwks_cache
    try:
        url = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
        resp = httpx.get(url, timeout=5)
        resp.raise_for_status()
        _jwks_cache = resp.json()
        _jwks_fetched_at = now
        log.info("JWKS refreshed from Supabase")
    except Exception as exc:
        log.warning(f"JWKS fetch failed (ES256 tokens will not verify): {exc}")
    return _jwks_cache


def _decode_hs256(token: str) -> dict:
    """Decode HS256 token with shared JWT secret."""
    return jwt.decode(
        token,
        SUPABASE_JWT_SECRET,
        algorithms=["HS256"],
        options={"verify_aud": False},
    )


def _decode_es256(token: str) -> dict:
    """Decode ES256 token using Supabase JWKS public keys."""
    jwks = _get_jwks()
    if not jwks:
        raise JWTError("JWKS unavailable — cannot verify ES256 token")
    return jwt.decode(
        token,
        jwks,
        algorithms=["ES256"],
        options={"verify_aud": False},
    )


def _decode_token(token: str) -> dict:
    """
    Inspect the JWT header to select the right algorithm, then decode.
    Falls back gracefully: unknown alg → try HS256 → try ES256.
    Raises JWTError if all attempts fail.
    """
    try:
        import base64, json as _json
        header = _json.loads(
            base64.urlsafe_b64decode(token.split(".")[0] + "==")
        )
        alg = header.get("alg", "HS256")
    except Exception:
        alg = "HS256"

    if alg == "ES256":
        return _decode_es256(token)

    # Default: HS256
    try:
        return _decode_hs256(token)
    except JWTError:
        # Last-ditch: maybe header lied — try ES256
        try:
            return _decode_es256(token)
        except Exception:
            raise  # re-raise the ES256 error (most informative)


def _friendly_error(exc: JWTError) -> str:
    msg = str(exc).lower()
    if "expired" in msg or isinstance(exc, ExpiredSignatureError):
        return "Your session has expired. Please log in again."
    if "signature" in msg or "invalid" in msg or "verify" in msg:
        return "Invalid authentication token. Please log in again."
    if "jwks" in msg or "unavailable" in msg:
        return "Authentication service temporarily unavailable. Please try again."
    return "Authentication failed. Please log in again."


def _validate_payload(payload: dict) -> dict:
    """
    Ensure the decoded payload contains the minimum required claims.
    Raises JWTError if any required claim is missing or invalid.
    """
    sub = payload.get("sub") or payload.get("user_id") or payload.get("id")
    if not sub:
        raise JWTError("Token is missing the 'sub' (user ID) claim")
    # Normalise — always expose as 'sub'
    payload["sub"] = str(sub)
    return payload


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """Dependency: requires a valid JWT. Returns decoded payload."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = _decode_token(credentials.credentials)
        return _validate_payload(payload)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your session has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_friendly_error(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Optional[dict]:
    """
    Dependency: optionally validates a JWT.
    Returns the decoded payload if valid, None if absent or invalid.
    Never raises — always safe to use on public endpoints.
    """
    if not credentials or not credentials.credentials:
        return None
    try:
        payload = _decode_token(credentials.credentials)
        return _validate_payload(payload)
    except JWTError:
        return None
    except Exception:
        return None
