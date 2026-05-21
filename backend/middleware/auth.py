"""
ScamGuard — JWT Authentication Middleware (v2)
==============================================
Supports BOTH token types that Supabase issues:

  HS256 — session tokens from sign_in_with_password()
           Verified with SUPABASE_JWT_SECRET (symmetric)

  ES256 — confirmation/magic-link tokens
           Verified via Supabase JWKS endpoint (asymmetric)
           Public keys are cached in memory (TTL 1 hour)

Root cause of "Session expired" bug:
  Supabase email confirmation tokens use ES256.
  The old middleware only accepted HS256.
  ES256 tokens → JWTError → 401 → "Session expired" message.
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

# ── JWKS cache ─────────────────────────────────────────────────────────────
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
        raise JWTError("JWKS not available")
    # python-jose accepts the full JWKS dict and picks the right key by kid
    return jwt.decode(
        token,
        jwks,
        algorithms=["ES256"],
        options={"verify_aud": False},
    )


def _decode_token(token: str) -> dict:
    """
    Try HS256 first (most common — login sessions).
    Fall back to ES256 (confirmation/magic-link tokens).
    Raises JWTError if both fail.
    """
    # Peek at the header to choose algorithm without full decode
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
    else:
        return _decode_hs256(token)


def _friendly_error(exc: JWTError) -> str:
    msg = str(exc).lower()
    if "expired" in msg or "exp" in msg:
        return "Your session has expired. Please log in again."
    if "signature" in msg or "invalid" in msg:
        return "Invalid authentication token. Please log in again."
    return "Authentication failed. Please log in again."


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
        # Ensure required claim exists
        if not payload.get("sub"):
            raise JWTError("Token missing 'sub' claim")
        return payload
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
    """Dependency: optionally validates a JWT. Returns None if absent/invalid."""
    if not credentials or not credentials.credentials:
        return None
    try:
        payload = _decode_token(credentials.credentials)
        return payload if payload.get("sub") else None
    except JWTError:
        return None
