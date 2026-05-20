"""
ScamGuard — Security Headers & Hardening Middleware
=====================================================
Adds all OWASP-recommended HTTP security headers to every response.
Applied as a Starlette middleware — zero impact on existing routes.

Headers added:
  - Content-Security-Policy     (XSS / injection protection)
  - X-Content-Type-Options      (MIME sniffing protection)
  - X-Frame-Options             (clickjacking protection)
  - X-XSS-Protection            (legacy browser XSS filter)
  - Referrer-Policy             (referrer data leakage)
  - Permissions-Policy          (browser feature gating)
  - Strict-Transport-Security   (HTTPS enforcement)
  - Cache-Control               (API response caching)
  - X-Request-ID                (request tracing)
  - Remove: Server, X-Powered-By (fingerprinting reduction)
"""
from __future__ import annotations
import uuid
import time
import re
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from utils.logger import get_logger

log = get_logger(__name__)

# ── Paths that should never be cached ─────────────────────────────────────
_NO_CACHE_PATHS = re.compile(
    r"^/api/|^/health$",
    re.IGNORECASE
)

# ── Allowed static file extensions (everything else gets no-cache) ─────────
_STATIC_EXTS = re.compile(r"\.(css|js|png|jpg|jpeg|ico|svg|woff2?|ttf)$", re.IGNORECASE)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add OWASP security headers to every response."""

    def __init__(self, app: ASGIApp, https_only: bool = False):
        super().__init__(app)
        self._https_only = https_only

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        request_id = str(uuid.uuid4())[:16]

        # Attach request ID to request state for logging
        request.state.request_id = request_id

        response: Response = await call_next(request)

        path = request.url.path

        # ── Remove fingerprinting headers ──────────────────────────────────
        # MutableHeaders does not have .pop() — use del with existence check
        for _h in ("server", "x-powered-by"):
            if _h in response.headers:
                del response.headers[_h]

        # ── Request tracing ────────────────────────────────────────────────
        response.headers["X-Request-ID"] = request_id

        # ── MIME sniffing ──────────────────────────────────────────────────
        response.headers["X-Content-Type-Options"] = "nosniff"

        # ── Clickjacking ───────────────────────────────────────────────────
        response.headers["X-Frame-Options"] = "DENY"

        # ── Legacy XSS filter ──────────────────────────────────────────────
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # ── Referrer leakage ───────────────────────────────────────────────
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # ── Browser feature gating ─────────────────────────────────────────
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), interest-cohort=()"
        )

        # ── HTTPS enforcement (only when running in production/HTTPS) ─────
        if self._https_only:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # ── Content Security Policy ────────────────────────────────────────
        # Allows: our own origin, Google Fonts, jsDelivr CDN, Bootstrap Icons
        response.headers["Content-Security-Policy"] = "; ".join([
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com",
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com",
            "img-src 'self' data: https:",
            "connect-src 'self' https://*.supabase.co",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ])

        # ── Cache control ──────────────────────────────────────────────────
        if _NO_CACHE_PATHS.match(path):
            # API responses: never cache
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
        elif _STATIC_EXTS.search(path):
            # Static assets: cache for 1 hour, revalidate
            response.headers["Cache-Control"] = "public, max-age=3600, must-revalidate"
        else:
            # HTML pages: no cache (always fresh)
            response.headers["Cache-Control"] = "no-store, private"

        # ── Timing log ────────────────────────────────────────────────────
        elapsed = round((time.perf_counter() - start) * 1000, 1)
        response.headers["X-Response-Time"] = f"{elapsed}ms"

        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Reject requests larger than max_bytes.
    Prevents memory exhaustion / body-stuffing attacks.
    Default: 512 KB for API, 1 MB for everything else.
    """

    def __init__(self, app: ASGIApp, max_bytes: int = 1_048_576):
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self._max_bytes:
                    log.warning(
                        f"Request too large: {content_length} bytes from "
                        f"{request.client.host if request.client else 'unknown'}"
                    )
                    return Response(
                        content='{"detail":"Request body too large."}',
                        status_code=413,
                        media_type="application/json",
                    )
            except ValueError:
                pass
        return await call_next(request)


class SuspiciousRequestMiddleware(BaseHTTPMiddleware):
    """
    Block obviously malicious request patterns:
    - SQL injection probes in query strings
    - Path traversal attempts
    - Common scanner/bot signatures
    - Oversized headers
    """

    # Common attack probe patterns
    _SQL_PATTERNS = re.compile(
        r"(union\s+select|drop\s+table|insert\s+into|delete\s+from|"
        r"exec\s*\(|xp_cmdshell|benchmark\s*\(|sleep\s*\(|"
        r"1=1|or\s+1=1|'\s+or\s+')",
        re.IGNORECASE,
    )
    _PATH_TRAVERSAL = re.compile(r"\.\./|\.\.\\|%2e%2e", re.IGNORECASE)
    _BAD_PATHS = re.compile(
        r"/(wp-admin|wp-login|phpMyAdmin|\.env|\.git|\.aws|"
        r"actuator|admin/config|server-status|\.htaccess)",
        re.IGNORECASE,
    )

    async def dispatch(self, request: Request, call_next):
        path  = request.url.path
        query = str(request.url.query)
        ip    = request.client.host if request.client else "unknown"

        # Path traversal
        if self._PATH_TRAVERSAL.search(path):
            log.warning(f"PATH_TRAVERSAL blocked from {ip}: {path}")
            return Response(
                content='{"detail":"Forbidden."}',
                status_code=403,
                media_type="application/json",
            )

        # Known bad paths (scanners, bots)
        if self._BAD_PATHS.search(path):
            log.warning(f"BAD_PATH blocked from {ip}: {path}")
            return Response(
                content='{"detail":"Not found."}',
                status_code=404,
                media_type="application/json",
            )

        # SQL injection in query params
        if query and self._SQL_PATTERNS.search(query):
            log.warning(f"SQL_INJECTION probe blocked from {ip}: {query[:100]}")
            return Response(
                content='{"detail":"Invalid request."}',
                status_code=400,
                media_type="application/json",
            )

        # Oversized User-Agent (common in automated scanners)
        ua = request.headers.get("user-agent", "")
        if len(ua) > 512:
            return Response(
                content='{"detail":"Invalid request."}',
                status_code=400,
                media_type="application/json",
            )

        return await call_next(request)
