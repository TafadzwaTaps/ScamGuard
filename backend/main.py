import os
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from config import ALLOWED_ORIGINS
from routers import check, report, entities, auth, scan
from middleware.security import (
    SecurityHeadersMiddleware,
    RequestSizeLimitMiddleware,
    SuspiciousRequestMiddleware,
)
from utils.logger import get_logger

log = get_logger(__name__)

# ── Environment ────────────────────────────────────────────────────────────
IS_PRODUCTION = os.getenv("RENDER", "") != "" or os.getenv("ENVIRONMENT", "") == "production"

# ── Rate limiter ───────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ── App ────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="ScamGuard API",
    description="Scam & Fraud Detection — Supabase + NLP powered.",
    version="3.0.0",
    # Disable Swagger UI in production to reduce attack surface
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
)

# ── Middleware stack (order matters — outermost wraps first) ───────────────

# 1. Block malicious request patterns before anything else runs
app.add_middleware(SuspiciousRequestMiddleware)

# 2. Enforce body size limit (512 KB for API)
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=524_288)

# 3. Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# 4. CORS — tighten in production via ALLOWED_ORIGINS env var
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID", "X-Response-Time"],
    max_age=600,
)

# 5. Security headers — HTTPS enforcement only in production
app.add_middleware(SecurityHeadersMiddleware, https_only=IS_PRODUCTION)

# ── Routers ────────────────────────────────────────────────────────────────
app.include_router(check.router)
app.include_router(report.router)
app.include_router(entities.router)
app.include_router(auth.router)
app.include_router(scan.router)

# ── Static frontend ────────────────────────────────────────────────────────
_BACKEND_DIR  = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_BACKEND_DIR, ".."))
STATIC_DIR    = os.path.join(_PROJECT_ROOT, "frontend", "static")
INDEX_FILE    = os.path.join(STATIC_DIR, "index.html")

if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    log.info(f"Serving static files from {STATIC_DIR}")


def _serve(filename: str):
    p = os.path.join(STATIC_DIR, filename)
    return FileResponse(p) if os.path.isfile(p) else JSONResponse(
        {"detail": f"{filename} not found"}, status_code=404
    )


@app.get("/",           include_in_schema=False)
async def serve_index():    return _serve("index.html")

@app.get("/login",      include_in_schema=False)
async def serve_login():    return _serve("login.html")

@app.get("/register",   include_in_schema=False)
async def serve_register(): return _serve("register.html")

@app.get("/confirm",    include_in_schema=False)
async def serve_confirm():  return _serve("confirm.html")

@app.get("/privacy",    include_in_schema=False)
async def serve_privacy():  return _serve("privacy.html")

@app.get("/terms",      include_in_schema=False)
async def serve_terms():    return _serve("terms.html")


# ── Health ─────────────────────────────────────────────────────────────────
@app.get("/health", tags=["health"])
def health():
    return {"status": "ok", "version": "3.0.0"}
