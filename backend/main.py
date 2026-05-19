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
from utils.logger import get_logger

log = get_logger(__name__)

# ── Rate limiter ───────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ── App ────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="ScamGuard API",
    description="Scam & Fraud Detection — Supabase + NLP powered.",
    version="3.0.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# ── Routers ────────────────────────────────────────────────────────────────
app.include_router(check.router)
app.include_router(report.router)
app.include_router(entities.router)
app.include_router(auth.router)
app.include_router(scan.router)  # v3 enhanced scan

# ── Static frontend ────────────────────────────────────────────────────────
_BACKEND_DIR  = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_BACKEND_DIR, ".."))
STATIC_DIR    = os.path.join(_PROJECT_ROOT, "frontend", "static")
INDEX_FILE    = os.path.join(STATIC_DIR, "index.html")

if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    log.info(f"Serving static files from {STATIC_DIR}")


@app.get("/", include_in_schema=False)
async def serve_index():
    if os.path.isfile(INDEX_FILE):
        return FileResponse(INDEX_FILE)
    return JSONResponse({"detail": f"Frontend not found at {INDEX_FILE}"}, status_code=404)


# ── Health ─────────────────────────────────────────────────────────────────
@app.get("/health", tags=["health"])
def health():
    return {"status": "ok", "version": "2.0.0"}
