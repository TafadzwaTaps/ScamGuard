"""
ScamGuard — Report Router  /api/v1/report  (v3.1 — Stabilized)
===============================================================
Fix history:
  v3.0 — Rewrote to use Supabase + JWT auth
  v3.1 — [FIX-3] Report ID is now captured directly from insert_report()
          return value, never from get_reports_for_entity()[0] which could
          return a pre-existing report if the DB returns rows newest-first.
        — Wrapped every DB operation in its own try/except with a
          meaningful log entry so failures are always traceable.
        — Duplicate-check failure is fail-open (non-fatal) with a warning log.
        — Score recompute failure is non-fatal; report is already saved.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request

from database import get_supabase
from models.schemas import ReportCreate, ReportResponse
from services.entity_service import (
    upsert_entity, get_reports_for_entity, count_recent_reports,
    insert_report, update_entity_score, user_already_reported, get_keywords,
)
from services.nlp_service import get_nlp_service
from services.scoring import compute_risk_score, risk_status
from middleware.auth import get_current_user
from utils.normalizer import normalize_value, sanitize_text, is_safe_text
from utils.logger import get_logger
from datetime import datetime

log = get_logger(__name__)
router = APIRouter(prefix="/api/v1", tags=["report"])


@router.post("/report", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def submit_report(
    payload: ReportCreate,
    user: dict = Depends(get_current_user),
):
    db      = get_supabase()
    user_id = user.get("sub", "")

    if not user_id:
        log.error("JWT 'sub' claim missing — token may be malformed or from an unsupported flow")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token. Please log in again.",
        )

    # ── Sanitise inputs ─────────────────────────────────────────────────────
    norm_value  = normalize_value(payload.type, payload.value)
    description = sanitize_text(payload.description)

    if not is_safe_text(description):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Report description contains invalid content.",
        )

    log.info(
        f"REPORT attempt | type={payload.type} | user={user_id[:8]}… | "
        f"entity={norm_value[:40]}"
    )

    # ── Find or create entity ────────────────────────────────────────────────
    try:
        entity = upsert_entity(db, payload.type, norm_value)
    except Exception as exc:
        log.error(f"Entity upsert failed | user={user_id[:8]}… | error={exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database temporarily unavailable. Please try again.",
        )

    entity_id = entity["id"]

    # ── Duplicate check ──────────────────────────────────────────────────────
    try:
        already_reported = user_already_reported(db, entity_id, user_id)
    except Exception as exc:
        # Non-fatal: a failed duplicate check should not block the submission.
        # The DB unique constraint will catch true duplicates at insert time.
        log.warning(
            f"Duplicate check failed (fail-open) | entity={entity_id} | "
            f"user={user_id[:8]}… | error={exc}"
        )
        already_reported = False

    if already_reported:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You have already submitted a report for this entity.",
        )

    # ── Insert report — [FIX-3] use the ID from the insert response directly ─
    try:
        inserted  = insert_report(db, entity_id, user_id, description, payload.tags or [])
        report_id = inserted.get("id", "")
        if not report_id:
            raise ValueError("insert_report returned a row without an 'id' field")
    except Exception as exc:
        log.error(
            f"Report insert failed | entity={entity_id} | "
            f"user={user_id[:8]}… | error={exc}"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not save report. Please try again in a moment.",
        )

    # ── Recompute risk score (non-fatal if this fails) ───────────────────────
    score = entity.get("risk_score", 0.0)
    try:
        reports      = get_reports_for_entity(db, entity_id, limit=50)
        recent_count = count_recent_reports(db, entity_id, days=7)

        db_keywords  = get_keywords(db)
        nlp          = get_nlp_service(db_keywords if db_keywords else None)
        all_text     = norm_value + " " + " ".join(r["description"] for r in reports)
        nlp_result   = nlp.analyse(all_text)

        created_raw = entity.get("created_at")
        try:
            entity_created_at = datetime.fromisoformat(
                created_raw.replace("Z", "+00:00") if created_raw else ""
            )
        except Exception:
            entity_created_at = None

        score = compute_risk_score(
            report_count=len(reports),
            nlp_score=nlp_result["nlp_score"],
            recent_reports_7d=recent_count,
            entity_created_at=entity_created_at,
        )
        update_entity_score(db, entity_id, score, len(reports))

    except Exception as exc:
        # Report is already saved — score recompute failure is not user-facing
        log.warning(
            f"Score recompute failed (non-fatal) | entity={entity_id} | error={exc}"
        )

    log.info(
        f"REPORT saved | id={report_id} | entity={entity_id} | "
        f"user={user_id[:8]}… | score={score}"
    )

    return ReportResponse(
        id=report_id,       # [FIX-3] Always the freshly inserted row's ID
        entity_id=entity_id,
        risk_score=score,
        message="Report submitted successfully. Thank you for helping protect the community.",
    )
