"""
Enhanced /api/v1/scan endpoint
================================
Superset of existing /api/v1/check — adds:
  - Zimbabwe intelligence layer
  - Explainable AI
  - URL phishing analysis
  - Structured scan_id for history

Preserves existing /api/v1/check endpoint fully.
All new logic lives in separate service modules.
"""
from __future__ import annotations
import uuid
from fastapi import APIRouter, Request, Depends
from slowapi import Limiter
from slowapi.util import get_remote_address
from datetime import datetime

from database import get_supabase
from models.schemas import (
    CheckRequest, ScanResponse, NLPResult, ReportOut,
    ZimIntelResponse, ZimFlag, ExplainResponse, RiskFactorOut, URLAnalysisResponse,
)
from services.entity_service import (
    upsert_entity, get_reports_for_entity,
    count_recent_reports, log_check, get_keywords,
)
from services.nlp_service import get_nlp_service
from services.scoring import compute_risk_score, risk_status
from services.zimbabwe_intel import analyse_zimbabwe
from services.explainer import explain
from services.url_analyzer import analyse_url
from middleware.auth import get_optional_user
from utils.normalizer import normalize_value
from utils.logger import get_logger
from config import CHECK_RATE_LIMIT

log = get_logger(__name__)
router = APIRouter(prefix="/api/v1", tags=["scan"])
limiter = Limiter(key_func=get_remote_address)


@router.post("/scan", response_model=ScanResponse)
@limiter.limit(CHECK_RATE_LIMIT)
async def enhanced_scan(
    request: Request,
    payload: CheckRequest,
    user: dict | None = Depends(get_optional_user),
):
    """
    Enhanced scan endpoint. Extends /check with:
    - Zimbabwe-specific intelligence
    - Explainable AI reasoning
    - URL phishing analysis (when type=url)
    - Structured scan_id
    """
    db = get_supabase()
    norm_value = normalize_value(payload.type, payload.value)

    # ── Step 1: Base NLP (reuse existing service) ──────────────────────────
    db_keywords = get_keywords(db)
    nlp = get_nlp_service(db_keywords if db_keywords else None)

    entity = upsert_entity(db, payload.type, norm_value)
    entity_id = entity["id"]

    reports = get_reports_for_entity(db, entity_id, limit=50)
    report_count = entity.get("report_count", len(reports))
    recent_count = count_recent_reports(db, entity_id, days=7)

    all_text = norm_value + " " + " ".join(r["description"] for r in reports)
    nlp_result = nlp.analyse(all_text)

    created_raw = entity.get("created_at")
    try:
        entity_created_at = datetime.fromisoformat(
            created_raw.replace("Z", "+00:00") if created_raw else ""
        )
    except Exception:
        entity_created_at = None

    # ── Step 2: Zimbabwe Intelligence ──────────────────────────────────────
    zim_result = analyse_zimbabwe(all_text)

    # ── Step 3: URL Analysis (only when type=url) ──────────────────────────
    url_result = None
    url_bonus = 0.0
    if payload.type == "url":
        url_result = analyse_url(norm_value)
        url_bonus = url_result.url_score

    # ── Step 4: Enhanced scoring (base + Zimbabwe + URL bonuses) ──────────
    base_score = compute_risk_score(
        report_count=report_count,
        nlp_score=nlp_result["nlp_score"],
        recent_reports_7d=recent_count,
        entity_created_at=entity_created_at,
    )
    final_score = round(min(100.0, base_score + zim_result.zim_score + url_bonus), 1)
    status = risk_status(final_score)

    # ── Step 5: Explainability ─────────────────────────────────────────────
    explain_result = explain(
        text=all_text,
        matched_keywords=nlp_result["matched_keywords"],
        regex_matches=nlp_result["regex_matches"],
        risk_score=final_score,
        zim_flags=zim_result.flags if zim_result.is_zimbabwe_specific else None,
        report_count=report_count,
    )

    # ── Step 6: Log check ─────────────────────────────────────────────────
    user_id = user["sub"] if user else None
    log_check(db, entity_id, final_score, user_id)

    scan_id = str(uuid.uuid4())
    log.info(f"SCAN id={scan_id} type={payload.type} score={final_score} status={status}")

    # ── Build response ─────────────────────────────────────────────────────
    sample = [
        ReportOut(
            id=r["id"],
            description=r["description"],
            tags=r.get("tags") or [],
            created_at=r["created_at"],
        )
        for r in reports[:3]
    ]

    zim_response = None
    if zim_result.is_zimbabwe_specific:
        zim_response = ZimIntelResponse(
            zim_score=zim_result.zim_score,
            categories=zim_result.categories,
            flags=[ZimFlag(**f) for f in zim_result.flags],
            safety_advice=zim_result.safety_advice,
            is_zimbabwe_specific=True,
        )

    explain_response = ExplainResponse(
        summary=explain_result.summary,
        risk_factors=[
            RiskFactorOut(
                factor=f.factor,
                detail=f.detail,
                severity=f.severity,
                score_contribution=f.score_contribution,
            )
            for f in explain_result.risk_factors
        ],
        urgency_detected=explain_result.urgency_detected,
        impersonation_detected=explain_result.impersonation_detected,
        financial_request_detected=explain_result.financial_request_detected,
        personal_data_request_detected=explain_result.personal_data_request_detected,
        what_to_do=explain_result.what_to_do,
        scam_type_guess=explain_result.scam_type_guess,
    )

    url_response = None
    if url_result:
        url_response = URLAnalysisResponse(
            is_suspicious=url_result.is_suspicious,
            url_score=url_result.url_score,
            flags=url_result.flags,
            explanations=url_result.explanations,
            domain=url_result.domain,
            is_shortened=url_result.is_shortened,
            has_ssl=url_result.has_ssl,
        )

    return ScanResponse(
        risk_score=final_score,
        status=status,
        report_count=report_count,
        nlp_flags=NLPResult(
            matched_keywords=nlp_result["matched_keywords"],
            regex_matches=nlp_result["regex_matches"],
            confidence=nlp_result["confidence"],
        ),
        sample_reports=sample,
        entity_id=entity_id,
        zim_intel=zim_response,
        explanation=explain_response,
        url_analysis=url_response,
        scan_id=scan_id,
    )
