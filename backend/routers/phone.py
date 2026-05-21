"""
Phone Intelligence Router
=========================
GET /api/v1/phone-intel?number=...
Returns structural phone analysis + community intelligence summary.
Public endpoint — no auth required.
"""
from fastapi import APIRouter, Request, Query, HTTPException
from slowapi import Limiter
from slowapi.util import get_remote_address
from pydantic import BaseModel
from typing import List, Optional

from database import get_supabase
from services.phone_intel import analyse_phone, enrich_with_community
from services.entity_service import get_reports_for_entity, upsert_entity
from utils.normalizer import normalize_value
from utils.logger import get_logger
from config import CHECK_RATE_LIMIT

log = get_logger(__name__)
router = APIRouter(prefix="/api/v1", tags=["phone-intel"])
limiter = Limiter(key_func=get_remote_address)


class PhoneIntelResponse(BaseModel):
    raw_number:            str
    normalized:            str
    e164_format:           str
    is_valid:              bool
    country:               str
    country_code:          str
    carrier:               str
    number_type:           str
    local_format:          str
    is_voip:               bool
    is_high_risk_origin:   bool
    is_zimbabwe:           bool
    report_count:          int
    recent_report_count:   int
    last_reported:         Optional[str]
    first_seen:            Optional[str]
    top_scam_categories:   List[str]
    risk_indicators:       List[str]
    intel_summary:         str


@router.get("/phone-intel", response_model=PhoneIntelResponse)
@limiter.limit(CHECK_RATE_LIMIT)
async def phone_intelligence(
    request: Request,
    number: str = Query(..., min_length=5, max_length=25, description="Phone number to analyse"),
):
    """
    Analyse a phone number: country, carrier, VOIP detection,
    community reports, risk indicators.
    """
    if not number.strip():
        raise HTTPException(status_code=400, detail="Phone number is required.")

    # Structural analysis (pure Python, no API calls)
    result = analyse_phone(number)

    # Enrich with community reports from DB
    try:
        db = get_supabase()
        norm = normalize_value("phone", number)
        entity = upsert_entity(db, "phone", norm)
        reports = get_reports_for_entity(db, entity["id"], limit=100)
        result = enrich_with_community(result, reports)
    except Exception as exc:
        log.warning(f"Phone intel DB enrichment failed (non-fatal): {exc}")

    return PhoneIntelResponse(
        raw_number          = result.raw_number,
        normalized          = result.normalized,
        e164_format         = result.e164_format,
        is_valid            = result.is_valid,
        country             = result.country,
        country_code        = result.country_code,
        carrier             = result.carrier,
        number_type         = result.number_type,
        local_format        = result.local_format,
        is_voip             = result.is_voip,
        is_high_risk_origin = result.is_high_risk_origin,
        is_zimbabwe         = result.is_zimbabwe,
        report_count        = result.report_count,
        recent_report_count = result.recent_report_count,
        last_reported       = result.last_reported,
        first_seen          = result.first_seen,
        top_scam_categories = result.top_scam_categories,
        risk_indicators     = result.risk_indicators,
        intel_summary       = result.intel_summary,
    )
