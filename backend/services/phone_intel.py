"""
ScamGuard — Phone Intelligence Service  (v2.0 — Normalized)
=============================================================
Replaces the hand-rolled regex/prefix-table implementation.

ROOT CAUSE OF OLD BUGS:
  • _ZW_PREFIXES / _ECONET_3 / _NETONE_3 tables only covered Zimbabwe
    prefixes, so any non-ZW number (e.g. Polish +48) fell through to
    "Unknown" carrier and was sometimes wrongly flagged as Zimbabwe.
  • _to_e164() always fell back to "+263" + sub, so "48506716775"
    became "+263506716775" — a valid-looking but wrong ZW number.

HOW IT IS FIXED:
  • All structural analysis is delegated to parse_phone() from
    services/phone_normalizer.py which uses the phonenumbers library.
  • analyse_phone() is now a thin wrapper that returns PhoneIntelResult.
  • enrich_with_community() is unchanged — it works on the result object.
  • All fields the router (routers/phone.py) expects are still present.

NO CHANGES needed in routers/phone.py — same PhoneIntelResult API.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from services.phone_normalizer import parse_phone, ParsedPhone
from utils.logger import get_logger

log = get_logger(__name__)


# ── Result dataclass (same field names as before — router unchanged) ─────────

@dataclass
class PhoneIntelResult:
    raw_number:           str   = ""
    normalized:           str   = ""
    e164_format:          str   = ""
    is_valid:             bool  = False
    country:              str   = "Unknown"
    country_code:         str   = ""
    carrier:              str   = "Unknown"
    number_type:          str   = "unknown"
    local_format:         str   = ""
    is_voip:              bool  = False
    is_high_risk_origin:  bool  = False
    is_zimbabwe:          bool  = False
    report_count:         int   = 0
    recent_report_count:  int   = 0
    last_reported:        Optional[str] = None
    first_seen:           Optional[str] = None
    top_scam_categories:  List[str] = field(default_factory=list)
    risk_indicators:      List[str] = field(default_factory=list)
    intel_summary:        str   = ""


# ── Scam category keyword patterns (unchanged from v1) ───────────────────────

_CATEGORY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"ecocash|mobile.?money|momo",          re.I), "EcoCash Fraud"),
    (re.compile(r"phish|verify|account|login|credential", re.I), "Phishing"),
    (re.compile(r"job|employ|vacancy|hiring|salary",     re.I), "Fake Job Scam"),
    (re.compile(r"prize|winner|lottery|won|claim",       re.I), "Lottery Scam"),
    (re.compile(r"crypto|bitcoin|invest|profit|double",  re.I), "Crypto Fraud"),
    (re.compile(r"landlord|deposit|rental|property",     re.I), "Fake Landlord"),
    (re.compile(r"romance|love|partner|soldier|nurse",   re.I), "Romance Scam"),
    (re.compile(r"customs|parcel|delivery|package|dhl",  re.I), "Parcel Scam"),
    (re.compile(r"irs|tax|refund|government|zimra",      re.I), "Government Impersonation"),
    (re.compile(r"whatsapp|telegram|forward|chain",      re.I), "WhatsApp Scam"),
]


# ── Core analysis ─────────────────────────────────────────────────────────────

def analyse_phone(number: str) -> PhoneIntelResult:
    """
    Parse and structurally analyse a phone number.
    Delegates all parsing to phone_normalizer.parse_phone() which uses
    the phonenumbers library — no hand-rolled prefix tables.

    Returns PhoneIntelResult with no community data yet.
    Call enrich_with_community() to add report-based fields.
    """
    parsed: ParsedPhone = parse_phone(number)

    local_fmt = parsed.national_format or parsed.e164

    result = PhoneIntelResult(
        raw_number          = number,
        normalized          = parsed.e164,
        e164_format         = parsed.e164,
        is_valid            = parsed.is_valid,
        country             = parsed.country,
        country_code        = parsed.country_code,
        carrier             = parsed.carrier,
        number_type         = parsed.number_type,
        local_format        = local_fmt,
        is_voip             = parsed.is_voip,
        is_high_risk_origin = parsed.is_high_risk_origin,
        is_zimbabwe         = parsed.is_zimbabwe,
    )

    result.intel_summary = _build_summary(result, 0)
    return result


# ── Community enrichment ──────────────────────────────────────────────────────

def enrich_with_community(result: PhoneIntelResult, reports: list[dict]) -> PhoneIntelResult:
    """
    Augment PhoneIntelResult with data from community reports.
    Mutates and returns the same result object.
    """
    if not reports:
        result.intel_summary = _build_summary(result, 0)
        return result

    result.report_count = len(reports)

    # Recent reports (last 30 days)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    recent = [r for r in reports if (r.get("created_at") or "") >= cutoff]
    result.recent_report_count = len(recent)

    # Timestamps
    timestamps = sorted(
        [r["created_at"] for r in reports if r.get("created_at")],
        reverse=True,
    )
    if timestamps:
        result.last_reported = timestamps[0]
        result.first_seen    = timestamps[-1]

    # Category extraction from descriptions
    all_text   = " ".join(r.get("description", "") for r in reports)
    categories: list[str] = []
    for pattern, label in _CATEGORY_PATTERNS:
        if pattern.search(all_text) and label not in categories:
            categories.append(label)
    result.top_scam_categories = categories[:5]

    # Risk indicators
    indicators: list[str] = []
    if result.is_high_risk_origin:
        indicators.append(f"Originates from high-risk country ({result.country})")
    if result.is_voip:
        indicators.append("VOIP / virtual number — harder to trace")
    if result.report_count >= 5:
        indicators.append(f"Reported {result.report_count} times by community members")
    elif result.report_count >= 2:
        indicators.append(f"Reported {result.report_count} times")
    if result.recent_report_count >= 3:
        indicators.append(f"{result.recent_report_count} reports in the last 30 days — actively flagged")
    if "EcoCash Fraud" in categories:
        indicators.append("Linked to EcoCash mobile money fraud")
    if "Phishing" in categories:
        indicators.append("Linked to phishing / credential theft")
    if "Fake Job Scam" in categories:
        indicators.append("Linked to fake job offer scams")
    if "Lottery Scam" in categories:
        indicators.append("Linked to lottery / prize scams")
    if not result.is_valid:
        indicators.append("Number format is non-standard or invalid")

    result.risk_indicators = indicators
    result.intel_summary   = _build_summary(result, len(reports))
    return result


# ── Summary builder ───────────────────────────────────────────────────────────

def _build_summary(r: PhoneIntelResult, report_count: int) -> str:
    parts: list[str] = []

    if r.country != "Unknown":
        parts.append(f"{r.country} number")
    if r.carrier not in ("Unknown", ""):
        parts.append(f"carrier: {r.carrier}")
    if r.number_type not in ("unknown", ""):
        type_label = {
            "mobile":   "mobile",
            "fixed":    "fixed line",
            "voip":     "VOIP",
            "toll_free": "toll-free",
        }.get(r.number_type, r.number_type)
        parts.append(type_label)

    if report_count == 0:
        parts.append("no community reports on record")
    elif report_count == 1:
        parts.append("1 community report")
    else:
        parts.append(f"{report_count} community reports")

    if r.is_high_risk_origin:
        parts.append("flagged as high-risk origin")
    if r.is_voip:
        parts.append("virtual/VOIP number")
    if not r.is_valid:
        parts.append("non-standard format")

    base = " · ".join(parts).capitalize() if parts else "Phone number analysed."
    return base + "."
