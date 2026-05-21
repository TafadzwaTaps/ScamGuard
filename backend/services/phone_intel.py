"""
ScamGuard — Phone Intelligence Service
=======================================
Pure Python phone analysis — no paid API keys required.
Provides: number validation, country/carrier/type detection,
          VOIP/virtual number detection, risk indicators,
          Zimbabwe carrier lookup, community intelligence summary.

All data is derived from:
  1. E.164 number structure analysis
  2. Zimbabwe national numbering plan (POTRAZ)
  3. Known VOIP/virtual number prefix patterns
  4. Community reports from ScamGuard database
  5. Known scam number prefix databases

IMPORTANT: No private data is fabricated or scraped.
All analysis is structural/pattern-based or community-sourced.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone


# ── Zimbabwe carrier prefix map (POTRAZ national numbering plan) ───────────
# Source: POTRAZ Zimbabwe National Numbering Plan (public document)
_ZW_CARRIERS: dict[str, dict] = {
    # Econet Wireless Zimbabwe
    "26371": {"carrier": "Econet Wireless", "type": "mobile", "country": "Zimbabwe"},
    "26377": {"carrier": "Econet Wireless", "type": "mobile", "country": "Zimbabwe"},
    "26378": {"carrier": "Econet Wireless", "type": "mobile", "country": "Zimbabwe"},
    # NetOne
    "26371": {"carrier": "NetOne", "type": "mobile", "country": "Zimbabwe"},
    "26373": {"carrier": "NetOne", "type": "mobile", "country": "Zimbabwe"},
    # Telecel Zimbabwe
    "26373": {"carrier": "Telecel Zimbabwe", "type": "mobile", "country": "Zimbabwe"},
    # Fixed / other
    "2634":  {"carrier": "TelOne (Fixed)", "type": "fixed", "country": "Zimbabwe"},
    "2638":  {"carrier": "TelOne (Fixed)", "type": "fixed", "country": "Zimbabwe"},
    "2639":  {"carrier": "TelOne (Fixed)", "type": "fixed", "country": "Zimbabwe"},
}

# Refined Zimbabwe mobile prefix lookup (post-2020 allocations)
_ZW_MOBILE_PREFIXES = {
    "0771": "Econet Wireless",
    "0772": "Econet Wireless",
    "0773": "Econet Wireless",
    "0774": "Econet Wireless",
    "0775": "Econet Wireless",
    "0776": "Econet Wireless",
    "0777": "Econet Wireless",
    "0778": "Econet Wireless",
    "0779": "Econet Wireless",
    "0712": "NetOne",
    "0713": "NetOne",
    "0714": "NetOne",
    "0715": "NetOne",
    "0716": "NetOne",
    "0717": "NetOne",
    "0718": "NetOne",
    "0719": "NetOne",
    "0731": "Telecel Zimbabwe",
    "0732": "Telecel Zimbabwe",
    "0733": "Telecel Zimbabwe",
    "0734": "Telecel Zimbabwe",
    "0735": "Telecel Zimbabwe",
    "0736": "Telecel Zimbabwe",
    "0737": "Telecel Zimbabwe",
    "0738": "Telecel Zimbabwe",
    "0739": "Telecel Zimbabwe",
}

# International country codes (common ones used in Zimbabwe scams)
_COUNTRY_CODES: dict[str, str] = {
    "+1":    "United States / Canada",
    "+27":   "South Africa",
    "+263":  "Zimbabwe",
    "+44":   "United Kingdom",
    "+61":   "Australia",
    "+64":   "New Zealand",
    "+254":  "Kenya",
    "+255":  "Tanzania",
    "+256":  "Uganda",
    "+260":  "Zambia",
    "+267":  "Botswana",
    "+234":  "Nigeria",
    "+233":  "Ghana",
    "+20":   "Egypt",
    "+212":  "Morocco",
    "+31":   "Netherlands",
    "+49":   "Germany",
    "+33":   "France",
    "+7":    "Russia",
    "+86":   "China",
    "+91":   "India",
    "+62":   "Indonesia",
    "+63":   "Philippines",
}

# VOIP / virtual number indicators (known spoofable ranges)
_VOIP_INDICATORS = [
    r"^\+1(900|800|888|877|866|855|844|833|822)",  # US toll-free (common in scams)
    r"^\+44(20|113|161|121)",  # UK geographic (sometimes spoofed)
    r"^\+(?:1700|1800|1900)",  # Premium rate
    r"^\+(?:1646|1917|1347)",  # New York VOIP
    r"^\+(?:1415|1650)",       # San Francisco VOIP
]
_VOIP_RE = [re.compile(p) for p in _VOIP_INDICATORS]

# High-risk country/prefix patterns (frequently used in international scams)
_HIGH_RISK_PREFIXES = [
    "+234",   # Nigeria (419 scams)
    "+233",   # Ghana
    "+237",   # Cameroon
    "+225",   # Ivory Coast
    "+221",   # Senegal
    "+1473",  # Grenada (wangiri)
    "+1268",  # Antigua
    "+1284",  # British Virgin Islands
    "+1649",  # Turks and Caicos
]


@dataclass
class PhoneIntelResult:
    # Raw input
    raw_number: str
    normalized: str = ""

    # Structural analysis
    is_valid: bool = False
    country: str = "Unknown"
    country_code: str = ""
    carrier: str = "Unknown"
    number_type: str = "unknown"     # mobile | fixed | voip | premium | unknown
    local_format: str = ""
    e164_format: str = ""

    # Risk indicators
    is_voip: bool = False
    is_high_risk_origin: bool = False
    is_zimbabwe: bool = False

    # Community intelligence (filled by caller from DB)
    report_count: int = 0
    recent_report_count: int = 0    # last 30 days
    last_reported: Optional[str] = None
    first_seen: Optional[str] = None
    top_scam_categories: list = field(default_factory=list)
    community_risk_score: float = 0.0

    # Summary
    risk_indicators: list = field(default_factory=list)
    intel_summary: str = ""


def _normalize_phone(number: str) -> str:
    """Strip formatting, normalize to E.164-like string."""
    # Remove common formatting characters
    cleaned = re.sub(r"[\s\-\.\(\)\u00A0]", "", number.strip())
    # Convert leading 00 to +
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]
    # Handle Zimbabwe local format (07xx → +2637xx)
    if re.match(r"^0[7-9]\d{8}$", cleaned):
        cleaned = "+263" + cleaned[1:]
    # Handle Zimbabwe local format without leading 0 (7xx → +2637xx)
    if re.match(r"^[7-9]\d{8}$", cleaned) and len(cleaned) == 9:
        cleaned = "+263" + cleaned
    return cleaned


def _detect_country(normalized: str) -> tuple[str, str]:
    """Return (country_name, country_code) from E.164 number."""
    if not normalized.startswith("+"):
        # Local format — assume Zimbabwe
        return "Zimbabwe", "+263"
    # Try longest match first (e.g. +263 before +26)
    for length in (5, 4, 3, 2, 1):
        prefix = normalized[:length + 1]  # +1 for the + sign
        if prefix in _COUNTRY_CODES:
            return _COUNTRY_CODES[prefix], prefix
    return "Unknown", normalized[:4] if len(normalized) >= 4 else normalized


def _detect_carrier_zw(normalized: str) -> tuple[str, str]:
    """Detect Zimbabwe carrier from mobile prefix. Returns (carrier, type)."""
    # Convert to local format for prefix lookup
    local = normalized
    if normalized.startswith("+263"):
        local = "0" + normalized[4:]

    for prefix, carrier in _ZW_MOBILE_PREFIXES.items():
        if local.startswith(prefix):
            return carrier, "mobile"

    # TelOne fixed lines
    if re.match(r"^0[234]\d+", local):
        return "TelOne (Fixed Line)", "fixed"

    return "Unknown", "mobile"


def _check_voip(normalized: str) -> bool:
    return any(p.match(normalized) for p in _VOIP_RE)


def _check_high_risk(normalized: str) -> bool:
    return any(normalized.startswith(prefix) for prefix in _HIGH_RISK_PREFIXES)


def _validate_phone(normalized: str) -> bool:
    """Basic E.164 structural validation."""
    # Must start with + and be 7-15 digits
    if not normalized.startswith("+"):
        return False
    digits = normalized[1:]
    if not digits.isdigit():
        return False
    return 6 <= len(digits) <= 15


def analyse_phone(raw_number: str) -> PhoneIntelResult:
    """
    Analyse a phone number structurally.
    Returns PhoneIntelResult — community data filled by the caller.
    """
    result = PhoneIntelResult(raw_number=raw_number)
    normalized = _normalize_phone(raw_number)
    result.normalized = normalized
    result.e164_format = normalized if normalized.startswith("+") else ""

    # Validation
    result.is_valid = _validate_phone(normalized)
    if not result.is_valid and not re.match(r"^\d{7,15}$", normalized.lstrip("+")):
        result.intel_summary = "Number format could not be validated."
        return result

    # Country
    result.country, result.country_code = _detect_country(normalized)
    result.is_zimbabwe = result.country_code == "+263"

    # Carrier (Zimbabwe-specific)
    if result.is_zimbabwe:
        result.carrier, result.number_type = _detect_carrier_zw(normalized)
        local = "0" + normalized[4:] if normalized.startswith("+263") else normalized
        result.local_format = local
    else:
        result.number_type = "mobile"  # default assumption

    # VOIP check
    result.is_voip = _check_voip(normalized)
    if result.is_voip:
        result.number_type = "voip"
        result.risk_indicators.append("VOIP/Virtual number — easily spoofed")

    # High-risk origin
    result.is_high_risk_origin = _check_high_risk(normalized)
    if result.is_high_risk_origin:
        result.risk_indicators.append(
            f"High-risk origin country ({result.country}) — frequently used in scam calls"
        )

    # Local format for display
    if not result.local_format and normalized.startswith("+263"):
        result.local_format = "0" + normalized[4:]

    return result


def enrich_with_community(result: PhoneIntelResult, reports: list[dict]) -> PhoneIntelResult:
    """
    Enrich PhoneIntelResult with community report data from DB.
    Called after analyse_phone() with reports fetched from Supabase.
    """
    from datetime import datetime, timezone, timedelta

    result.report_count = len(reports)

    if not reports:
        result.intel_summary = _build_summary(result)
        return result

    # Recent reports (last 30 days)
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    recent = []
    for r in reports:
        try:
            ts = r.get("created_at", "")
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt >= cutoff:
                recent.append(r)
        except Exception:
            pass
    result.recent_report_count = len(recent)

    # Last and first reported
    sorted_reports = sorted(
        [r for r in reports if r.get("created_at")],
        key=lambda r: r["created_at"]
    )
    if sorted_reports:
        result.last_reported  = sorted_reports[-1]["created_at"]
        result.first_seen     = sorted_reports[0]["created_at"]

    # Top scam categories from tags
    tag_counts: dict[str, int] = {}
    for r in reports:
        for tag in (r.get("tags") or []):
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
    result.top_scam_categories = sorted(tag_counts, key=tag_counts.get, reverse=True)[:5]

    if result.recent_report_count > 0:
        result.risk_indicators.append(
            f"Recently reported {result.recent_report_count} time(s) in the last 30 days"
        )

    result.intel_summary = _build_summary(result)
    return result


def _build_summary(r: PhoneIntelResult) -> str:
    parts = []
    if r.is_zimbabwe and r.carrier != "Unknown":
        parts.append(f"{r.carrier} number")
    elif r.country != "Unknown":
        parts.append(f"Registered in {r.country}")
    if r.number_type == "voip":
        parts.append("VOIP/virtual number")
    if r.report_count > 0:
        parts.append(f"reported {r.report_count} time(s) by the community")
    if r.recent_report_count > 0:
        parts.append(f"{r.recent_report_count} recent report(s)")
    if not parts:
        return "No community intelligence available for this number."
    return ". ".join(parts).capitalize() + "."
