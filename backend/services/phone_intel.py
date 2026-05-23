"""
ScamGuard — Phone Intelligence Service (v2)
============================================
Pure Python phone analysis — no paid API keys required.

BUGS FIXED in v2:
  1. Raw digit strings (no +) were wrongly assumed to be Zimbabwe,
     producing "Unknown" carrier and the raw digits as local_format.
  2. _build_summary used .capitalize() which lowercased "Zimbabwe"
     to "zimbabwe" mid-sentence.
  3. _ZW_CARRIERS dict had duplicate keys (26371 used for both
     Econet and NetOne — last write won, silently wrong).
  4. 9-digit numbers starting with non-ZW digit prefixes were
     incorrectly prepended with +263.
  5. local_format not set for non-Zimbabwe numbers (showed e164 raw).

All data is structural/pattern-based or community-sourced.
No private data is fabricated or scraped.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional


# ── Country code table (longest-prefix first for matching) ────────────────
# Keys must be E.164 prefix including the leading +
_COUNTRY_CODES: dict[str, str] = {
    # 4-digit codes (match before 3-digit)
    "+1473": "Grenada",
    "+1268": "Antigua and Barbuda",
    "+1284": "British Virgin Islands",
    "+1649": "Turks and Caicos Islands",
    "+1664": "Montserrat",
    "+1876": "Jamaica",
    # 3-digit codes
    "+263": "Zimbabwe",
    "+260": "Zambia",
    "+267": "Botswana",
    "+254": "Kenya",
    "+255": "Tanzania",
    "+256": "Uganda",
    "+234": "Nigeria",
    "+233": "Ghana",
    "+237": "Cameroon",
    "+225": "Ivory Coast",
    "+221": "Senegal",
    "+212": "Morocco",
    "+251": "Ethiopia",
    "+252": "Somalia",
    "+258": "Mozambique",
    "+266": "Lesotho",
    "+268": "Eswatini",
    "+353": "Ireland",
    "+358": "Finland",
    "+351": "Portugal",
    "+380": "Ukraine",
    "+381": "Serbia",
    "+385": "Croatia",
    "+386": "Slovenia",
    "+421": "Slovakia",
    "+420": "Czech Republic",
    "+994": "Azerbaijan",
    "+998": "Uzbekistan",
    # 2-digit codes
    "+27": "South Africa",
    "+20": "Egypt",
    "+31": "Netherlands",
    "+32": "Belgium",
    "+33": "France",
    "+34": "Spain",
    "+36": "Hungary",
    "+39": "Italy",
    "+40": "Romania",
    "+41": "Switzerland",
    "+43": "Austria",
    "+44": "United Kingdom",
    "+45": "Denmark",
    "+46": "Sweden",
    "+47": "Norway",
    "+48": "Poland",
    "+49": "Germany",
    "+55": "Brazil",
    "+60": "Malaysia",
    "+61": "Australia",
    "+62": "Indonesia",
    "+63": "Philippines",
    "+64": "New Zealand",
    "+65": "Singapore",
    "+66": "Thailand",
    "+7":  "Russia",
    "+81": "Japan",
    "+82": "South Korea",
    "+84": "Vietnam",
    "+86": "China",
    "+90": "Turkey",
    "+91": "India",
    "+92": "Pakistan",
    "+93": "Afghanistan",
    "+94": "Sri Lanka",
    "+98": "Iran",
    # 1-digit code (last resort)
    "+1": "United States / Canada",
}

# ── Zimbabwe carrier prefix lookup (POTRAZ national numbering plan) ────────
# Local format (0XXX) → carrier name
_ZW_CARRIERS: dict[str, tuple[str, str]] = {
    # Econet Wireless (07XX)
    "0771": ("Econet Wireless", "mobile"),
    "0772": ("Econet Wireless", "mobile"),
    "0773": ("Econet Wireless", "mobile"),
    "0774": ("Econet Wireless", "mobile"),
    "0775": ("Econet Wireless", "mobile"),
    "0776": ("Econet Wireless", "mobile"),
    "0777": ("Econet Wireless", "mobile"),
    "0778": ("Econet Wireless", "mobile"),
    "0779": ("Econet Wireless", "mobile"),
    # NetOne (071X)
    "0712": ("NetOne", "mobile"),
    "0713": ("NetOne", "mobile"),
    "0714": ("NetOne", "mobile"),
    "0715": ("NetOne", "mobile"),
    "0716": ("NetOne", "mobile"),
    "0717": ("NetOne", "mobile"),
    "0718": ("NetOne", "mobile"),
    "0719": ("NetOne", "mobile"),
    # Telecel Zimbabwe (073X)
    "0730": ("Telecel Zimbabwe", "mobile"),
    "0731": ("Telecel Zimbabwe", "mobile"),
    "0732": ("Telecel Zimbabwe", "mobile"),
    "0733": ("Telecel Zimbabwe", "mobile"),
    "0734": ("Telecel Zimbabwe", "mobile"),
    "0735": ("Telecel Zimbabwe", "mobile"),
    "0736": ("Telecel Zimbabwe", "mobile"),
    "0737": ("Telecel Zimbabwe", "mobile"),
    "0738": ("Telecel Zimbabwe", "mobile"),
    "0739": ("Telecel Zimbabwe", "mobile"),
    # TelOne fixed lines (024X, 029X)
    "0242": ("TelOne (Harare Fixed)", "fixed"),
    "0292": ("TelOne (Bulawayo Fixed)", "fixed"),
    "0252": ("TelOne (Gweru Fixed)", "fixed"),
    "0272": ("TelOne (Mutare Fixed)", "fixed"),
}

# ── VOIP / premium rate indicators ────────────────────────────────────────
_VOIP_PATTERNS = [
    (re.compile(r"^\+1(900|800|888|877|866|855|844|833|822)"), "US Toll-Free / Premium Rate"),
    (re.compile(r"^\+1(646|917|347|929)"),                     "US VOIP (New York area)"),
    (re.compile(r"^\+1(415|650|510|669)"),                     "US VOIP (San Francisco area)"),
    (re.compile(r"^\+44(20|113|161|121|131)"),                 "UK Geographic VOIP"),
    (re.compile(r"^\+1900"),                                   "Premium Rate"),
]

# ── High-risk origin prefixes ──────────────────────────────────────────────
_HIGH_RISK_PREFIXES = [
    ("+234", "Nigeria"),
    ("+233", "Ghana"),
    ("+237", "Cameroon"),
    ("+225", "Ivory Coast"),
    ("+221", "Senegal"),
    ("+1473", "Grenada (wangiri scams)"),
    ("+1268", "Antigua (wangiri scams)"),
    ("+1284", "British Virgin Islands"),
    ("+1649", "Turks and Caicos"),
]


@dataclass
class PhoneIntelResult:
    raw_number: str
    normalized: str = ""
    is_valid: bool = False
    country: str = "Unknown"
    country_code: str = ""
    carrier: str = "Unknown"
    number_type: str = "unknown"
    local_format: str = ""
    e164_format: str = ""
    is_voip: bool = False
    voip_label: str = ""
    is_high_risk_origin: bool = False
    is_zimbabwe: bool = False
    report_count: int = 0
    recent_report_count: int = 0
    last_reported: Optional[str] = None
    first_seen: Optional[str] = None
    top_scam_categories: list = field(default_factory=list)
    community_risk_score: float = 0.0
    risk_indicators: list = field(default_factory=list)
    intel_summary: str = ""


# ── Normalisation ──────────────────────────────────────────────────────────

def _normalize_phone(raw: str) -> str:
    """
    Normalise to E.164 format where possible.

    Handles:
      +263771234567  →  +263771234567   (already E.164)
      0771234567     →  +263771234567   (ZW local, 10 digits starting 07)
      771234567      →  +263771234567   (ZW local, 9 digits starting 7xx)
      00263771...    →  +263771...      (international prefix 00)
      +447911123456  →  +447911123456   (UK, unchanged)
      48506716775    →  48506716775     (raw digits — kept as-is, NOT ZW)
    """
    s = re.sub(r"[\s\-\.\(\)\u00A0\u202F]", "", raw.strip())

    # 00XX → +XX (international dialling prefix)
    if s.startswith("00") and len(s) > 4:
        s = "+" + s[2:]
        return s

    # Already E.164
    if s.startswith("+"):
        return s

    # Zimbabwe local format: exactly 10 digits starting with 07, 08, or 09
    if re.match(r"^0[789]\d{8}$", s):
        return "+263" + s[1:]

    # Zimbabwe short local: exactly 9 digits starting with 7, 8, or 9
    # ONLY if it looks like a Zimbabwe mobile prefix (71x, 72x, 73x, 77x-79x)
    if re.match(r"^[789]\d{8}$", s):
        first_two = s[:2]
        zw_mobile_starts = ("71", "72", "73", "74", "75", "76", "77", "78", "79")
        if first_two in zw_mobile_starts:
            return "+263" + s

    # Anything else (raw digits without +): return as-is for validation
    return s


# ── Country detection ──────────────────────────────────────────────────────

def _detect_country(normalized: str) -> tuple[str, str]:
    """Match longest E.164 prefix to country. Returns (country, code)."""
    if not normalized.startswith("+"):
        return "Unknown", ""

    # Try longest prefix first (4 chars after + = 5 total, down to 1 char after +)
    for prefix_len in (5, 4, 3, 2, 1):
        candidate = normalized[:prefix_len + 1]  # +1 for leading "+"
        if candidate in _COUNTRY_CODES:
            return _COUNTRY_CODES[candidate], candidate

    return "Unknown", normalized[:5] if len(normalized) >= 5 else normalized


# ── Carrier detection ──────────────────────────────────────────────────────

def _detect_carrier_zw(normalized: str) -> tuple[str, str]:
    """
    Detect Zimbabwe carrier from E.164 number.
    Converts to local format (0XXX) for prefix table lookup.
    Returns (carrier, number_type).
    """
    # Convert +263XXXXXXX → 0XXXXXXX
    if normalized.startswith("+263"):
        local = "0" + normalized[4:]
    else:
        local = normalized  # already local or unknown format

    # 4-digit prefix lookup
    prefix4 = local[:4]
    if prefix4 in _ZW_CARRIERS:
        return _ZW_CARRIERS[prefix4]

    # TelOne fixed lines: starts with 02XX
    if re.match(r"^02\d{2}", local):
        return "TelOne (Fixed Line)", "fixed"

    return "Unknown", "mobile"


def _make_local_format(normalized: str, country_code: str) -> str:
    """
    Build a human-readable local display format.
    Zimbabwe:      +263771234567  →  0771 234 567
    UK:            +447911234567  →  07911 234 567 (simplified)
    SA:            +27821234567   →  082 123 4567
    Other:         show E.164 as-is
    """
    if not normalized.startswith("+"):
        return normalized  # can't format without country info

    if country_code == "+263":
        # +263XXXXXXXX → 0XXX XXX XXX
        digits = "0" + normalized[4:]
        if len(digits) == 10:
            return f"{digits[:4]} {digits[4:7]} {digits[7:]}"
        return digits

    if country_code == "+27":
        # +27XXXXXXXXX → 0XX XXX XXXX
        digits = "0" + normalized[3:]
        if len(digits) == 10:
            return f"{digits[:3]} {digits[3:6]} {digits[6:]}"
        return digits

    if country_code == "+44":
        # +44XXXXXXXXXX → 0XXXXXXXXXX
        digits = "0" + normalized[3:]
        return digits

    if country_code in ("+1", "+1473", "+1268", "+1284", "+1649"):
        # +1XXXXXXXXXX → (XXX) XXX-XXXX
        digits = normalized[2:]
        if len(digits) == 10:
            return f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"

    # Default: show E.164
    return normalized


# ── VOIP / high-risk checks ────────────────────────────────────────────────

def _check_voip(normalized: str) -> tuple[bool, str]:
    for pattern, label in _VOIP_PATTERNS:
        if pattern.match(normalized):
            return True, label
    return False, ""


def _check_high_risk(normalized: str) -> tuple[bool, str]:
    for prefix, label in _HIGH_RISK_PREFIXES:
        if normalized.startswith(prefix):
            return True, label
    return False, ""


# ── Validation ─────────────────────────────────────────────────────────────

def _validate(normalized: str) -> bool:
    """E.164 structural validation: +[1-15 digits]."""
    if not normalized.startswith("+"):
        return False
    digits = normalized[1:]
    return digits.isdigit() and 6 <= len(digits) <= 15


# ── Summary builder ────────────────────────────────────────────────────────

def _build_summary(r: PhoneIntelResult) -> str:
    """Build a plain-English summary. Does NOT use .capitalize() to avoid lowercasing."""
    parts = []

    if r.is_zimbabwe and r.carrier != "Unknown":
        parts.append(f"{r.carrier} number ({r.country})")
    elif r.country not in ("Unknown", ""):
        parts.append(f"Registered in {r.country}")

    if r.is_voip and r.voip_label:
        parts.append(f"VOIP/virtual number ({r.voip_label})")
    elif r.is_voip:
        parts.append("VOIP/virtual number — easily spoofed")

    if r.is_high_risk_origin:
        parts.append(f"High-risk origin — frequently used in scam calls")

    if r.report_count > 0:
        parts.append(f"reported {r.report_count} time(s) by the ScamGuard community")

    if r.recent_report_count > 0:
        parts.append(f"{r.recent_report_count} report(s) in the last 30 days")

    if not parts:
        return "No community intelligence available for this number."

    # Join without .capitalize() to preserve proper nouns
    sentence = ". ".join(p[0].upper() + p[1:] for p in parts) + "."
    return sentence


# ── Main entry point ───────────────────────────────────────────────────────

def analyse_phone(raw_number: str) -> PhoneIntelResult:
    """Structurally analyse a phone number. Community data added by caller."""
    result = PhoneIntelResult(raw_number=raw_number)

    normalized = _normalize_phone(raw_number)
    result.normalized = normalized

    # Validation
    result.is_valid = _validate(normalized)
    if not result.is_valid:
        # Accept plain digit strings ≥7 chars but mark limited analysis
        if not re.match(r"^\d{7,15}$", normalized):
            result.intel_summary = "Could not parse this number. Please include the country code (e.g. +263771234567)."
            return result
        # Plain digits — limited analysis, no country detection
        result.intel_summary = "Enter the number with country code (e.g. +263 for Zimbabwe) for full analysis."
        result.local_format = normalized
        return result

    result.e164_format = normalized

    # Country
    result.country, result.country_code = _detect_country(normalized)
    result.is_zimbabwe = (result.country_code == "+263")

    # Carrier
    if result.is_zimbabwe:
        result.carrier, result.number_type = _detect_carrier_zw(normalized)
    else:
        result.carrier = "Not available"
        result.number_type = "mobile"

    # Local display format
    result.local_format = _make_local_format(normalized, result.country_code)

    # VOIP check
    result.is_voip, result.voip_label = _check_voip(normalized)
    if result.is_voip:
        result.number_type = "voip"
        label = result.voip_label or "VOIP/Virtual"
        result.risk_indicators.append(f"VOIP/Virtual number ({label}) — easily spoofed")

    # High-risk origin
    result.is_high_risk_origin, hr_label = _check_high_risk(normalized)
    if result.is_high_risk_origin:
        result.risk_indicators.append(
            f"High-risk origin: {hr_label} — frequently used in international scam calls"
        )

    result.intel_summary = _build_summary(result)
    return result


def enrich_with_community(result: PhoneIntelResult, reports: list[dict]) -> PhoneIntelResult:
    """Enrich PhoneIntelResult with community report data from Supabase."""
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
            if ts:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt >= cutoff:
                    recent.append(r)
        except Exception:
            pass
    result.recent_report_count = len(recent)

    # First / last reported
    dated = sorted(
        [r for r in reports if r.get("created_at")],
        key=lambda r: r["created_at"]
    )
    if dated:
        result.first_seen    = dated[0]["created_at"]
        result.last_reported = dated[-1]["created_at"]

    # Top scam categories from report tags
    tag_counts: dict[str, int] = {}
    for r in reports:
        for tag in (r.get("tags") or []):
            if tag:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
    result.top_scam_categories = sorted(tag_counts, key=tag_counts.get, reverse=True)[:5]

    if result.recent_report_count > 0:
        result.risk_indicators.append(
            f"Recently reported {result.recent_report_count} time(s) in the last 30 days"
        )

    result.intel_summary = _build_summary(result)
    return result
