"""
ScamGuard — Phone Normalization Service
========================================
Single source of truth for all phone number parsing and normalization.

ROOT CAUSE OF BUGS THIS FIXES:
  1. utils/normalizer.py used bare regex: re.sub(r"[^digits+]", "", value)
     This produced "263775629690" for "0775629690" (missing leading +),
     "48506716775" for "+48506716775" (stripped), and made the same
     physical number appear as 3–5 separate DB entities.

  2. phone_intel.py used hand-rolled prefix tables that mis-classified
     Polish +48 numbers as Zimbabwean because the 2-digit prefix "48"
     was not in any table, so the code fell through to a Zimbabwe default.

SOLUTION:
  Use the `phonenumbers` library (same data Google uses).
  All callers import `normalize_phone()` from this module.
  The returned E.164 string is the canonical entity key stored in the DB.

PARSE STRATEGY (order matters):
  1. If number starts with "+" → parse with no region hint (unambiguous)
  2. If number starts with "00" → convert to "+" and parse
  3. If number has ≥ 10 digits and starts with a known country code
     (e.g. "263...", "48...") → prepend "+" and parse
  4. If number starts with "0" → try ZW (Zimbabwe) first as that is the
     platform's primary market, then try other common regions
  5. If all attempts fail → return the raw cleaned string so the caller
     can still create an entity (better than crashing)

This strategy correctly handles:
  +263775629690  → +263775629690  (ZW, explicit)
  263775629690   → +263775629690  (ZW, leading CC)
  0775629690     → +263775629690  (ZW, local)
  +48506716775   → +48506716775   (PL, explicit)
  48506716775    → +48506716775   (PL, leading CC)
  +12125551234   → +12125551234   (US, explicit)
  00447911123456 → +447911123456  (GB, 00-prefix)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional

try:
    import phonenumbers
    from phonenumbers import (
        PhoneNumberFormat,
        PhoneNumberType,
        geocoder,
        carrier as carrier_lib,
        number_type as get_number_type,
    )
    _PHONENUMBERS_AVAILABLE = True
except ImportError:
    _PHONENUMBERS_AVAILABLE = False

from utils.logger import get_logger

log = get_logger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

# Regions to attempt when a number has no country prefix.
# ZW is first because it is ScamGuard's primary market.
_FALLBACK_REGIONS = ["ZW", "ZA", "US", "GB", "KE", "NG", "IN"]

# Map phonenumbers type int → our string label
_TYPE_MAP = {
    PhoneNumberType.MOBILE:             "mobile",
    PhoneNumberType.FIXED_LINE:         "fixed",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "mobile",
    PhoneNumberType.VOIP:               "voip",
    PhoneNumberType.TOLL_FREE:          "toll_free",
    PhoneNumberType.PREMIUM_RATE:       "premium",
    PhoneNumberType.PERSONAL_NUMBER:    "personal",
    PhoneNumberType.PAGER:              "pager",
    PhoneNumberType.UAN:                "uan",
    PhoneNumberType.VOICEMAIL:          "voicemail",
    PhoneNumberType.UNKNOWN:            "unknown",
} if _PHONENUMBERS_AVAILABLE else {}

# Countries with elevated scam risk (used for risk_indicators)
_HIGH_RISK_COUNTRIES = {
    "NG", "GH", "CI", "SN", "CM",   # West Africa
    "IN", "PK", "BD",                # South Asia
    "RU", "UA", "BY",               # Eastern Europe
    "CO", "VE",                      # Latin America
    "EG", "MA",                      # North Africa
}

# Known VOIP carrier name fragments
_VOIP_CARRIERS = {"twilio", "vonage", "bandwidth", "google voice", "skype", "magicjack", "ringcentral", "lingo"}


@dataclass
class ParsedPhone:
    """All metadata extracted from a single phone number."""
    raw:               str
    e164:              str           # canonical key — always populated
    normalized:        str           # same as e164 when valid, else cleaned raw
    national_format:   str  = ""
    international_format: str = ""
    is_valid:          bool = False
    country:           str  = "Unknown"
    country_code:      str  = ""     # ISO 3166-1 alpha-2, e.g. "ZW"
    calling_code:      int  = 0      # numeric, e.g. 263
    carrier:           str  = "Unknown"
    number_type:       str  = "unknown"
    is_voip:           bool = False
    is_high_risk_origin: bool = False
    is_zimbabwe:       bool = False
    description:       str  = ""     # geocoder description (city/region)


def _clean_raw(number: str) -> str:
    """Strip formatting, keep digits and a single leading +."""
    if not isinstance(number, str):
        return ""
    # Remove all whitespace and formatting chars
    cleaned = re.sub(r"[\s\-.()/]", "", number.strip())
    # Collapse multiple + signs
    cleaned = re.sub(r"\++", "+", cleaned)
    # Remove any non-digit/+ characters left
    cleaned = re.sub(r"[^\d+]", "", cleaned)
    return cleaned[:25]


def _try_parse(number_str: str, region: Optional[str] = None):
    """Attempt to parse; return phonenumbers.PhoneNumber or None."""
    if not _PHONENUMBERS_AVAILABLE:
        return None
    try:
        parsed = phonenumbers.parse(number_str, region)
        if phonenumbers.is_possible_number(parsed):
            return parsed
    except Exception:
        pass
    return None


@lru_cache(maxsize=4096)
def parse_phone(raw_number: str) -> ParsedPhone:
    """
    Parse and normalize a phone number into a ParsedPhone dataclass.
    Results are cached — call sites pay for parsing only once per unique input.

    Args:
        raw_number: Any format — "+263775629690", "0775629690", "48506716775", …

    Returns:
        ParsedPhone with .e164 as the canonical entity key.
    """
    raw    = raw_number or ""
    cleaned = _clean_raw(raw)

    if not cleaned or len(cleaned) < 5:
        return ParsedPhone(raw=raw, e164=cleaned or raw, normalized=cleaned or raw)

    if not _PHONENUMBERS_AVAILABLE:
        # Graceful degradation — use the old regex logic
        log.warning("phonenumbers library not available — using regex fallback")
        return _regex_fallback(raw, cleaned)

    parsed = None

    # ── Strategy 1: explicit international (starts with + or 00) ────────────
    if cleaned.startswith("+"):
        parsed = _try_parse(cleaned)

    elif cleaned.startswith("00"):
        parsed = _try_parse("+" + cleaned[2:])

    # ── Strategy 2: leading country code without + (e.g. "263...", "48...") ─
    if parsed is None and not cleaned.startswith("0"):
        parsed = _try_parse("+" + cleaned)

    # ── Strategy 3: local format starting with 0 — try ZW first, then others
    if parsed is None and cleaned.startswith("0"):
        for region in _FALLBACK_REGIONS:
            parsed = _try_parse(cleaned, region)
            if parsed and phonenumbers.is_valid_number(parsed):
                break

    # ── Strategy 4: bare digits, no 0 prefix, no + — try adding + ──────────
    if parsed is None and not cleaned.startswith("0"):
        for region in _FALLBACK_REGIONS:
            parsed = _try_parse(cleaned, region)
            if parsed and phonenumbers.is_valid_number(parsed):
                break

    # ── Could not parse → return best-effort result ──────────────────────────
    if parsed is None:
        log.debug(f"parse_phone: could not parse {raw!r} — returning cleaned string")
        return ParsedPhone(
            raw        = raw,
            e164       = cleaned,
            normalized = cleaned,
        )

    # ── Extract all metadata ─────────────────────────────────────────────────
    is_valid  = phonenumbers.is_valid_number(parsed)
    e164      = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
    natl      = phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL)
    intl_fmt  = phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
    cc        = phonenumbers.region_code_for_number(parsed) or ""
    country   = geocoder.country_name_for_number(parsed, "en") or "Unknown"
    car_name  = carrier_lib.name_for_number(parsed, "en") or "Unknown"
    ntype_int = get_number_type(parsed)
    ntype_str = _TYPE_MAP.get(ntype_int, "unknown")
    desc      = geocoder.description_for_number(parsed, "en") or ""
    calling_c = parsed.country_code or 0

    is_voip = (
        ntype_int == PhoneNumberType.VOIP
        or any(v in car_name.lower() for v in _VOIP_CARRIERS)
    )
    is_zw       = (cc == "ZW")
    is_high_risk = (cc in _HIGH_RISK_COUNTRIES)

    return ParsedPhone(
        raw                  = raw,
        e164                 = e164,
        normalized           = e164,
        national_format      = natl,
        international_format = intl_fmt,
        is_valid             = is_valid,
        country              = country,
        country_code         = cc,
        calling_code         = calling_c,
        carrier              = car_name,
        number_type          = ntype_str,
        is_voip              = is_voip,
        is_high_risk_origin  = is_high_risk,
        is_zimbabwe          = is_zw,
        description          = desc,
    )


def normalize_phone(raw_number: str) -> str:
    """
    Return the E.164 canonical form of a phone number.
    This is the value stored in the DB `entities.value` column.

    Example:
        normalize_phone("0775629690")   → "+263775629690"
        normalize_phone("263775629690") → "+263775629690"
        normalize_phone("48506716775")  → "+48506716775"
    """
    return parse_phone(raw_number).e164


def _regex_fallback(raw: str, cleaned: str) -> ParsedPhone:
    """
    Used only when phonenumbers library is missing.
    Reproduces the old regex behavior but returns a ParsedPhone object.
    """
    e164 = cleaned
    if not e164.startswith("+"):
        if e164.startswith("00"):
            e164 = "+" + e164[2:]
        elif e164.startswith("263") and len(e164) >= 12:
            e164 = "+" + e164
        elif e164.startswith("0") and len(e164) >= 9:
            e164 = "+263" + e164[1:]
        else:
            e164 = e164  # keep as-is
    is_zw = e164.startswith("+263")
    return ParsedPhone(
        raw        = raw,
        e164       = e164,
        normalized = e164,
        is_valid   = len(e164) >= 10,
        is_zimbabwe = is_zw,
        country    = "Zimbabwe" if is_zw else "Unknown",
        country_code = "ZW" if is_zw else "",
    )
