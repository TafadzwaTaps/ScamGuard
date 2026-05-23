"""
ScamGuard — Input Normalisation, Sanitisation, and Validation  (v3.1)
======================================================================
All user input passes through here before being stored or processed.

Change vs v3.0:
  normalize_value(type_="phone", ...) now delegates to
  services.phone_normalizer.normalize_phone() which uses the
  phonenumbers library for accurate E.164 conversion.

  This is the ONLY change. All other functions are identical.

  The delegation is done with a lazy import to avoid a circular import
  (phone_normalizer imports utils.logger).
"""
from __future__ import annotations
import re
import html
from urllib.parse import urlparse, quote

# ── Dangerous characters / patterns ────────────────────────────────────────
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x80-\x9f]")
_NULL_BYTES     = re.compile(r"\x00")
_SCRIPT_TAGS    = re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)
_HTML_TAGS      = re.compile(r"<[^>]+>")
_SQL_PROBES     = re.compile(
    r"(;\s*drop\s|;\s*delete\s|;\s*insert\s|;\s*update\s|'--|\bunion\s+select\b)",
    re.IGNORECASE,
)


def sanitize_text(text: str, max_len: int = 4000) -> str:
    """
    Full sanitisation pipeline for user-supplied text fields.
    Removes: control chars, null bytes, HTML/script tags, excessive whitespace.
    Does NOT HTML-encode — that is the frontend's responsibility.
    """
    if not isinstance(text, str):
        return ""
    text = _NULL_BYTES.sub("", text)
    text = _CONTROL_CHARS.sub("", text)
    text = _SCRIPT_TAGS.sub("", text)
    text = _HTML_TAGS.sub("", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()[:max_len]


def normalize_value(type_: str, value: str) -> str:
    """
    Normalise an entity value based on its type.

    For phone numbers: delegates to services.phone_normalizer.normalize_phone()
    which uses the phonenumbers library to produce E.164 format.
    This ensures "+263775629690", "0775629690", and "263775629690" all
    produce the same canonical string "+263775629690" for DB storage.

    For URLs: lowercases, parses, reconstructs.
    For messages: collapses whitespace.
    """
    if not isinstance(value, str):
        return ""
    value = sanitize_text(value, max_len=2048)

    if type_ == "phone":
        # Delegate to the phonenumbers-based normalizer
        # Lazy import avoids potential circular dependency at module load time
        try:
            from services.phone_normalizer import normalize_phone
            return normalize_phone(value)
        except ImportError:
            # Fallback if the module isn't available (e.g. during tests)
            digits = re.sub(r"[^\d+]", "", value)
            digits = re.sub(r"\++", "+", digits)
            return digits[:20]

    if type_ == "url":
        try:
            raw = value.lower()
            if "://" not in raw:
                raw = "https://" + raw
            p = urlparse(raw)
            if not p.netloc or len(p.netloc) < 3:
                return value[:2048]
            return p.geturl()[:2048]
        except Exception:
            return value.lower()[:2048]

    # message: collapse whitespace
    return re.sub(r"\s+", " ", value)[:2048]


def validate_url(value: str) -> bool:
    """Return True if value looks like a valid URL."""
    try:
        p = urlparse(value if "://" in value else "https://" + value)
        return bool(p.netloc) and len(p.netloc) >= 3
    except Exception:
        return False


def is_safe_text(text: str) -> bool:
    """
    Quick safety check — returns False if text looks like an injection probe.
    Used as an extra guard layer before DB storage.
    """
    if _SQL_PROBES.search(text):
        return False
    if _SCRIPT_TAGS.search(text):
        return False
    return True
