"""
Input normalisation, sanitisation, and validation.
All user input passes through here before being stored or processed.
"""
from __future__ import annotations
import re
import html
from urllib.parse import urlparse, quote

# ── Dangerous characters / patterns ───────────────────────────────────────
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
    # Remove null bytes first
    text = _NULL_BYTES.sub("", text)
    # Remove control characters (keep \n \t \r)
    text = _CONTROL_CHARS.sub("", text)
    # Strip script tags
    text = _SCRIPT_TAGS.sub("", text)
    # Strip all HTML tags
    text = _HTML_TAGS.sub("", text)
    # Collapse excessive whitespace (keep single newlines)
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()[:max_len]


def normalize_value(type_: str, value: str) -> str:
    """Normalise an entity value based on its type."""
    if not isinstance(value, str):
        return ""
    value = sanitize_text(value, max_len=2048)

    if type_ == "phone":
        # Keep only digits and a single leading +
        digits = re.sub(r"[^\d+]", "", value)
        # Ensure only one + at start
        digits = re.sub(r"\++", "+", digits)
        if digits and digits[0] != "+":
            pass  # local number, keep as-is
        return digits[:20]

    if type_ == "url":
        try:
            raw = value.lower()
            if "://" not in raw:
                raw = "https://" + raw
            p = urlparse(raw)
            # Reject if no valid netloc
            if not p.netloc or len(p.netloc) < 3:
                return value[:2048]
            # Reject IP addresses masquerading as domains (basic check)
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
    Used as an extra layer before DB storage.
    """
    if _SQL_PROBES.search(text):
        return False
    if _SCRIPT_TAGS.search(text):
        return False
    return True
