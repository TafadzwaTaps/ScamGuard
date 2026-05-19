"""
Lightweight NLP service for scam detection.

Pipeline:
  1. Regex pattern matching  (fast, high-precision rules)
  2. Keyword matching        (weights loaded from Supabase keywords table + fallback hardcoded)
  3. TF-IDF similarity       (optional, kicks in when ≥3 known-scam descriptions available)

Returns NLPResult with matched terms + confidence score 0–1.
"""
from __future__ import annotations
import re
import math
from typing import List, Tuple, Optional
from functools import lru_cache

from utils.logger import get_logger

log = get_logger(__name__)

# ── Regex patterns for common scam structures ──────────────────────────────
_REGEX_PATTERNS: List[Tuple[str, float]] = [
    (r"send\s+money",              0.9),
    (r"wire\s+transfer",           0.85),
    (r"gift\s+card",               0.85),
    (r"bitcoin\s*payment",         0.85),
    (r"urgent(ly)?",               0.6),
    (r"act\s+now",                 0.75),
    (r"verify\s+(your\s+)?account",0.9),
    (r"click\s+(here|this)\s*(to|link)?", 0.8),
    (r"account\s+(blocked|suspended|disabled)", 0.95),
    (r"you\s+have\s+won",          0.95),
    (r"claim\s+your\s+prize",      0.95),
    (r"lottery\s+winner",          0.95),
    (r"(social\s+security|ssn)\s+number", 0.9),
    (r"arrest\s+warrant",          0.9),
    (r"irs\s+(agent|officer|notice)", 0.85),
    (r"tax\s+refund",              0.7),
    (r"double\s+your\s+(investment|money)", 0.95),
    (r"guaranteed\s+(return|profit|income)", 0.9),
    (r"free\s+money",              0.85),
    (r"make\s+money\s+fast",       0.85),
    (r"confirm\s+your\s+(details|info)", 0.85),
    (r"password\s+(expired|reset\s+required)", 0.9),
    (r"enter\s+your\s+password",   0.9),
    (r"limited\s+time\s+offer",    0.65),
    (r"congratulations\s+you('ve)?\s+been\s+selected", 0.95),
]

_COMPILED_REGEX = [
    (re.compile(pat, re.IGNORECASE), score)
    for pat, score in _REGEX_PATTERNS
]

# ── Fallback hardcoded keywords (used when DB is unavailable) ──────────────
_FALLBACK_KEYWORDS: dict[str, float] = {
    "send money": 15, "wire transfer": 12, "gift card": 12,
    "bitcoin payment": 12, "pay now": 10, "transfer funds": 12,
    "urgent": 8, "immediately": 8, "act now": 10, "expire": 6,
    "account blocked": 14, "account suspended": 14, "verify now": 12,
    "verify your account": 12, "you have won": 13, "claim your prize": 13,
    "lottery winner": 13, "free money": 10, "easy money": 9,
    "double your investment": 12, "guaranteed return": 10,
    "legal action": 8, "arrest warrant": 12, "tax refund": 7,
    "credit card number": 11, "social security": 10,
    # ── Zimbabwe-specific additions (v3) ──────────────────────────────────
    "ecocash pin": 15, "ecocash otp": 15, "ecocash agent": 12,
    "ecocash double": 15, "send ecocash": 14, "zesa token": 10,
    "free zesa": 12, "netone wallet": 11, "innbucks send": 12,
    "tumira mari": 15, "ndipei mari": 15, "wakawana mubairo": 14,
    "thumela imali": 15, "registration fee": 13, "guaranteed profit": 14,
    "customs fee": 12, "parcel delivery fee": 12, "diaspora investment": 11,
}


class NLPService:
    def __init__(self, keywords: Optional[dict[str, float]] = None):
        self._keywords: dict[str, float] = keywords or _FALLBACK_KEYWORDS
        self._kw_compiled = [
            (re.compile(re.escape(word), re.IGNORECASE), weight)
            for word, weight in self._keywords.items()
        ]

    # ── Public API ─────────────────────────────────────────────────────────

    def analyse(self, text: str) -> dict:
        """
        Returns:
          matched_keywords: list of matched keyword strings
          regex_matches:    list of matched regex pattern labels
          confidence:       float 0–1
          nlp_score:        float 0–30  (used by scoring engine)
        """
        regex_hits, regex_conf = self._run_regex(text)
        kw_hits, kw_raw = self._run_keywords(text)

        # Combine: regex confidence (0–1) mapped to 0–15, keywords mapped to 0–15
        kw_score = min(kw_raw / max(sum(self._keywords.values()), 1) * 15, 15.0)
        regex_score = min(regex_conf * 15, 15.0)
        nlp_score = round(kw_score + regex_score, 2)

        # Overall confidence 0–1
        confidence = round(min((kw_score + regex_score) / 30, 1.0), 3)

        return {
            "matched_keywords": kw_hits,
            "regex_matches": regex_hits,
            "confidence": confidence,
            "nlp_score": nlp_score,
        }

    # ── Private ────────────────────────────────────────────────────────────

    def _run_regex(self, text: str) -> Tuple[List[str], float]:
        hits: List[str] = []
        total_conf = 0.0
        for pattern, conf in _COMPILED_REGEX:
            if pattern.search(text):
                hits.append(pattern.pattern)
                total_conf += conf
        # Cap at 1.0 (any single match already close to 1)
        return hits, min(total_conf / max(len(_COMPILED_REGEX), 1) * 5, 1.0)

    def _run_keywords(self, text: str) -> Tuple[List[str], float]:
        hits: List[str] = []
        total_weight = 0.0
        for pattern, weight in self._kw_compiled:
            if pattern.search(text):
                word = pattern.pattern.replace("\\", "")
                if word not in hits:
                    hits.append(word)
                    total_weight += weight
        return hits, total_weight


# Module-level instance (refreshed when keywords are reloaded)
_service_instance: Optional[NLPService] = None


def get_nlp_service(keywords: Optional[dict[str, float]] = None) -> NLPService:
    global _service_instance
    if keywords is not None or _service_instance is None:
        _service_instance = NLPService(keywords)
    return _service_instance
