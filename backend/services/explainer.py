"""
Explainable AI Engine
=====================
Takes raw NLP + Zimbabwe intel results and produces human-readable
explanations of WHY content was flagged and WHAT to do about it.

Adds to existing pipeline — never replaces it.
Returns ExplainResult with structured reasoning.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional
import re


@dataclass
class RiskFactor:
    factor: str          # Short label
    detail: str          # Full explanation
    severity: str        # low | medium | high | critical
    score_contribution: float


@dataclass
class ExplainResult:
    summary: str                          # One-sentence verdict
    risk_factors: List[RiskFactor] = field(default_factory=list)
    urgency_detected: bool = False
    impersonation_detected: bool = False
    financial_request_detected: bool = False
    personal_data_request_detected: bool = False
    what_to_do: List[str] = field(default_factory=list)
    scam_type_guess: str = ""             # Best guess at scam category


# ── Urgency patterns ────────────────────────────────────────────────────────
_URGENCY = re.compile(
    r"\b(urgent|immediately|act\s+now|limited\s+time|expire[sd]?|"
    r"last\s+chance|final\s+notice|within\s+\d+\s+(hour|minute|day)|"
    r"right\s+now|do\s+not\s+delay|asap)\b",
    re.IGNORECASE
)

# ── Impersonation patterns ──────────────────────────────────────────────────
_IMPERSONATION = re.compile(
    r"\b(we\s+are\s+from|on\s+behalf\s+of|official\s+(message|notice|communication)|"
    r"your\s+(bank|provider|network|government|zimra|zesa|ecocash|cbz|netone|econet)|"
    r"microsoft|amazon|paypal|google|apple|irs|hmrc|sars)\b",
    re.IGNORECASE
)

# ── Financial request patterns ──────────────────────────────────────────────
_FINANCIAL = re.compile(
    r"\b(send\s+(money|cash|funds|payment)|pay\s+(now|fee|deposit|registration)|"
    r"transfer\s+(funds|money|amount)|wire\s+transfer|gift\s+card|bitcoin|"
    r"ecocash|innbucks|one\s*wallet|western\s+union|moneygram)\b",
    re.IGNORECASE
)

# ── Personal data request patterns ─────────────────────────────────────────
_PERSONAL_DATA = re.compile(
    r"\b(your\s+(pin|otp|password|cvv|id\s+number|passport|account\s+number)|"
    r"verify\s+your\s+(identity|account|details|information)|"
    r"confirm\s+your\s+(personal|banking|card)\s+(details|info|number)|"
    r"enter\s+your\s+(password|pin|otp|code))\b",
    re.IGNORECASE
)

# ── Scam type classifiers ───────────────────────────────────────────────────
_SCAM_TYPE_RULES = [
    (re.compile(r"(lottery|winner|prize|selected|congratulations)", re.IGNORECASE), "Lottery / Prize Scam"),
    (re.compile(r"(ecocash|innbucks|one.?wallet).{0,60}(send|transfer|double|bonus)", re.IGNORECASE), "Mobile Money Fraud"),
    (re.compile(r"(job|employ|hiring|vacancy|position).{0,60}(fee|register|apply)", re.IGNORECASE), "Fake Job Scam"),
    (re.compile(r"(bitcoin|crypto|invest|trading).{0,60}(profit|return|double|guaranteed)", re.IGNORECASE), "Cryptocurrency Fraud"),
    (re.compile(r"(verify|confirm|update).{0,40}(account|password|pin|otp|banking)", re.IGNORECASE), "Phishing Attack"),
    (re.compile(r"(parcel|package|customs|delivery).{0,60}(fee|pay|transfer)", re.IGNORECASE), "Parcel / Delivery Scam"),
    (re.compile(r"(romance|love|partner|relationship).{0,60}(money|send|emergency)", re.IGNORECASE), "Romance Scam"),
    (re.compile(r"(zesa|electricity|token|unit).{0,40}(free|win|bonus|prize)", re.IGNORECASE), "Fake Utility Promotion"),
    (re.compile(r"(bank|cbz|fbc|stanbic|steward).{0,40}(verify|otp|pin|suspend)", re.IGNORECASE), "Bank Phishing"),
]


def _severity(weight: float) -> str:
    if weight >= 0.85: return "critical"
    if weight >= 0.7:  return "high"
    if weight >= 0.5:  return "medium"
    return "low"


def explain(
    text: str,
    matched_keywords: List[str],
    regex_matches: List[str],
    risk_score: float,
    zim_flags: Optional[List[dict]] = None,
    report_count: int = 0,
) -> ExplainResult:
    """
    Build a human-readable explanation from all detection signals.
    Called AFTER existing NLP + Zimbabwe intel — purely additive.
    """
    factors: List[RiskFactor] = []

    # ── Urgency detection ──────────────────────────────────────────────────
    urgency_detected = bool(_URGENCY.search(text))
    if urgency_detected:
        factors.append(RiskFactor(
            factor="Urgency Manipulation",
            detail="Message uses time pressure to force quick decisions without thinking — "
                   "a classic social engineering technique.",
            severity="high",
            score_contribution=8.0,
        ))

    # ── Impersonation detection ────────────────────────────────────────────
    impersonation_detected = bool(_IMPERSONATION.search(text))
    if impersonation_detected:
        factors.append(RiskFactor(
            factor="Impersonation",
            detail="Message claims to be from an official organisation or trusted brand. "
                   "Legitimate organisations do not request sensitive info via SMS or WhatsApp.",
            severity="critical",
            score_contribution=12.0,
        ))

    # ── Financial request ──────────────────────────────────────────────────
    financial_detected = bool(_FINANCIAL.search(text))
    if financial_detected:
        factors.append(RiskFactor(
            factor="Financial Request",
            detail="Message requests a money transfer or payment. No legitimate prize, "
                   "job offer, or government service requires upfront payment.",
            severity="critical",
            score_contribution=15.0,
        ))

    # ── Personal data request ──────────────────────────────────────────────
    personal_data_detected = bool(_PERSONAL_DATA.search(text))
    if personal_data_detected:
        factors.append(RiskFactor(
            factor="Credential Harvesting",
            detail="Message asks for your PIN, OTP, password, or personal ID. "
                   "No bank, mobile money provider, or official body needs this via message.",
            severity="critical",
            score_contribution=15.0,
        ))

    # ── Keyword matches ────────────────────────────────────────────────────
    if matched_keywords:
        factors.append(RiskFactor(
            factor=f"Scam Keywords ({len(matched_keywords)} detected)",
            detail=f"Detected known fraud phrases: {', '.join(matched_keywords[:5])}{'...' if len(matched_keywords) > 5 else ''}",
            severity=_severity(len(matched_keywords) / 10),
            score_contribution=min(len(matched_keywords) * 2.0, 10.0),
        ))

    # ── Zimbabwe-specific flags ────────────────────────────────────────────
    if zim_flags:
        for flag in zim_flags[:3]:  # top 3
            factors.append(RiskFactor(
                factor=flag["category"],
                detail=flag["explanation"],
                severity=_severity(flag["confidence"]),
                score_contribution=round(flag["confidence"] * 8, 1),
            ))

    # ── Community reports ──────────────────────────────────────────────────
    if report_count >= 3:
        factors.append(RiskFactor(
            factor=f"Community Reports ({report_count})",
            detail=f"This has been independently reported {report_count} times by community members.",
            severity="high" if report_count >= 5 else "medium",
            score_contribution=min(report_count * 3.0, 15.0),
        ))

    # ── Scam type classification ───────────────────────────────────────────
    scam_type = ""
    for pattern, label in _SCAM_TYPE_RULES:
        if pattern.search(text):
            scam_type = label
            break

    # ── Summary ───────────────────────────────────────────────────────────
    if risk_score >= 60:
        summary = (
            f"High-risk content detected{f' — likely {scam_type}' if scam_type else ''}. "
            f"{len(factors)} fraud indicator(s) found. Do not engage."
        )
    elif risk_score >= 30:
        summary = (
            f"Suspicious content{f' — possible {scam_type}' if scam_type else ''}. "
            f"{len(factors)} indicator(s) flagged. Verify independently before responding."
        )
    else:
        summary = (
            "No significant fraud indicators detected. "
            "Always stay vigilant — when in doubt, do not share personal details."
        )

    # ── What to do ─────────────────────────────────────────────────────────
    what_to_do: List[str] = []
    if financial_detected:
        what_to_do.append("Do NOT send any money or make any payment.")
    if personal_data_detected:
        what_to_do.append("Do NOT share your PIN, OTP, password, or ID number.")
    if impersonation_detected:
        what_to_do.append("Contact the organisation directly using their OFFICIAL number — not the one in the message.")
    if urgency_detected:
        what_to_do.append("Ignore any deadlines — urgency is used to stop you thinking clearly.")
    if report_count > 0:
        what_to_do.append(f"Block and report this contact. {report_count} others have already flagged it.")
    if not what_to_do:
        what_to_do.append("If unsure, block and do not respond. Report to ScamGuard community.")

    return ExplainResult(
        summary=summary,
        risk_factors=factors,
        urgency_detected=urgency_detected,
        impersonation_detected=impersonation_detected,
        financial_request_detected=financial_detected,
        personal_data_request_detected=personal_data_detected,
        what_to_do=what_to_do,
        scam_type_guess=scam_type,
    )
