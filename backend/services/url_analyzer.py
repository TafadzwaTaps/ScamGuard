"""
URL Phishing & Reputation Analyzer
====================================
Pure Python — no external API keys needed.
Analyses URLs for: typosquatting, suspicious patterns,
known phishing TLDs, suspicious subdomains, URL shorteners,
homoglyph attacks, and Zimbabwe-specific fake domains.

Additive to existing check flow — called only for type='url'.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import List


@dataclass
class URLAnalysisResult:
    is_suspicious: bool = False
    url_score: float = 0.0        # 0–20 additive to main risk score
    flags: List[str] = field(default_factory=list)
    explanations: List[str] = field(default_factory=list)
    domain: str = ""
    is_shortened: bool = False
    has_ssl: bool = False


# ── Known URL shorteners ────────────────────────────────────────────────────
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "short.link", "rb.gy", "cutt.ly", "shorturl.at",
    "tiny.cc", "shorte.st", "linktr.ee", "wa.me",
}

# ── High-risk TLDs commonly used in phishing ───────────────────────────────
_RISKY_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # free domains, massively abused
    ".xyz", ".top", ".click", ".download", ".win", ".loan",
    ".work", ".review", ".science", ".date", ".accountant",
    ".stream", ".faith", ".trade", ".webcam", ".racing",
}

# ── Brands commonly spoofed in Zimbabwe ────────────────────────────────────
_SPOOFED_BRANDS = [
    "ecocash", "econet", "netone", "telecel", "zesa", "zimra",
    "cbz", "fbc", "steward", "stanbic", "nbs", "innbucks",
    "whatsapp", "facebook", "paypal", "google", "microsoft",
    "amazon", "netflix", "dhl", "fedex", "ups",
]

# ── Suspicious URL patterns ─────────────────────────────────────────────────
_SUSPICIOUS_PATTERNS = [
    (re.compile(r"\d{4,}", re.IGNORECASE),
     "Long number sequence in domain", 4.0),
    (re.compile(r"(login|signin|verify|account|secure|update|confirm|banking)", re.IGNORECASE),
     "Phishing keyword in URL path", 5.0),
    (re.compile(r"@"),
     "@ symbol in URL — hides true destination", 8.0),
    (re.compile(r"(\.php\?|\.asp\?|\.jsp\?).*(id=|user=|account=|token=)", re.IGNORECASE),
     "Dynamic parameter pattern common in phishing", 4.0),
    (re.compile(r"http://", re.IGNORECASE),
     "Non-HTTPS URL — unencrypted connection", 3.0),
    (re.compile(r"(free|win|prize|bonus|reward|claim).{0,20}(click|now|here)", re.IGNORECASE),
     "Prize/reward language in URL", 6.0),
    (re.compile(r"-{2,}"),
     "Multiple hyphens — common in typosquatting", 3.0),
]

# ── Homoglyph detection (Cyrillic/look-alike chars) ────────────────────────
_HOMOGLYPHS = re.compile(
    r"[аеіоурсхАВСЕІКМНОРТХ]"  # Cyrillic characters that look like Latin
)


def _extract_domain(url: str) -> tuple[str, str, bool]:
    """Returns (domain, tld, has_ssl)."""
    try:
        if "://" not in url:
            url = "https://" + url
        parsed = urlparse(url)
        domain = parsed.netloc.lower().lstrip("www.")
        has_ssl = parsed.scheme == "https"
        # Extract TLD
        parts = domain.split(".")
        tld = "." + parts[-1] if len(parts) >= 2 else ""
        return domain, tld, has_ssl
    except Exception:
        return url, "", False


def _check_typosquatting(domain: str) -> List[tuple[str, float]]:
    """Check if domain is typosquatting a known brand."""
    issues = []
    domain_lower = domain.lower()
    for brand in _SPOOFED_BRANDS:
        if brand in domain_lower and domain_lower != brand + ".com":
            # Brand is embedded but domain isn't the official one
            if not domain_lower.startswith(brand + "."):
                issues.append((
                    f"Possible {brand.upper()} impersonation — '{domain}' contains brand name but isn't the official domain",
                    7.0
                ))
    return issues


def analyse_url(url: str) -> URLAnalysisResult:
    """
    Analyse a URL for phishing indicators.
    Returns URLAnalysisResult — purely additive to existing scoring.
    """
    if not url or not url.strip():
        return URLAnalysisResult()

    domain, tld, has_ssl = _extract_domain(url)
    flags: List[str] = []
    explanations: List[str] = []
    score = 0.0

    # ── URL shortener check ────────────────────────────────────────────────
    is_shortened = any(s in domain for s in _SHORTENERS)
    if is_shortened:
        flags.append("URL Shortener")
        explanations.append(
            "This URL uses a shortener service — the real destination is hidden. "
            "Scammers use these to disguise malicious links."
        )
        score += 6.0

    # ── Risky TLD ──────────────────────────────────────────────────────────
    if tld in _RISKY_TLDS:
        flags.append(f"High-Risk TLD ({tld})")
        explanations.append(
            f"The '{tld}' domain extension is heavily abused by scammers "
            "due to being free or extremely cheap."
        )
        score += 5.0

    # ── No SSL ─────────────────────────────────────────────────────────────
    if not has_ssl:
        flags.append("No HTTPS")
        explanations.append(
            "This URL uses HTTP, not HTTPS — your data is unencrypted. "
            "Legitimate financial or account sites always use HTTPS."
        )
        score += 3.0

    # ── Homoglyph attack ───────────────────────────────────────────────────
    if _HOMOGLYPHS.search(domain):
        flags.append("Homoglyph Attack")
        explanations.append(
            "URL contains look-alike characters (e.g., Cyrillic 'а' instead of Latin 'a') "
            "— a sophisticated phishing technique to deceive visual inspection."
        )
        score += 10.0

    # ── Suspicious patterns ────────────────────────────────────────────────
    full_url = url.lower()
    for pattern, description, pts in _SUSPICIOUS_PATTERNS:
        if pattern.search(full_url):
            flags.append("Suspicious Pattern")
            explanations.append(description)
            score += pts

    # ── Typosquatting ──────────────────────────────────────────────────────
    for desc, pts in _check_typosquatting(domain):
        flags.append("Brand Impersonation")
        explanations.append(desc)
        score += pts

    # ── Excessive subdomains ───────────────────────────────────────────────
    subdomain_parts = domain.split(".")
    if len(subdomain_parts) >= 4:
        flags.append("Excessive Subdomains")
        explanations.append(
            f"Domain '{domain}' has {len(subdomain_parts) - 2} subdomains — "
            "scammers use this to make fake URLs look legitimate."
        )
        score += 4.0

    url_score = round(min(score, 20.0), 1)
    is_suspicious = url_score >= 5.0

    return URLAnalysisResult(
        is_suspicious=is_suspicious,
        url_score=url_score,
        flags=list(dict.fromkeys(flags)),  # deduplicate preserving order
        explanations=explanations,
        domain=domain,
        is_shortened=is_shortened,
        has_ssl=has_ssl,
    )
