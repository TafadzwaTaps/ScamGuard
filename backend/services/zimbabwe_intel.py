"""
Zimbabwe-Specific Scam Intelligence Layer
==========================================
Extends the base NLP service with Zimbabwe-specific patterns.
Covers: EcoCash, ZESA, CBZ, NetOne, Telecel, fake jobs,
        WhatsApp scams, diaspora fraud, Innbucks, fake promotions.

ALL detection is additive — never replaces existing logic.
Returns structured ZimIntelResult merged into CheckResponse.
"""
from __future__ import annotations
import re
from typing import List, Tuple
from dataclasses import dataclass, field

# ── Zimbabwe-specific regex patterns ──────────────────────────────────────
# Each tuple: (pattern, weight 0–1, category label, explanation)
_ZIM_PATTERNS: List[Tuple[str, float, str, str]] = [

    # ── EcoCash Fraud ──────────────────────────────────────────────────────
    (r"ecocash\s*(agent|number|wallet|pin|otp|code|reversal)", 0.85,
     "EcoCash Fraud", "References EcoCash transaction details — common in mobile money fraud"),
    (r"send\s+\d+.{0,30}ecocash|ecocash.{0,30}\d+", 0.9,
     "EcoCash Fraud", "Requests EcoCash money transfer — high-risk pattern"),
    (r"ecocash.*bonus|bonus.*ecocash", 0.8,
     "EcoCash Fraud", "Fake EcoCash bonus promotion"),
    (r"ecocash.*double|double.*ecocash", 0.95,
     "EcoCash Fraud", "EcoCash money doubling scam — extremely common in Zimbabwe"),
    (r"ecocash.*reversal|reversal.*ecocash", 0.9,
     "EcoCash Fraud", "Fake EcoCash reversal scam — agent claims to need your PIN"),
    (r"wrong\s+number.*ecocash|ecocash.*wrong\s+number", 0.88,
     "EcoCash Fraud", "Wrong number EcoCash scam — sends money then demands return"),

    # ── ZESA (Zimbabwe Electricity Supply Authority) ────────────────────────
    (r"zesa\s*(token|recharge|unit|electricity|credit|prepaid)", 0.75,
     "ZESA Scam", "References ZESA electricity tokens — often used in fake promotions"),
    (r"zesa.*free|free.*zesa|zesa.*bonus|bonus.*zesa", 0.9,
     "ZESA Scam", "Fake free ZESA electricity promotion"),
    (r"zesa.*winner|win.*zesa", 0.92,
     "ZESA Scam", "Fake ZESA lottery winner notification"),

    # ── CBZ / Banking Fraud ─────────────────────────────────────────────────
    (r"cbz\s*(bank|account|card|otp|pin|verify)", 0.8,
     "Banking Fraud", "References CBZ bank details — common in phishing attacks"),
    (r"(fbc|zbfh|steward|nbs)\s*(bank|account|otp|pin)", 0.78,
     "Banking Fraud", "References Zimbabwean bank credentials — phishing indicator"),
    (r"verify\s+your\s+(cbz|fbc|steward|nbs|stanbic)\s+account", 0.92,
     "Banking Fraud", "Fake bank account verification — phishing"),

    # ── Telecom Scams (NetOne, Telecel, Econet) ────────────────────────────
    (r"netone\s*(one\s*wallet|bonus|free|winner|prize|otp|pin)", 0.82,
     "Telecom Scam", "Suspicious NetOne promotion or OTP request"),
    (r"telecel\s*(bonus|free|winner|prize|otp)", 0.82,
     "Telecom Scam", "Suspicious Telecel promotion"),
    (r"econet\s*(bonus|free\s+data|winner|prize|otp|pin)", 0.78,
     "Telecom Scam", "Suspicious Econet promotion — verify with official channels"),

    # ── Innbucks ───────────────────────────────────────────────────────────
    (r"innbucks\s*(send|transfer|agent|wallet|pin|otp|code)", 0.8,
     "Innbucks Fraud", "References Innbucks transaction details"),
    (r"innbucks.*double|double.*innbucks", 0.95,
     "Innbucks Fraud", "Innbucks money doubling scam"),

    # ── Fake Job Scams ─────────────────────────────────────────────────────
    (r"(job|work|employment|vacancy|hiring).{0,60}(whatsapp|telegram|apply now|zimbabwe)", 0.72,
     "Fake Job Scam", "Fake job offer — verify with official employer channels"),
    (r"earn\s+\$?\d+.{0,40}(daily|weekly|per\s+day|per\s+week).{0,40}(home|zimbabwe|zim)", 0.85,
     "Fake Job Scam", "Unrealistic earnings claim — common work-from-home scam"),
    (r"registration\s+fee.{0,60}(job|work|employ|position)", 0.92,
     "Fake Job Scam", "Upfront payment required for job — always a scam"),
    (r"(data\s+entry|online\s+typing|copy\s+paste).{0,60}(earn|paid|payment)", 0.8,
     "Fake Job Scam", "Fake data-entry job — no legitimate employer pays for typing tasks"),

    # ── WhatsApp Scams ─────────────────────────────────────────────────────
    (r"forward\s+this.{0,80}(people|contacts|friends|group)", 0.8,
     "WhatsApp Chain Scam", "Chain message asking to forward — classic WhatsApp scam"),
    (r"whatsapp.{0,40}(gold|plus|premium|pro).{0,40}(download|install|click)", 0.9,
     "WhatsApp Scam", "Fake WhatsApp premium version — malware distribution"),
    (r"your\s+whatsapp.{0,60}(expire|banned|suspend|blocked)", 0.88,
     "WhatsApp Scam", "Fake WhatsApp account threat — social engineering"),
    (r"click.{0,40}link.{0,40}whatsapp|whatsapp.{0,40}click.{0,40}link", 0.85,
     "WhatsApp Scam", "WhatsApp phishing link"),

    # ── Diaspora Scams ─────────────────────────────────────────────────────
    (r"(uk|usa|canada|australia).{0,60}(package|parcel|customs|delivery).{0,60}(fee|pay|transfer)", 0.88,
     "Diaspora Parcel Scam", "Fake overseas parcel requiring upfront customs fees"),
    (r"(lover|partner|soldier|doctor).{0,60}(stuck|stranded|emergency).{0,60}(send|money|transfer)", 0.92,
     "Romance/Diaspora Scam", "Romance scam pattern — fake emergency requiring money"),
    (r"diaspora.{0,60}(investment|scheme|returns|profit)", 0.82,
     "Diaspora Investment Scam", "Fake diaspora investment scheme"),

    # ── Cryptocurrency Scams ───────────────────────────────────────────────
    (r"(bitcoin|crypto|usdt|bnb).{0,60}(double|multiply|invest|profit).{0,60}(zimbabwe|zim|harare)", 0.93,
     "Crypto Scam", "Cryptocurrency doubling/investment scam targeting Zimbabwe"),
    (r"guaranteed\s+(profit|return|income).{0,40}(crypto|bitcoin|invest)", 0.95,
     "Crypto Scam", "Guaranteed crypto returns — always fraudulent"),

    # ── Fake Government / Official Scams ───────────────────────────────────
    (r"(zimra|government|ministry|council).{0,60}(refund|rebate|payment|grant)", 0.88,
     "Fake Government Scam", "Fake government payment or refund — ZIMRA never contacts via SMS/WhatsApp"),
    (r"(passport|id|birth\s+certificate).{0,60}(renew|expire|urgent).{0,60}(fee|pay|send)", 0.85,
     "Government Impersonation", "Fake document renewal urgency — verify at official offices"),

    # ── Shona Language Scam Phrases ────────────────────────────────────────
    (r"tumira\s*(mari|imari|cash|pesa|mobi)", 0.88,
     "Shona Scam Phrase", "Shona: 'send money' — direct financial request"),
    (r"ndipei\s*(mari|number|pin|code|otp)", 0.9,
     "Shona Scam Phrase", "Shona: 'give me money/code' — common in fraud messages"),
    (r"(wakawana|wahwina|wawana)\s*(mubairo|prize|muwani|money)", 0.9,
     "Shona Scam Phrase", "Shona: 'you have won a prize' — lottery scam"),
    (r"(pindura|bvuma|tendera)\s*(zvino|ino|iyi)", 0.75,
     "Shona Scam Phrase", "Shona: 'reply/accept now' — urgency manipulation"),

    # ── Ndebele Language Scam Phrases ─────────────────────────────────────
    (r"thumela\s*(imali|icash|inombolo)", 0.88,
     "Ndebele Scam Phrase", "Ndebele: 'send money/number' — financial fraud"),
    (r"unqobe\s*(umklomelo|imali|indlela)", 0.88,
     "Ndebele Scam Phrase", "Ndebele: 'you have won' — prize scam"),
]

_COMPILED_ZIM = [
    (re.compile(pat, re.IGNORECASE | re.DOTALL), weight, category, explanation)
    for pat, weight, category, explanation in _ZIM_PATTERNS
]

# ── Zimbabwe scam category descriptions ───────────────────────────────────
CATEGORY_DESCRIPTIONS = {
    "EcoCash Fraud":          "Mobile money fraud targeting EcoCash users — never share your PIN or OTP",
    "ZESA Scam":              "Fake ZESA electricity promotions — ZESA does not run WhatsApp prize draws",
    "Banking Fraud":          "Bank phishing attack — your bank will never ask for your PIN via SMS",
    "Telecom Scam":           "Fake telecom promotion — verify offers at official service centres only",
    "Innbucks Fraud":         "Mobile money fraud targeting Innbucks — never share wallet credentials",
    "Fake Job Scam":          "Fraudulent job offer — legitimate employers never charge registration fees",
    "WhatsApp Chain Scam":    "WhatsApp chain message designed to spread or harvest contacts",
    "WhatsApp Scam":          "WhatsApp-based social engineering or phishing attack",
    "Diaspora Parcel Scam":   "Fake overseas delivery requiring upfront customs payment",
    "Romance/Diaspora Scam":  "Romance or diaspora emergency scam — designed to exploit trust",
    "Diaspora Investment Scam": "Fake investment opportunity targeting diaspora Zimbabweans",
    "Crypto Scam":            "Cryptocurrency fraud — no legitimate investment guarantees returns",
    "Fake Government Scam":   "Government impersonation — ZIMRA/ministries never use WhatsApp for payments",
    "Government Impersonation": "Fake official communication — verify all government matters in person",
    "Shona Scam Phrase":      "Shona-language scam indicator detected",
    "Ndebele Scam Phrase":    "Ndebele-language scam indicator detected",
}

# ── Safety advice per category ─────────────────────────────────────────────
SAFETY_ADVICE = {
    "EcoCash Fraud":   "Never share your EcoCash PIN or OTP. Report to *771# or call 114.",
    "ZESA Scam":       "Report fake ZESA promotions to ZESA customer care: 0242 700 111.",
    "Banking Fraud":   "Call your bank's official number immediately if you shared any details.",
    "Telecom Scam":    "Report to your network operator. NetOne: 155, Econet: 111, Telecel: 711.",
    "Fake Job Scam":   "Verify jobs at ZIMDEF or official company websites. Never pay to apply.",
    "Crypto Scam":     "Report to POTRAZ or ZRP CID. Never invest in guaranteed-return crypto.",
    "Fake Government Scam": "Visit your nearest ZIMRA/government office. Official comms use .gov.zw emails.",
    "WhatsApp Scam":   "Report in WhatsApp: Settings → Help → Contact Us. Block the number.",
    "default":         "Do not engage. Block and report the contact to ZRP CID Commercial Crimes Unit.",
}


@dataclass
class ZimIntelResult:
    zim_score: float = 0.0          # 0–25 additive bonus to main score
    categories: List[str] = field(default_factory=list)
    flags: List[dict] = field(default_factory=list)   # [{category, explanation, confidence}]
    safety_advice: str = ""
    is_zimbabwe_specific: bool = False


def analyse_zimbabwe(text: str) -> ZimIntelResult:
    """
    Run Zimbabwe-specific intelligence on text.
    Returns ZimIntelResult — always additive, never replaces base NLP.
    """
    if not text or not text.strip():
        return ZimIntelResult()

    flags: List[dict] = []
    categories_seen: set = set()
    total_weight = 0.0

    for pattern, weight, category, explanation in _COMPILED_ZIM:
        if pattern.search(text):
            if category not in categories_seen:
                categories_seen.add(category)
                flags.append({
                    "category": category,
                    "explanation": explanation,
                    "confidence": round(weight, 2),
                    "advice": SAFETY_ADVICE.get(category, SAFETY_ADVICE["default"]),
                })
                total_weight += weight

    if not flags:
        return ZimIntelResult()

    # zim_score: max 25 pts (added to main risk score)
    zim_score = round(min(25.0, total_weight / max(len(_COMPILED_ZIM), 1) * 100), 1)

    # Pick safety advice from highest-confidence category
    top_flag = max(flags, key=lambda f: f["confidence"])
    advice = top_flag["advice"]

    return ZimIntelResult(
        zim_score=zim_score,
        categories=sorted(categories_seen),
        flags=flags,
        safety_advice=advice,
        is_zimbabwe_specific=True,
    )


def get_category_description(category: str) -> str:
    return CATEGORY_DESCRIPTIONS.get(category, "Suspicious pattern detected")
