from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass(frozen=True)
class Signal:
    category: str  # "heuristics" | "regex" | "ai_semantic"
    code: str
    label: str
    weight: int
    evidence: str
    phrase: str = ""

    def to_dict(self) -> dict[str, str | int]:
        return {
            "category": self.category,
            "code": self.code,
            "label": self.label,
            "weight": self.weight,
            "evidence": self.evidence,
            "phrase": self.phrase,
        }


@dataclass(frozen=True)
class InspectedLink:
    url: str
    host: str
    status: str  # "safe" | "suspicious" | "malicious"
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "url": self.url,
            "host": self.host,
            "status": self.status,
            "reason": self.reason,
        }


@dataclass
class AnalysisResult:
    risk_score: int
    verdict: str  # "safe" | "caution" | "high_risk"
    attack_vector: str
    recommended_action: str
    summary: str
    breakdown: dict[str, int]
    signals: list[Signal] = field(default_factory=list)
    matched_phrases: list[str] = field(default_factory=list)
    inspected_links: list[InspectedLink] = field(default_factory=list)
    redacted_preview: str = ""
    text_hash: str = ""


URL_REGEX = re.compile(r"https?://[^\s<>'\"()]+", re.IGNORECASE)
IP_URL_REGEX = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s]*)?", re.IGNORECASE)
ZERO_WIDTH_REGEX = re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff]")
CYRILLIC_CHAR_REGEX = re.compile(r"[\u0400-\u04FF]")
LATIN_CHAR_REGEX = re.compile(r"[A-Za-z]")

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
}
RISKY_TLDS = (".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".zip", ".cfd", ".work", ".loan")
SUSPICIOUS_URL_PATHS = re.compile(
    r"/(?:auth|login|signin|sso[-_]?verify|verify|account[-_]?update|reset[-_]?mfa|wallet|claim|airdrop|remittance|invoice|secure[-_]?portal)",
    re.IGNORECASE,
)

CREDENTIAL_ASK_REGEX = re.compile(
    r"\b(?:otp|one[- ]time[- ]pass(?:word|code)|2fa|mfa|verification code|pin code|seed phrase|recovery phrase|private key|password|ssn|social security|routing number|wire transfer|remittance|gift card|iban|swift)\b",
    re.IGNORECASE,
)

CRYPTO_LURE_REGEX = re.compile(
    r"\b(?:connect (?:your )?wallet|airdrop|claim (?:your )?(?:tokens?|reward)|seed phrase|metamask|ledger live|drain|gas fee refund|usdt|eth transfer)\b",
    re.IGNORECASE,
)

URGENCY_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    (
        "Immediate action deadline",
        re.compile(
            r"\b(?:urgent(?:ly)?|immediately|right away|asap|action required|final notice|expires? (?:today|in \d+ hours?)|before \d{1,2}(?::\d{2})?\s*(?:am|pm))\b",
            re.IGNORECASE,
        ),
        16,
    ),
    (
        "Account suspension or penalty threat",
        re.compile(
            r"\b(?:account (?:will be )?(?:suspended|locked|deactivated|terminated)|uninterrupted access|avoid (?:suspension|penalty|termination)|overdue)\b",
            re.IGNORECASE,
        ),
        18,
    ),
]

IMPERSONATION_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    (
        "Executive / authority pressure (BEC)",
        re.compile(
            r"\b(?:cfo|ceo|executive|board meetings?|back-to-back meetings?|it helpdesk|security team|compliance office|hr department)\b",
            re.IGNORECASE,
        ),
        16,
    ),
    (
        "Secrecy / verification bypass",
        re.compile(
            r"\b(?:keep this confidential|strictly confidential|do not (?:share|discuss|call)|unable to take calls|bypass (?:standard|normal))\b",
            re.IGNORECASE,
        ),
        20,
    ),
    (
        "Financial settlement / payment redirect",
        re.compile(
            r"\b(?:vendor settlement|update (?:our )?(?:bank|remittance|direct deposit|payroll)|confirm (?:the )?wire|invoice #\w+|urgent payment)\b",
            re.IGNORECASE,
        ),
        18,
    ),
]

AI_COURTESY_PHRASES = re.compile(
    r"\b(?:i hope this (?:message|email) finds you well|kindly (?:note|facilitate|confirm|update|provide|review|verify)|please be advised|rest assured|your prompt attention|at your earliest convenience|in order to ensure|furthermore|additionally|warm regards)\b",
    re.IGNORECASE,
)

RECRUITER_LURE_PHRASES = re.compile(
    r"\b(?:impressed by your (?:profile|background)|exclusive (?:opportunity|role)|confidential search|verify your (?:portfolio|identity)|sign (?:the )?nda via|download (?:the )?assessment)\b",
    re.IGNORECASE,
)

BRAND_KEYWORDS = ("microsoft", "google", "okta", "paypal", "docusign", "stripe", "aws", "linkedin", "chase", "bank of america")
OFFICIAL_DOMAINS = {
    "microsoft": ("microsoft.com", "office.com", "live.com"),
    "google": ("google.com", "accounts.google.com"),
    "okta": ("okta.com",),
    "paypal": ("paypal.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "stripe": ("stripe.com",),
    "aws": ("amazon.com", "aws.amazon.com"),
    "linkedin": ("linkedin.com",),
    "chase": ("chase.com",),
    "bank of america": ("bankofamerica.com",),
}


def redact_sensitive_text(text: str, max_len: int = 160) -> str:
    """Privacy-first preview: mask emails, long numbers, and query parameters before logging."""
    cleaned = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[email]", text)
    cleaned = re.sub(r"(https?://[^\s?#]+)\?[^\s]+", r"\1?[redacted]", cleaned)
    cleaned = re.sub(r"\b\d{4,}\b", "[num]", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > max_len:
        return cleaned[: max_len - 3] + "..."
    return cleaned


def _extract_snippet(match: re.Match[str] | None, fallback: str = "") -> str:
    if not match:
        return fallback
    return f'Matched: "{match.group(0)}"'


def _analyze_urls(text: str, source_url: str | None) -> tuple[list[Signal], list[InspectedLink]]:
    signals: list[Signal] = []
    inspected_links: list[InspectedLink] = []
    urls = URL_REGEX.findall(text)

    if IP_URL_REGEX.search(text):
        m = IP_URL_REGEX.search(text)
        signals.append(
            Signal(
                category="regex",
                code="ip_literal_url",
                label="Raw IP-address link instead of verified domain",
                weight=28,
                evidence=_extract_snippet(m),
                phrase=m.group(0) if m else "",
            )
        )

    lower_text = text.lower()
    mentioned_brands = [b for b in BRAND_KEYWORDS if b in lower_text and b in OFFICIAL_DOMAINS]

    for raw_url in urls:
        parsed = urlparse(raw_url)
        host = (parsed.hostname or "").lower()
        if not host:
            continue

        link_reasons: list[str] = []
        link_status = "safe"

        if IP_URL_REGEX.match(raw_url):
            link_reasons.append("Raw IP host")
            link_status = "malicious"

        if "xn--" in host:
            link_reasons.append("Punycode homograph")
            link_status = "malicious"
            signals.append(
                Signal(
                    category="regex",
                    code="punycode_homograph",
                    label="Punycode/IDN lookalike domain detected",
                    weight=25,
                    evidence=f"Host: {host}",
                    phrase=raw_url,
                )
            )

        if host in SHORTENER_DOMAINS:
            link_reasons.append("URL shortener hides destination")
            if link_status == "safe":
                link_status = "suspicious"
            signals.append(
                Signal(
                    category="regex",
                    code="url_shortener",
                    label="Obfuscated shortened URL hides destination",
                    weight=16,
                    evidence=f"Host: {host}",
                    phrase=raw_url,
                )
            )

        if host.endswith(RISKY_TLDS):
            link_reasons.append("High-risk TLD")
            if link_status == "safe":
                link_status = "suspicious"
            signals.append(
                Signal(
                    category="regex",
                    code="risky_tld",
                    label="High-risk disposable TLD in message link",
                    weight=16,
                    evidence=f"Host: {host}",
                    phrase=raw_url,
                )
            )

        if SUSPICIOUS_URL_PATHS.search(parsed.path or ""):
            link_reasons.append("Credential/payment lure path")
            link_status = "malicious"
            signals.append(
                Signal(
                    category="regex",
                    code="credential_url_path",
                    label="Credential or payment lure path in URL",
                    weight=18,
                    evidence=f"Path: {parsed.path}",
                    phrase=raw_url,
                )
            )

        for brand in mentioned_brands:
            allowed = OFFICIAL_DOMAINS[brand]
            if not any(host == d or host.endswith(f".{d}") for d in allowed):
                link_reasons.append(f"Impersonates {brand.title()}")
                link_status = "malicious"
                signals.append(
                    Signal(
                        category="regex",
                        code="brand_domain_mismatch",
                        label=f"Mentions '{brand.title()}' but links to unrelated host",
                        weight=22,
                        evidence=f"External host: {host}",
                        phrase=raw_url,
                    )
                )
                break

        inspected_links.append(
            InspectedLink(
                url=raw_url,
                host=host,
                status=link_status,
                reason="; ".join(link_reasons) if link_reasons else "Verified domain structure",
            )
        )

    if source_url:
        _ = urlparse(source_url).hostname

    return signals, inspected_links


def _analyze_heuristics(text: str) -> list[Signal]:
    signals: list[Signal] = []

    if ZERO_WIDTH_REGEX.search(text):
        signals.append(
            Signal(
                category="regex",
                code="zero_width_obfuscation",
                label="Invisible zero-width Unicode characters used to evade filters",
                weight=22,
                evidence="Hidden zero-width characters detected",
            )
        )

    if CYRILLIC_CHAR_REGEX.search(text) and LATIN_CHAR_REGEX.search(text):
        signals.append(
            Signal(
                category="regex",
                code="mixed_script_homoglyph",
                label="Mixed Cyrillic/Latin script homoglyph spoofing detected",
                weight=24,
                evidence="Mixed Unicode character sets in message",
            )
        )

    for label, pattern, weight in URGENCY_PATTERNS:
        m = pattern.search(text)
        if m:
            signals.append(
                Signal(
                    category="heuristics",
                    code="urgency_pressure",
                    label=label,
                    weight=weight,
                    evidence=_extract_snippet(m),
                    phrase=m.group(0),
                )
            )

    for label, pattern, weight in IMPERSONATION_PATTERNS:
        m = pattern.search(text)
        if m:
            signals.append(
                Signal(
                    category="heuristics",
                    code="impersonation_coercion",
                    label=label,
                    weight=weight,
                    evidence=_extract_snippet(m),
                    phrase=m.group(0),
                )
            )

    cred_matches = list(CREDENTIAL_ASK_REGEX.finditer(text))
    if cred_matches:
        unique_terms = list(dict.fromkeys(m.group(0).lower() for m in cred_matches))
        weight = min(30, 18 + (len(unique_terms) - 1) * 6)
        signals.append(
            Signal(
                category="regex",
                code="sensitive_request",
                label="Requests sensitive credentials, OTP, or funds",
                weight=weight,
                evidence=f"Terms: {', '.join(unique_terms[:4])}",
                phrase=cred_matches[0].group(0),
            )
        )

    crypto_matches = list(CRYPTO_LURE_REGEX.finditer(text))
    if crypto_matches:
        unique_terms = list(dict.fromkeys(m.group(0).lower() for m in crypto_matches))
        signals.append(
            Signal(
                category="heuristics",
                code="crypto_wallet_lure",
                label="Web3 / crypto wallet authorization lure",
                weight=22,
                evidence=f"Terms: {', '.join(unique_terms[:3])}",
                phrase=crypto_matches[0].group(0),
            )
        )

    return signals


def _analyze_ai_semantic(text: str, existing_signals: list[Signal]) -> list[Signal]:
    """
    AI-vs-AI semantic analyzer: detects Gen-AI phishing fingerprints where polished,
    typo-free prose conceals social-engineering intent.
    """
    signals: list[Signal] = []
    courtesy_matches = list(AI_COURTESY_PHRASES.finditer(text))
    recruiter_matches = list(RECRUITER_LURE_PHRASES.finditer(text))
    has_coercive_intent = any(
        s.code
        in {
            "urgency_pressure",
            "impersonation_coercion",
            "sensitive_request",
            "ip_literal_url",
            "credential_url_path",
            "crypto_wallet_lure",
        }
        for s in existing_signals
    )

    if courtesy_matches and has_coercive_intent:
        unique_courtesy = list(dict.fromkeys(m.group(0).lower() for m in courtesy_matches))
        signals.append(
            Signal(
                category="ai_semantic",
                code="llm_politeness_urgency_pivot",
                label="AI-style formal politeness masking urgent/sensitive ask",
                weight=18,
                evidence=f"Phrasing: {', '.join(unique_courtesy[:3])}",
                phrase=courtesy_matches[0].group(0),
            )
        )
    elif len(courtesy_matches) >= 2:
        unique_courtesy = list(dict.fromkeys(m.group(0).lower() for m in courtesy_matches))
        signals.append(
            Signal(
                category="ai_semantic",
                code="llm_cadence_cluster",
                label="Templated Gen-AI transition cadence detected",
                weight=10,
                evidence=f"Phrasing: {', '.join(unique_courtesy[:3])}",
                phrase=courtesy_matches[0].group(0),
            )
        )

    if recruiter_matches:
        unique_recruiter = list(dict.fromkeys(m.group(0).lower() for m in recruiter_matches))
        signals.append(
            Signal(
                category="ai_semantic",
                code="personalized_outreach_lure",
                label="Hyper-personalized outreach lure pattern",
                weight=15,
                evidence=f"Lure cues: {', '.join(unique_recruiter[:3])}",
                phrase=recruiter_matches[0].group(0),
            )
        )

    words = re.findall(r"\b[a-zA-Z]{2,}\b", text)
    if len(words) >= 25 and has_coercive_intent:
        avg_word_len = sum(len(w) for w in words) / len(words)
        has_all_caps_spam = bool(re.search(r"\b[A-Z]{5,}\b", text))
        if avg_word_len >= 4.7 and not has_all_caps_spam and len(existing_signals) >= 2:
            signals.append(
                Signal(
                    category="ai_semantic",
                    code="synthetic_polish_anomaly",
                    label="Clean, typo-free executive tone paired with high-risk triggers",
                    weight=10,
                    evidence=f"Avg word length {avg_word_len:.1f} with {len(existing_signals)} risk triggers",
                )
            )

    return signals


def _classify_attack_vector(signals: list[Signal], risk_score: int) -> tuple[str, str]:
    codes = {s.code for s in signals}
    if risk_score < 30:
        return (
            "Benign Workspace Communication",
            "No intervention needed. Standard communication hygiene applies.",
        )
    if "crypto_wallet_lure" in codes:
        return (
            "Web3 / Wallet Drain Lure",
            "Never sign unknown wallet approvals or share seed phrases. Verify the campaign on the official domain.",
        )
    if "personalized_outreach_lure" in codes:
        return (
            "Hyper-Personalized Outreach Lure",
            "Do not download unknown assessments or sign external NDAs. Confirm recruiter identity via official company channels.",
        )
    if "brand_domain_mismatch" in codes or "credential_url_path" in codes or "ip_literal_url" in codes:
        return (
            "Credential & MFA Harvesting",
            "Do not click login links or enter SSO/OTP codes. Open the service directly from a bookmarked official URL.",
        )
    if "impersonation_coercion" in codes or "sensitive_request" in codes:
        return (
            "Business Email Compromise (BEC)",
            "Verify any wire, remittance, or confidential request out-of-band (voice call or verified internal Slack) before acting.",
        )
    return (
        "Suspicious Social Engineering",
        "Inspect sender identity and link destinations carefully before replying or clicking.",
    )


def analyze_message(text: str, source_url: str | None = None) -> AnalysisResult:
    """Run localized regex, behavioral heuristics, and AI-vs-AI semantic scoring."""
    normalized = text.strip()
    url_signals, inspected_links = _analyze_urls(normalized, source_url)
    heuristic_signals = _analyze_heuristics(normalized)
    combined = url_signals + heuristic_signals
    semantic_signals = _analyze_ai_semantic(normalized, combined)

    all_signals = combined + semantic_signals

    seen: set[tuple[str, str]] = set()
    deduped: list[Signal] = []
    for sig in all_signals:
        key = (sig.code, sig.evidence)
        if key not in seen:
            seen.add(key)
            deduped.append(sig)

    breakdown = {"heuristics": 0, "regex": 0, "ai_semantic": 0}
    for sig in deduped:
        breakdown[sig.category] = breakdown.get(sig.category, 0) + sig.weight

    risk_score = max(0, min(100, sum(breakdown.values())))

    if risk_score >= 65:
        verdict = "high_risk"
        summary = "High-confidence social engineering detected. Do not click links, share codes, or transfer funds."
    elif risk_score >= 30:
        verdict = "caution"
        summary = "Suspicious conversational or link indicators found. Verify the sender through a trusted channel."
    else:
        verdict = "safe"
        summary = "No significant social engineering or semantic phishing indicators detected."

    attack_vector, recommended_action = _classify_attack_vector(deduped, risk_score)
    matched_phrases = list(dict.fromkeys(sig.phrase for sig in deduped if sig.phrase))
    text_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]

    return AnalysisResult(
        risk_score=risk_score,
        verdict=verdict,
        attack_vector=attack_vector,
        recommended_action=recommended_action,
        summary=summary,
        breakdown=breakdown,
        signals=deduped,
        matched_phrases=matched_phrases,
        inspected_links=inspected_links,
        redacted_preview=redact_sensitive_text(normalized),
        text_hash=text_hash,
    )
