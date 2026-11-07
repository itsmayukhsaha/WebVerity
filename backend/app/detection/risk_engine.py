"""Intelligent risk scoring engine (Phase 3).

Transparent, configurable, deterministic scoring: converts correlated
evidence into a 0-100 integer risk score with breakdown, reasons, and
precedence rules for confirmed threat-intelligence matches.

This is a heuristic scoring model — explicitly NOT a probability.
"""

from enum import StrEnum

from backend.app.detection.evidence_correlator import (
    CorrelatedEvidence,
    EvidenceCategory,
    EvidenceItem,
)
from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Configurable initial weights (not validated probabilities).
DEFAULT_WEIGHTS: dict[str, int] = {
    "confirmed_phishing_match": 90,
    "confirmed_malware_match": 90,
    "strong_brand_impersonation": 35,
    "suspicious_url_characteristics": 15,
    "suspicious_redirect_behaviour": 20,
    "high_risk_page_behaviour": 25,
    "suspicious_dns_domain_evidence": 10,
    "weak_tls_configuration": 5,
    "expired_certificate": 5,
    "missing_security_headers": 2,
}

# Map evidence categories to model keys and their cap (prevents domination).
CATEGORY_RULES: dict[EvidenceCategory, tuple[str, int]] = {
    EvidenceCategory.MALICIOUS_INDICATOR: ("confirmed_match", 100),
    EvidenceCategory.SUSPICIOUS: ("suspicious_evidence", 50),
    EvidenceCategory.SECURITY_WEAKNESS: ("weakness_evidence", 8),
    EvidenceCategory.NEUTRAL: ("neutral_evidence", 0),
}


class ScoreBreakdown(BaseModel):
    """Per-source contribution to the final score."""

    threat_intelligence: int = 0
    url_analysis: int = 0
    dns_analysis: int = 0
    tls_analysis: int = 0
    http_security: int = 0
    redirect_analysis: int = 0
    content_analysis: int = 0
    domain_intelligence: int = 0


class RiskAssessment(BaseModel):
    """Explainable risk output of the risk engine."""

    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    classification: RiskLevel
    score_breakdown: ScoreBreakdown
    reasons: list[str] = Field(default_factory=list)
    is_probability: bool = Field(
        False, description="Heuristic score — explicitly not a probability"
    )


# Evidence id prefixes/substrings mapped to reason phrasing.
_REASON_PHRASES = {
    "confirmed_phishing": "Confirmed phishing match from threat intelligence",
    "confirmed_malware": "Confirmed malware URL match from threat intelligence",
    "TI_": "Known threat indicator matched",
    "URL_": "Suspicious URL characteristics detected",
    "DNS_": "Suspicious DNS or domain evidence",
    "TLS_": "TLS configuration weakness observed",
    "HTTP_": "HTTP security configuration weakness",
    "REDIRECT_": "Suspicious redirect behaviour",
    "CONTENT_": "High-risk page/form behaviour",
    "BRAND_": "Strong brand impersonation indicators",
}


def _reason_for(item: EvidenceItem) -> str:
    for prefix, phrase in _REASON_PHRASES.items():
        if item.id.startswith(prefix):
            return phrase
    return item.description[:120]


def classify_level(score: int) -> RiskLevel:
    """Initial classification bands (0-19 LOW, 20-49 MODERATE, 50-79 HIGH,
    80-100 CRITICAL)."""
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 20:
        return RiskLevel.MODERATE
    return RiskLevel.LOW


def calculate_risk(
    evidence: CorrelatedEvidence,
    weights: dict[str, int] | None = None,
    has_verified_intelligence: bool | None = None,
    completed_modules: int = 0,
    total_modules: int = 0,
) -> RiskAssessment:
    """Deterministically score correlated evidence into 0-100 risk.

    Precedence rule: a confirmed threat-intelligence match (verified by the
    provider) forces a CRITICAL classification regardless of other evidence,
    because provider verification dominates all heuristics.
    """
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    breakdown = ScoreBreakdown()
    reasons: list[str] = []

    confirmed_match = False
    for item in evidence.malicious:
        confirmed_match = confirmed_match or item.confidence >= 0.9
        if "threat_intelligence" in item.origin or item.id.startswith("TI_"):
            breakdown.threat_intelligence = min(
                breakdown.threat_intelligence + w.get("confirmed_malware_match", 90), 100
            )
        reasons.append(_reason_for(item))

    category_scores: dict[EvidenceCategory, int] = {}
    for item in evidence.items:
        if item.category in (EvidenceCategory.MALICIOUS_INDICATOR, EvidenceCategory.UNAVAILABLE):
            continue
        cap = CATEGORY_RULES[item.category][1]
        if cap == 0:
            continue
        category_scores.setdefault(item.category, 0)
        if item.category == EvidenceCategory.SUSPICIOUS:
            weight = w.get("suspicious_url_characteristics", 15)
        else:
            weight = w.get("missing_security_headers", 2)
        category_scores[item.category] = min(category_scores[item.category] + weight, cap)

    source_map = {
        "url_analysis": "url_analysis",
        "dns_analysis": "dns_analysis",
        "tls_analysis": "tls_analysis",
        "http_security": "http_security",
        "redirect_analysis": "redirect_analysis",
        "content_analysis": "content_analysis",
        "domain_intelligence": "domain_intelligence",
    }
    for item in evidence.items:
        if item.category in (EvidenceCategory.MALICIOUS_INDICATOR, EvidenceCategory.UNAVAILABLE):
            continue
        weight = (
            w.get("suspicious_url_characteristics", 15)
            if item.category == EvidenceCategory.SUSPICIOUS
            else w.get("missing_security_headers", 2)
        )
        field = source_map.get(item.origin)
        if field:
            current = getattr(breakdown, field)
            setattr(breakdown, field, min(current + weight, 60))
        if len(reasons) < 12 and not any(r == _reason_for(item) for r in reasons):
            reasons.append(_reason_for(item))

    total = sum(
        [
            breakdown.threat_intelligence,
            breakdown.url_analysis,
            breakdown.dns_analysis,
            breakdown.tls_analysis,
            breakdown.http_security,
            breakdown.redirect_analysis,
            breakdown.content_analysis,
            breakdown.domain_intelligence,
        ]
    )
    total = min(total, 100)

    # Precedence: confirmed intelligence dominates heuristics.
    if confirmed_match:
        total = max(total, 90)
        reasons.insert(0, "Confirmed threat-intelligence match — MALICIOUS classification")

    risk_level = classify_level(total)
    if confirmed_match:
        risk_level = RiskLevel.CRITICAL

    # Insufficient-evidence guard: few completed modules cap the escalation.
    if total_modules > 0 and completed_modules < (total_modules // 2) and not confirmed_match:
        if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            risk_level = RiskLevel.MODERATE
        reasons.append(
            "Insufficient completed checks — classification capped at MODERATE "
            "pending further evidence"
        )

    return RiskAssessment(
        risk_score=total,
        risk_level=risk_level,
        classification=risk_level,
        score_breakdown=breakdown,
        reasons=reasons or ["No strong threat indicators observed in the completed checks."],
    )


__all__ = ["DEFAULT_WEIGHTS", "RiskAssessment", "RiskLevel", "calculate_risk", "classify_level"]
