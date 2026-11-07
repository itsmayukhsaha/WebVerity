"""Module 6 — Advanced risk correlation engine.

Extends the Phase 1 rule-based engine with:
- Separate THREAT RISK (phishing/malicious likelihood) and SECURITY POSTURE
  (configuration quality) scores that are never mixed.
- Independent evidence CONFIDENCE accounting for module completion and
  intelligence verification status.
- Anti-double-counting via seen-rule dedup and category caps.

Threat-risk classification: 0-24 LOW, 25-49 MODERATE, 50-74 HIGH, 75-100 CRITICAL.
"""

from typing import Any

from backend.app.detection.rules_engine import FINDING_TYPES, RULE_WEIGHTS
from backend.app.schemas.evidence import Finding
from backend.app.schemas.scan import ConfidenceLevel, RiskClassification, ThreatAssessment

LOW_RISK_DISCLAIMER = (
    "No strong threat indicators observed in the completed checks. "
    "This does not guarantee that the website is safe."
)

# Threat-risk category caps (URL 50% / DNS 25% / TLS 25% preserved from Phase 1;
# Phase 2 modules share a separate evidence pool capped per category).
CATEGORY_CAPS: dict[str, int] = {
    "url_analysis": 50,
    "dns_analysis": 25,
    "tls_analysis": 25,
    "redirect_analysis": 20,
    "content_analysis": 30,
    "http_security": 10,  # header weaknesses are NOT threat evidence
    "domain_intelligence": 15,
    "threat_intelligence": 70,
}

# Module completion statuses that count as usable evidence.
GOOD_STATUSES = {"COMPLETED", "RESOLVED", "OK"}
DEGRADED_STATUSES = {"TIMEOUT", "RATE_LIMITED", "UNAVAILABLE", "SKIPPED", "NOT_APPLICABLE"}
FAILED_STATUSES = {"FAILED", "ERROR"}

THREAT_RULE_WEIGHTS: dict[str, int] = {
    **RULE_WEIGHTS,
    # Phase 2 threat indicators
    "TI_VERIFIED_MALICIOUS_URL": 70,
    "TI_MALICIOUS_URL_UNVERIFIED": 25,
    "CONTENT_BRAND_IMPERSONATION": 30,
    "CONTENT_EXTERNAL_FORM_ACTION": 15,
    "CONTENT_DECEPTIVE_METADATA": 12,
    "CONTENT_PUNYCODE_HOST": 12,
    "REDIRECT_SSRF_BLOCKED": 35,
    "REDIRECT_HTTPS_DOWNGRADE": 10,
    "REDIRECT_CROSS_DOMAIN": 5,
    "REDIRECT_SHORTENER": 8,
    "REDIRECT_LOOP": 8,
    "REDIRECT_TOO_MANY": 8,
    "REDIRECT_LONG_CHAIN": 3,
    "RDAP_NEW_DOMAIN": 8,
    "RDAP_PENDING_DELETE": 12,
    "RDAP_EXPIRING_SOON": 3,
    "RDAP_DOMAIN_NOT_FOUND": 5,
}

# Rules that contribute to SECURITY POSTURE only (never to threat risk).
SECURITY_POSTURE_ONLY = {
    "HTTP_MISSING_HSTS",
    "HTTP_MISSING_CSP",
    "HTTP_MISSING_XCONTENTTYPE",
    "HTTP_MISSING_XFRAMEOPTIONS",
    "HTTP_MISSING_REFERRER_POLICY",
    "HTTP_MISSING_PERMISSIONS_POLICY",
    "HTTP_NO_HTTPS",
    "HTTP_COOKIE_MISSING_SECURE",
    "HTTP_COOKIE_MISSING_HTTPONLY",
    "HTTP_COOKIE_MISSING_SAMESITE",
    "HTTP_SERVER_DISCLOSURE",
    "HTTP_OUTDATED_SERVER",
    "TLS_HTTP_NO_ENCRYPTION",
    "TLS_DEPRECATED_PROTOCOL",
    "TLS_WEAK_KEY_SIZE",
    "TLS_EXPIRING_SOON",
    "DNS_NO_MX_RECORDS",
}

# Rules that indicate an outright threat (drive both posture slightly and threat risk).
THREAT_RULE_WEIGHTS_POPULATE = {
    "HTTP_UNEXPECTED_CONTENT_TYPE": 12,
    "HTTP_ERROR_STATUS": 0,
    "HTTP_NON_HTML_ROOT": 0,
    "CONTENT_PASSWORD_INPUT": 0,
    "CONTENT_EXCESSIVE_EXTERNAL_LINKS": 4,
    "CONTENT_META_REFRESH": 4,
    "CONTENT_EMPTY_PAGE": 0,
    "CONTENT_TRUNCATED": 0,
    "DNS_TIMEOUT": 0,
    "TLS_HANDSHAKE_ERROR": 0,
    "DNS_NXDOMAIN": 20,
}

POSTURE_WEIGHTS: dict[str, int] = {
    "HTTP_MISSING_HSTS": 10,
    "HTTP_MISSING_CSP": 15,
    "HTTP_MISSING_XCONTENTTYPE": 8,
    "HTTP_MISSING_XFRAMEOPTIONS": 8,
    "HTTP_MISSING_REFERRER_POLICY": 5,
    "HTTP_MISSING_PERMISSIONS_POLICY": 5,
    "HTTP_NO_HTTPS": 25,
    "HTTP_COOKIE_MISSING_SECURE": 10,
    "HTTP_COOKIE_MISSING_HTTPONLY": 10,
    "HTTP_COOKIE_MISSING_SAMESITE": 5,
    "HTTP_SERVER_DISCLOSURE": 5,
    "HTTP_OUTDATED_SERVER": 8,
    "TLS_HTTP_NO_ENCRYPTION": 25,
    "TLS_DEPRECATED_PROTOCOL": 10,
    "TLS_WEAK_KEY_SIZE": 8,
    "TLS_EXPIRING_SOON": 5,
    "DNS_NO_MX_RECORDS": 5,
    "HTTP_UNEXPECTED_CONTENT_TYPE": 8,
}


def classify_threat(score: int) -> RiskClassification:
    """Map a 0-100 threat risk score to its classification band."""
    if score >= 75:
        return RiskClassification.CRITICAL
    if score >= 50:
        return RiskClassification.HIGH
    if score >= 25:
        return RiskClassification.MODERATE
    return RiskClassification.LOW


def calculate_security_posture(findings: list[Finding]) -> int:
    """Score the website's security-configuration quality (0 = weak, 100 = strong).

    Only configuration-weakness rules count here. Missing headers can never
    push the THREAT score up.
    """
    penalty = 0
    seen: set[str] = set()
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        penalty += POSTURE_WEIGHTS.get(finding.id, 0)
    return max(0, 100 - min(penalty, 100))


def calculate_confidence(
    module_statuses: dict[str, str],
    findings: list[Finding],
    intelligence_results: list[dict[str, Any]] | None = None,
) -> ConfidenceLevel:
    """Evidence confidence — independent of threat risk.

    Accounts for module completion quality and the reliability/verification
    status of intelligence sources. Module timeouts reduce confidence; they
    never raise risk.
    """
    total = 0
    usable = 0
    for _module, status_value in module_statuses.items():
        total += 1
        if status_value in GOOD_STATUSES:
            usable += 1
        elif status_value in DEGRADED_STATUSES:
            usable += 0.5

    completeness = (usable / total) if total else 0.0

    # Verified intelligence strengthens confidence in the overall verdict.
    verified_intel = False
    if intelligence_results:
        for r in intelligence_results:
            if r.get("match_found") and r.get("verified"):
                verified_intel = True

    # Critical-rule presence (strong evidence) boosts confidence slightly.
    has_strong_evidence = any(
        FINDING_TYPES.get(f.id) == "CONFIRMED_THREAT_INDICATOR" or f.id.startswith("TI_VERIFIED")
        for f in findings
    )

    if completeness >= 0.9 and (verified_intel or has_strong_evidence):
        return ConfidenceLevel.HIGH
    if completeness >= 0.9:
        return ConfidenceLevel.HIGH
    if completeness >= 0.6:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def calculate_threat_risk(
    findings: list[Finding],
    module_statuses: dict[str, str],
) -> tuple[int, str, list[str]]:
    """Compute the correlated threat (phishing/malicious) risk score.

    Returns (score, explanation, top_rule_ids). Configuration-only weaknesses
    (SECURITY_CONFIGURATION_WEAKNESS / posture-only rules) are excluded from
    the threat score so that a legit site with poor headers is never labeled
    a phishing threat.
    """
    category_scores = dict.fromkeys(CATEGORY_CAPS, 0)
    seen_rule_ids: set[str] = set()
    contributing: list[tuple[str, int, str]] = []

    for finding in findings:
        rule_id = finding.id
        if rule_id in seen_rule_ids or rule_id in SECURITY_POSTURE_ONLY:
            continue
        seen_rule_ids.add(rule_id)

        weight = THREAT_RULE_WEIGHTS.get(rule_id, THREAT_RULE_WEIGHTS_POPULATE.get(rule_id, 0))
        if weight <= 0:
            continue
        category = finding.module
        if category not in category_scores:
            continue
        category_scores[category] += weight
        contributing.append((rule_id, weight, category))

    # Enforce category caps (prevents single-category domination / double counting)
    capped = {
        cat: min(score, cap)
        for cat, score, cap in zip(
            CATEGORY_CAPS.keys(), category_scores.values(), CATEGORY_CAPS.values(), strict=False
        )
    }
    total = min(sum(capped.values()), 100)

    explanation_rules = [
        f"{rid} (+{w} [{cat}])" for rid, w, cat in sorted(contributing, key=lambda x: -x[1])[:8]
    ]

    if total >= 75:
        explanation = (
            "Critical threat indicators: verified threat-feed matches, strong hostname "
            "impersonation, or severe infrastructure forgery. Do not submit credentials."
        )
    elif total >= 50:
        explanation = (
            "High threat risk: correlated suspicious signals across modules strongly "
            "suggest deceptive or malicious infrastructure."
        )
    elif total >= 25:
        explanation = (
            "Moderate threat signals detected. Corroborate before entering credentials "
            "or sensitive information."
        )
    else:
        explanation = LOW_RISK_DISCLAIMER

    if explanation_rules:
        explanation += f" Contributing evidence: {'; '.join(explanation_rules)}."

    return total, explanation, [r for r, _, _ in contributing]


def calculate_risk_score(
    findings: list[Finding],
    module_statuses: dict[str, str],
    intelligence_results: list[dict[str, Any]] | None = None,
) -> ThreatAssessment:
    """Phase 2 entry point: full correlated assessment.

    Kept backward compatible with Phase 1 callers (same name/signature plus an
    optional intelligence argument).
    """
    threat_score, explanation, _ = calculate_threat_risk(findings, module_statuses)
    calculate_security_posture(findings)  # posture is stored separately by callers
    confidence = calculate_confidence(module_statuses, findings, intelligence_results)
    classification = classify_threat(threat_score)

    return ThreatAssessment(
        risk_score=threat_score,
        classification=classification,
        confidence=confidence,
        is_probability=False,
        explanation=explanation,
    )
