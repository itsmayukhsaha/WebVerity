"""Actionable security recommendation generator (Phase 2).

Derives human-readable recommendations from deduplicated findings, separating
defensive-hardening advice from threat-response guidance.
"""

from backend.app.detection.aggregator import AggregatedScanResult
from backend.app.schemas.scan import RiskClassification

RECOMMENDATION_MAP: dict[str, str] = {
    # HTTP security posture
    "HTTP_MISSING_HSTS": "Enable HSTS (Strict-Transport-Security) to enforce HTTPS.",
    "HTTP_MISSING_CSP": "Deploy a Content-Security-Policy to limit script injection.",
    "HTTP_MISSING_XCONTENTTYPE": "Set X-Content-Type-Options: nosniff on all responses.",
    "HTTP_MISSING_XFRAMEOPTIONS": "Add X-Frame-Options: DENY or CSP frame-ancestors to prevent clickjacking.",
    "HTTP_MISSING_REFERRER_POLICY": "Set a Referrer-Policy to limit referrer leakage.",
    "HTTP_MISSING_PERMISSIONS_POLICY": "Declare a Permissions-Policy restricting sensitive browser features.",
    "HTTP_NO_HTTPS": "Serve the site exclusively over HTTPS with automatic redirects.",
    "HTTP_COOKIE_MISSING_SECURE": "Mark session cookies with the Secure attribute.",
    "HTTP_COOKIE_MISSING_HTTPONLY": "Mark session cookies with the HttpOnly attribute.",
    "HTTP_COOKIE_MISSING_SAMESITE": "Set SameSite=Lax or Strict on state-changing cookies.",
    "HTTP_SERVER_DISCLOSURE": "Remove version details from the Server/X-Powered-By headers.",
    # TLS
    "TLS_HOSTNAME_MISMATCH": "Fix the certificate hostname mismatch immediately.",
    "TLS_CERTIFICATE_EXPIRED": "Renew the expired TLS certificate.",
    "TLS_UNTRUSTED_CHAIN": "Serve the complete trusted certificate chain.",
    "TLS_DEPRECATED_PROTOCOL": "Disable deprecated TLS versions (TLSv1.0/1.1).",
    "TLS_WEAK_KEY_SIZE": "Use a modern key size (RSA >= 2048 or ECDSA P-256).",
    "TLS_WEAK_SIGNATURE_ALGO": "Reissue the certificate with a SHA-256+ signature algorithm.",
    # Content / phishing response
    "CONTENT_BRAND_IMPERSONATION": (
        "Potential brand impersonation detected: do not enter credentials; verify the "
        "site through an independent official channel."
    ),
    "TI_VERIFIED_MALICIOUS_URL": (
        "Threat feeds list this URL as malicious: avoid the site entirely and report it "
        "to your security team or browser vendor."
    ),
    "TI_MALICIOUS_URL_UNVERIFIED": (
        "A threat feed flagged this indicator, but the match is unverified: treat with "
        "high caution and cross-check the source attribution."
    ),
    "CONTENT_EXTERNAL_FORM_ACTION": (
        "Forms submit data to an external domain: verify the destination before entering "
        "any sensitive information."
    ),
    "REDIRECT_HTTPS_DOWNGRADE": "Do not proceed: the redirect chain downgrades to plaintext HTTP.",
    "REDIRECT_SHORTENER": "Expand shortened links and confirm the destination before trusting it.",
    "RDAP_NEW_DOMAIN": (
        "The domain is newly registered: scrutinize it before trusting login or payment pages."
    ),
}


def generate_recommendations(aggregated: AggregatedScanResult) -> list[str]:
    """Produce an ordered, deduplicated recommendation list for a scan result."""
    recommendations: list[str] = []
    seen: set[str] = set()

    # Threat-response items first, ordered by severity of the matching finding.
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ordered_findings = sorted(
        aggregated.findings,
        key=lambda f: severity_order.get(f.severity.value, 5),
    )

    for finding in ordered_findings:
        rec = RECOMMENDATION_MAP.get(finding.id)
        if rec and rec not in seen:
            seen.add(rec)
            recommendations.append(rec)

    # Baseline guidance when nothing specific matched.
    if not recommendations:
        if aggregated.threat_assessment.classification in (
            RiskClassification.HIGH,
            RiskClassification.CRITICAL,
        ):
            recommendations.append(
                "Multiple correlated threat indicators were observed: exercise extreme "
                "caution and verify the site through independent channels."
            )
        else:
            recommendations.append(
                "No specific hardening actions matched the observed evidence. Maintain "
                "standard monitoring and verify URLs before entering credentials."
            )

    return recommendations[:15]
