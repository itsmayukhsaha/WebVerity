"""Module 4 — External threat intelligence integrations.

Central registry that orchestrates all configured providers. Failures in any
single provider are isolated and reported as standardized results; the scan
pipeline never crashes due to intelligence outages.
"""

from typing import Any

from backend.app.analyzers.url_analyzer.normalizer import NormalizedURL
from backend.app.core.logging import logger, sanitize_url_for_logging
from backend.app.intelligence.base import (
    ThreatIntelligenceProvider,
    ThreatIntelligenceResult,
    combine_results,
    redact_url_for_external_query,
)
from backend.app.intelligence.phishtank import PhishTankProvider
from backend.app.intelligence.urlhaus import URLhausProvider
from backend.app.schemas.evidence import Finding, Severity

MODULE_NAME = "threat_intelligence"

# Verified threat-feed match weight — dominates weak heuristics per policy.
VERIFIED_MATCH_WEIGHT = 70
UNVERIFIED_MATCH_WEIGHT = 25


def get_configured_providers() -> list[ThreatIntelligenceProvider]:
    """Instantiate every provider adapter (availability is decided per provider)."""
    return [
        URLhausProvider(),
        PhishTankProvider(),
        # Future adapters (OpenPhish, AlienVault OTX) implement the same
        # ThreatIntelligenceProvider protocol and can be appended here.
    ]


def check_threat_intelligence(normalized: NormalizedURL) -> tuple[dict[str, Any], list[Finding]]:
    """Query every configured provider against the redacted URL and domain.

    Args:
        normalized: Normalized target URL.

    Returns:
        Tuple of (module_result_dict, findings_list).
    """
    findings: list[Finding] = []
    results: list[ThreatIntelligenceResult] = []

    redacted_url = redact_url_for_external_query(normalized.normalized_url)
    domain = normalized.hostname

    for provider in get_configured_providers():
        try:
            results.append(provider.check_url(redacted_url))
            results.append(provider.check_domain(domain))
        except Exception as e:  # never let one provider break the scan
            logger.error(
                f"Threat provider '{provider.get_source_name()}' failed: {e}", exc_info=True
            )
            results.append(
                ThreatIntelligenceResult(
                    source=provider.get_source_name(),
                    query=domain,
                    error=f"Unexpected provider error: {e}",
                    status="FAILED",
                )
            )

    for result in results:
        if not result.match_found:
            continue
        verified = result.match_found and result.verified
        findings.append(
            Finding(
                id="TI_VERIFIED_MALICIOUS_URL" if verified else "TI_MALICIOUS_URL_UNVERIFIED",
                module=MODULE_NAME,
                severity=Severity.CRITICAL if verified else Severity.MEDIUM,
                title=(
                    f"Verified Threat-Feed Match ({result.source})"
                    if verified
                    else f"Unverified Threat-Feed Match ({result.source})"
                ),
                description=(
                    f"Source '{result.source}' reports the indicator as "
                    f"'{result.threat_type}' with confidence '{result.confidence}'. "
                    f"{'Human/machine-verified by the source.' if verified else 'Match is not independently verified by the source.'} "
                    f"Last seen: {result.last_seen or 'unknown'}."
                ),
                evidence={
                    "source": result.source,
                    "query": sanitize_url_for_logging(result.query),
                    "verified": verified,
                    "threat_type": result.threat_type,
                    "confidence": result.confidence,
                },
            )
        )

    module_result = combine_results(results)
    module_result["findings"] = [f.model_dump() for f in findings]
    return module_result, findings


__all__ = [
    "PhishTankProvider",
    "URLhausProvider",
    "check_threat_intelligence",
    "get_configured_providers",
]
