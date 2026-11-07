"""Final detection orchestrator (Phase 3).

Receives Phase 2 scan results, gathers normalized intelligence, correlates
evidence, and produces one unified detection result with risk, confidence,
and explanations. Provider failures never block the scan.
"""

import asyncio
from typing import Any

from backend.app.core.logging import logger
from backend.app.detection.confidence_engine import (
    ConfidenceAssessment,
    calculate_confidence,
)
from backend.app.detection.evidence_correlator import (
    CorrelatedEvidence,
    correlate_evidence,
)
from backend.app.detection.risk_engine import RiskAssessment, calculate_risk


class DetectionResult:
    """Unified detection output combining Phase 2 assessment with Phase 3
    correlation, scoring, and confidence."""

    def __init__(
        self,
        risk: RiskAssessment,
        confidence: ConfidenceAssessment,
        evidence: CorrelatedEvidence,
        intelligence_matches: list[dict[str, Any]],
        explanation: str,
    ):
        self.risk = risk
        self.confidence = confidence
        self.evidence = evidence
        self.intelligence_matches = intelligence_matches
        self.explanation = explanation

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk.risk_score,
            "risk_level": self.risk.risk_level.value,
            "classification": self.risk.classification.value,
            "score_breakdown": self.risk.score_breakdown.model_dump(),
            "reasons": self.risk.reasons,
            "confidence_score": self.confidence.confidence_score,
            "confidence_level": self.confidence.confidence_level.value,
            "confidence_explanation": self.confidence.explanation,
            "successful_checks": self.confidence.successful_checks,
            "failed_checks": self.confidence.failed_checks,
            "unavailable_providers": self.confidence.unavailable_providers,
            "evidence": [e.model_dump() for e in self.evidence.items],
            "duplicates_removed": self.evidence.duplicates_removed,
            "intelligence_matches": self.intelligence_matches,
            "explanation": self.explanation,
            "is_probability": False,
        }


async def run_detection(
    aggregated,
    module_statuses: dict[str, str],
) -> DetectionResult:
    """Run the Phase 3 detection pipeline over completed Phase 2 results.

    Args:
        aggregated: ``AggregatedScanResult`` from the Phase 2 pipeline.
        module_statuses: Module name -> status map.
    """
    from backend.app.analyzers.url_analyzer.normalizer import NormalizedURL
    from backend.app.intelligence.intelligence_manager import collect_intelligence

    def _query(normalized_url: str) -> NormalizedURL:
        # Minimal container re-using the existing normalizer output fields.
        return NormalizedURL(
            normalized_url=normalized_url,
            redacted_url=normalized_url,
            scheme="https",
            hostname="",
            unicode_hostname="",
            has_punycode=False,
            port=443,
            path="/",
            query="",
        )

    matches: list[dict[str, Any]] = []
    try:
        url = (aggregated.modules.get("url_analysis") or {}).get("features", {}).get("url")
        domain = (aggregated.modules.get("dns_analysis") or {}).get("domain")
        # collect_intelligence expects a NormalizedURL; build one via helper.
        from backend.app.intelligence.intelligence_manager import _deduplicate  # noqa: F401

        normalized_stub = None
        for candidate in (url, domain):
            if candidate:
                from urllib.parse import urlparse

                host = urlparse(candidate).hostname or domain or ""
                normalized_stub = NormalizedURL(
                    normalized_url=candidate
                    if candidate.startswith("http")
                    else f"https://{candidate}",
                    redacted_url=candidate,
                    scheme="https",
                    hostname=host,
                    unicode_hostname=host,
                    has_punycode=False,
                    port=443,
                    path="/",
                    query="",
                )
                break
        if normalized_stub is not None:
            normalized_matches = await asyncio.wait_for(
                asyncio.to_thread(collect_intelligence, normalized_stub), timeout=15.0
            )
            matches = [m.model_dump() for m in normalized_matches]
    except Exception as e:
        logger.error(f"Phase 3 intelligence collection failed (non-fatal): {e}", exc_info=True)
        matches = []

    evidence = correlate_evidence(
        findings=aggregated.findings,
        module_statuses=module_statuses,
        intelligence_matches=matches,
    )

    verified = any(
        m.get("matched") and m.get("verification_status") == "confirmed" for m in matches
    )
    completed = sum(1 for s in module_statuses.values() if s in ("COMPLETED", "RESOLVED", "OK"))
    risk = calculate_risk(
        evidence=evidence,
        has_verified_intelligence=verified,
        completed_modules=completed,
        total_modules=len(module_statuses),
    )
    confidence = calculate_confidence(module_statuses, evidence, matches)

    explanation_parts = list(risk.reasons[:5])
    explanation = " ".join(explanation_parts)
    if evidence.duplicates_removed:
        explanation += (
            f" ({evidence.duplicates_removed} duplicate finding(s) removed before scoring.)"
        )
    if any(e.category.value == "unavailable" for e in evidence.items):
        explanation += (
            " Some checks did not complete; missing evidence is not interpreted as a clean result."
        )
    explanation += (
        (
            " Scores are heuristic and explicitly not calibrated probabilities. "
            "No strong threat indicators observed in the completed checks does not "
            "guarantee that the website is safe."
        )
        if risk.risk_score < 20
        else ""
    )

    return DetectionResult(
        risk=risk,
        confidence=confidence,
        evidence=evidence,
        intelligence_matches=matches,
        explanation=explanation,
    )
