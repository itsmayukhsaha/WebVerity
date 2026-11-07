"""Confidence engine (Phase 3): independent of risk scoring.

Measures how much we trust the verdict, not how risky the target is.
High confidence is never reported when essential checks have failed.
"""

from enum import StrEnum
from typing import Any

from backend.app.detection.evidence_correlator import (
    CorrelatedEvidence,
    EvidenceCategory,
)
from pydantic import BaseModel, Field


class ConfidenceLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# Minimum modules that must complete before HIGH confidence is possible.
_MIN_COMPLETED_FOR_HIGH = 6


class ConfidenceAssessment(BaseModel):
    """Independent confidence verdict."""

    confidence_score: int = Field(..., ge=0, le=100)
    confidence_level: ConfidenceLevel
    successful_checks: list[str] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)
    unavailable_providers: list[str] = Field(default_factory=list)
    explanation: str = Field(...)


def calculate_confidence(
    module_statuses: dict[str, str],
    evidence: CorrelatedEvidence,
    intelligence_matches: list[dict[str, Any]] | None = None,
) -> ConfidenceAssessment:
    """Compute evidence confidence from completion, reliability, verification,
    corroboration, and freshness of intelligence."""
    good = {"COMPLETED", "RESOLVED", "OK"}
    degraded = {"UNKNOWN", "PARTIAL"}
    successful = [m for m, s in module_statuses.items() if s in good]
    failed = [m for m, s in module_statuses.items() if s in ("FAILED", "ERROR", "TIMEOUT")]
    unavailable = [m for m, s in module_statuses.items() if s in ("SKIPPED",)]

    total = len(module_statuses) or 1
    weighted_completion = sum(
        1 if s in good else 0.5 if s in degraded else 0.0 for s in module_statuses.values()
    )
    completeness = weighted_completion / total

    verified_matches = [
        m
        for m in (intelligence_matches or [])
        if m.get("matched") and m.get("verification_status") == "confirmed"
    ]
    corroboration_bonus = 0.0
    if verified_matches and len(evidence.malicious) > 1:
        corroboration_bonus = 0.1  # independent sources agree

    # Source reliability: mean confidence of completed evidence items.
    completed_items = [i for i in evidence.items if i.category != EvidenceCategory.UNAVAILABLE]
    reliability = (
        sum(i.confidence for i in completed_items) / len(completed_items)
        if completed_items
        else 0.5
    )

    score = 0.6 * completeness + 0.25 * reliability + corroboration_bonus
    if verified_matches:
        score = max(score, 0.85)

    # Never high confidence with essential checks failed.
    if failed and score >= 0.8:
        score = 0.75

    level = (
        ConfidenceLevel.HIGH
        if score >= 0.8 and len(successful) >= _MIN_COMPLETED_FOR_HIGH
        else ConfidenceLevel.MEDIUM
        if score >= 0.5
        else ConfidenceLevel.LOW
    )

    parts = [
        f"{len(successful)}/{total} checks completed successfully",
        f"evidence reliability {reliability:.2f}",
    ]
    if verified_matches:
        parts.append(
            f"{len(verified_matches)} provider-verified threat match(es) corroborate the verdict"
        )
    if failed:
        parts.append(f"{len(failed)} check(s) failed: {', '.join(failed)}")
    if unavailable:
        parts.append(f"{len(unavailable)} provider(s) unavailable: {', '.join(unavailable)}")

    return ConfidenceAssessment(
        confidence_score=round(score * 100),
        confidence_level=level,
        successful_checks=successful,
        failed_checks=failed,
        unavailable_providers=unavailable,
        explanation="; ".join(parts) + ". Observation count alone is not proof of reliability.",
    )


__all__ = ["ConfidenceAssessment", "ConfidenceLevel", "calculate_confidence"]
