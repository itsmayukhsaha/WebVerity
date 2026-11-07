"""Module 4 — Threat intelligence provider interface and shared models.

Defines the standardized ``ThreatIntelligenceProvider`` contract and result
format used by every external source. Providers must NEVER cause a scan to
fail: all errors are captured into the standardized result.
"""

from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, Field


class ProviderStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"  # no credentials / not configured
    DEGRADED = "DEGRADED"  # errors observed recently
    RATE_LIMITED = "RATE_LIMITED"


class ThreatIntelligenceResult(BaseModel):
    """Standardized result returned by every provider."""

    source: str = Field(..., description="Provider source name, e.g. 'URLhaus'")
    query: str = Field(..., description="Redacted query indicator sent to the source")
    match_found: bool = Field(False, description="Whether a threat record matched")
    verified: bool = Field(
        False, description="Whether the match is human/automated verified by the source"
    )
    threat_type: str | None = Field(None, description="Threat classification from source")
    confidence: str = Field(
        "UNKNOWN", description="Provider-assigned confidence: UNKNOWN/LOW/MEDIUM/HIGH"
    )
    last_seen: str | None = Field(None, description="Last seen timestamp when available")
    reference: str | None = Field(None, description="Attribution/reference URL")
    error: str | None = Field(None, description="Error message if the lookup failed")
    status: str = Field("COMPLETED", description="Lookup execution status")


class ThreatIntelligenceProvider(Protocol):
    """Contract for all external threat intelligence adapters."""

    def get_source_name(self) -> str:
        """Human-readable provider name."""
        ...

    def get_provider_status(self) -> ProviderStatus:
        """Current availability state of the provider."""
        ...

    def check_url(self, url: str) -> ThreatIntelligenceResult:
        """Query the provider for the given (redacted) URL."""
        ...

    def check_domain(self, domain: str) -> ThreatIntelligenceResult:
        """Query the provider for the given domain."""
        ...


def redact_url_for_external_query(url: str) -> str:
    """Strip query strings and fragments before sending indicators externally.

    External providers must never receive sensitive URL parameters.
    """
    from urllib.parse import urlsplit, urlunparse

    parsed = urlsplit(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def combine_results(results: list[ThreatIntelligenceResult]) -> dict[str, Any]:
    """Combine provider results into the threat_intelligence module output."""
    return {
        "module": "threat_intelligence",
        "status": "COMPLETED" if results else "UNAVAILABLE",
        "providers_checked": len(results),
        "any_match": any(r.match_found for r in results),
        "any_verified_match": any(r.match_found and r.verified for r in results),
        "results": [r.model_dump() for r in results],
        "findings": [],
    }
