"""Normalized threat-intelligence data models (Phase 3).

Extends the Phase 2 ``ThreatIntelligenceResult`` contract with the richer
normalized indicator/match schema required for explainable evidence
correlation. Providers convert their raw responses into these models; the
correlator and risk engine consume them exclusively.
"""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class IndicatorType(StrEnum):
    """Type of threat indicator."""

    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"


class MatchType(StrEnum):
    """How the submitted indicator matched a stored threat record."""

    EXACT_URL = "exact_url"
    CANONICAL_URL = "canonical_url"
    EXACT_DOMAIN = "exact_domain"
    SUBDOMAIN = "subdomain"
    NONE = "none"


class VerificationStatus(StrEnum):
    """Source-side verification of the threat report."""

    CONFIRMED = "confirmed"
    UNVERIFIED = "unverified"
    UNKNOWN = "unknown"


class ProviderResponseStatus(StrEnum):
    """Execution status of a provider lookup."""

    MATCH = "match"
    CLEAN = "clean"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    ERROR = "error"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


class NormalizedIndicatorMatch(BaseModel):
    """Normalized, explainable result of a single provider lookup."""

    provider: str = Field(..., description="Provider name, e.g. 'URLhaus'")
    indicator_type: IndicatorType = Field(..., description="Kind of indicator queried")
    indicator_value: str = Field(..., description="Normalized indicator that was queried")
    original_value: str = Field(..., description="Original (pre-normalization, redacted) indicator")
    matched: bool = Field(False, description="Whether a threat record matched")
    match_type: MatchType = Field(MatchType.NONE, description="Matching method used")
    threat_category: str | None = Field(None, description="e.g. 'phishing', 'malware_url'")
    verification_status: VerificationStatus = Field(
        VerificationStatus.UNKNOWN, description="Source-side verification state"
    )
    source_url: str | None = Field(None, description="Attribution/reference URL")
    first_observed: str | None = Field(None, description="First-seen timestamp from source")
    last_observed: str | None = Field(None, description="Last-seen timestamp from source")
    retrieved_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="When this result was retrieved",
    )
    expires_at: str | None = Field(None, description="Freshness expiry for cached results")
    response_status: ProviderResponseStatus = Field(
        ProviderResponseStatus.CLEAN, description="Provider lookup execution status"
    )
    error: str | None = Field(None, description="Error detail when the lookup failed")
    is_probability: bool = Field(
        False,
        description="Always False: heuristic/threat-feed evidence is not a probability",
    )


class ProviderHealth(BaseModel):
    """Provider availability snapshot for the status endpoint."""

    provider: str
    configured: bool
    enabled: bool
    status: ProviderResponseStatus
    description: str
