"""Pydantic schemas for standardized findings and evidence."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Severity ratings for security observations and findings."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Finding(BaseModel):
    """Standardized finding record produced by analyzers and rules."""

    id: str = Field(..., description="Unique rule or indicator identifier")
    module: str = Field(
        ..., description="Analyzer module name (e.g. url_analysis, dns_analysis, tls_analysis)"
    )
    severity: Severity = Field(..., description="Severity classification")
    title: str = Field(..., description="Short summary of the observation")
    description: str = Field(..., description="Detailed explanation of the observation")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Raw supporting evidence")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="ISO-8601 UTC timestamp",
    )
