"""Pydantic schemas for scan requests, responses, and module outputs."""

from enum import StrEnum
from typing import Any

from backend.app.schemas.evidence import Finding
from pydantic import BaseModel, Field


class ScanStatus(StrEnum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RiskClassification(StrEnum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConfidenceLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ScanCreateRequest(BaseModel):
    """Scan submission payload."""

    url: str = Field(
        ..., description="Target website URL to analyze", min_length=3, max_length=2048
    )


class ThreatAssessment(BaseModel):
    """Aggregated risk assessment and explainability metadata."""

    risk_score: int = Field(
        ..., ge=0, le=100, description="Heuristic threat risk score between 0 and 100"
    )
    classification: RiskClassification = Field(
        ..., description="Risk category: LOW, MODERATE, HIGH, CRITICAL"
    )
    confidence: ConfidenceLevel = Field(
        ..., description="Confidence rating based on evidence completeness"
    )
    is_probability: bool = Field(
        False, description="Explicit indicator that this is a heuristic score, not a probability"
    )
    explanation: str | None = Field(None, description="Human-readable summary of the evaluation")
    security_posture_score: int = Field(
        100, ge=0, le=100, description="Security configuration quality (0=weak, 100=strong)"
    )


class ModuleResults(BaseModel):
    """Analysis results by module."""

    url_analysis: dict[str, Any] = Field(
        default_factory=dict, description="URL feature extraction and structural analysis"
    )
    dns_analysis: dict[str, Any] = Field(
        default_factory=dict, description="DNS record queries and infrastructure data"
    )
    tls_analysis: dict[str, Any] = Field(
        default_factory=dict, description="TLS certificate inspection and trust validation"
    )
    http_security: dict[str, Any] = Field(
        default_factory=dict, description="HTTP security header and cookie assessment"
    )
    redirect_analysis: dict[str, Any] = Field(
        default_factory=dict, description="Redirect chain analysis"
    )
    content_analysis: dict[str, Any] = Field(
        default_factory=dict, description="Passive HTML content analysis"
    )
    domain_intelligence: dict[str, Any] = Field(
        default_factory=dict, description="RDAP domain registration intelligence"
    )
    threat_intelligence: dict[str, Any] = Field(
        default_factory=dict, description="External threat intelligence lookups"
    )


class ScanResponse(BaseModel):
    """Complete scan result response contract."""

    scan_id: str = Field(..., description="Unique UUID for this scan record")
    status: ScanStatus = Field(..., description="Scan execution status")
    target: str = Field(..., description="Target domain or normalized host")
    threat_assessment: ThreatAssessment = Field(..., description="Calculated threat evaluation")
    modules: ModuleResults = Field(..., description="Detailed module outputs")
    findings: list[Finding] = Field(
        default_factory=list, description="Aggregated security findings"
    )
    recommendations: list[str] = Field(
        default_factory=list, description="Actionable security recommendations"
    )
    scan_metadata: dict[str, Any] = Field(
        default_factory=dict, description="Module completion metadata and counters"
    )
    created_at: str = Field(..., description="ISO-8601 creation timestamp")
    completed_at: str | None = Field(None, description="ISO-8601 completion timestamp")
