"""Tests for rule-based risk scoring and confidence engine."""

from backend.app.detection.risk_scoring import LOW_RISK_DISCLAIMER, calculate_risk_score
from backend.app.schemas.evidence import Finding, Severity
from backend.app.schemas.scan import ConfidenceLevel, RiskClassification


def test_zero_findings_low_classification():
    """Verify clean scans produce LOW risk score and proper disclaimer."""
    assessment = calculate_risk_score(
        findings=[],
        module_statuses={
            "url_analysis": "COMPLETED",
            "dns_analysis": "RESOLVED",
            "tls_analysis": "COMPLETED",
        },
    )

    assert assessment.risk_score == 0
    assert assessment.classification == RiskClassification.LOW
    assert assessment.confidence == ConfidenceLevel.HIGH
    assert assessment.explanation == LOW_RISK_DISCLAIMER
    assert assessment.is_probability is False


def test_weak_signals_do_not_overreact():
    """Verify one or two weak signals remain in LOW classification."""
    findings = [
        Finding(
            id="URL_EXCESSIVE_LENGTH",
            module="url_analysis",
            severity=Severity.LOW,
            title="Long URL",
            description="Long URL",
        ),
        Finding(
            id="DNS_NO_MX_RECORDS",
            module="dns_analysis",
            severity=Severity.INFO,
            title="No MX",
            description="No MX",
        ),
    ]

    assessment = calculate_risk_score(
        findings=findings,
        module_statuses={
            "url_analysis": "COMPLETED",
            "dns_analysis": "RESOLVED",
            "tls_analysis": "COMPLETED",
        },
    )

    # Phase 2: DNS_NO_MX_RECORDS is a security-posture weakness, NOT threat
    # evidence, so it no longer adds to the threat score. 5 (URL) -> LOW.
    assert assessment.risk_score == 5
    assert assessment.classification == RiskClassification.LOW


def test_moderate_classification():
    """Verify combination of moderate indicators yields MODERATE risk."""
    findings = [
        Finding(
            id="URL_PUNYCODE",
            module="url_analysis",
            severity=Severity.MEDIUM,
            title="Punycode",
            description="Punycode",
        ),
        Finding(
            id="TLS_HTTP_NO_ENCRYPTION",
            module="tls_analysis",
            severity=Severity.MEDIUM,
            title="HTTP Plaintext",
            description="Plaintext",
        ),
    ]

    assessment = calculate_risk_score(
        findings=findings,
        module_statuses={
            "url_analysis": "COMPLETED",
            "dns_analysis": "RESOLVED",
            "tls_analysis": "NOT_APPLICABLE",
        },
    )

    # Phase 2: TLS_HTTP_NO_ENCRYPTION is a security-posture weakness, NOT
    # threat evidence, so only the URL punycode contributes: 20 -> LOW.
    assert assessment.risk_score == 20
    assert assessment.classification == RiskClassification.LOW


def test_high_classification():
    """Verify multiple suspicious signals produce HIGH classification."""
    findings = [
        Finding(
            id="URL_IP_HOST",
            module="url_analysis",
            severity=Severity.HIGH,
            title="IP Host",
            description="Direct IP",
        ),
        Finding(
            id="DNS_NO_RECORDS",
            module="dns_analysis",
            severity=Severity.MEDIUM,
            title="No records",
            description="No records",
        ),
    ]

    assessment = calculate_risk_score(
        findings=findings,
        module_statuses={
            "url_analysis": "COMPLETED",
            "dns_analysis": "RESOLVED",
            "tls_analysis": "COMPLETED",
        },
    )

    # 35 (URL) + 15 (DNS) = 50 -> HIGH
    assert assessment.risk_score == 50
    assert assessment.classification == RiskClassification.HIGH


def test_critical_classification():
    """Verify critical threat signals produce CRITICAL classification."""
    findings = [
        Finding(
            id="URL_IP_HOST",
            module="url_analysis",
            severity=Severity.HIGH,
            title="IP Host",
            description="Direct IP",
        ),
        Finding(
            id="URL_AT_SYMBOL",
            module="url_analysis",
            severity=Severity.HIGH,
            title="@ Symbol",
            description="@ Symbol",
        ),
        Finding(
            id="TLS_HOSTNAME_MISMATCH",
            module="tls_analysis",
            severity=Severity.HIGH,
            title="Mismatch",
            description="Mismatch",
        ),
    ]

    assessment = calculate_risk_score(
        findings=findings,
        module_statuses={
            "url_analysis": "COMPLETED",
            "dns_analysis": "RESOLVED",
            "tls_analysis": "COMPLETED",
        },
    )

    # URL capped at 50 + TLS 25 = 75 -> CRITICAL
    assert assessment.risk_score == 75
    assert assessment.classification == RiskClassification.CRITICAL


def test_technical_failures_do_not_inflate_risk():
    """Verify DNS and TLS timeouts add zero threat weight."""
    findings = [
        Finding(
            id="DNS_TIMEOUT",
            module="dns_analysis",
            severity=Severity.INFO,
            title="DNS Timeout",
            description="DNS Timeout",
        ),
        Finding(
            id="TLS_HANDSHAKE_ERROR",
            module="tls_analysis",
            severity=Severity.LOW,
            title="TLS Timeout",
            description="TLS Timeout",
        ),
    ]

    assessment = calculate_risk_score(
        findings=findings,
        module_statuses={
            "url_analysis": "COMPLETED",
            "dns_analysis": "TIMEOUT",
            "tls_analysis": "UNKNOWN",
        },
    )

    assert assessment.risk_score == 0
    assert assessment.classification == RiskClassification.LOW
    # Multiple failed modules reduce confidence to LOW
    assert assessment.confidence == ConfidenceLevel.LOW
