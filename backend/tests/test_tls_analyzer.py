"""Tests for TLS certificate analyzer with mocked network fixtures."""

from unittest.mock import patch

from backend.app.analyzers.tls_analyzer.handshake import TLSHandshakeResult
from backend.app.analyzers.tls_analyzer.validator import match_hostname, validate_tls


def test_hostname_matching_helper():
    """Verify RFC 6125 wildcard and exact hostname matching logic."""
    assert match_hostname("example.com", ["example.com"]) is True
    assert match_hostname("sub.example.com", ["*.example.com"]) is True
    assert match_hostname("deep.sub.example.com", ["*.example.com"]) is False
    assert match_hostname("other.com", ["example.com"]) is False


def test_tls_http_not_applicable():
    """Verify HTTP requests produce NOT_APPLICABLE status and transport finding."""
    res, findings = validate_tls(scheme="http", hostname="example.com", port=80)
    assert res["status"] == "NOT_APPLICABLE"
    assert res["https_enabled"] is False
    assert res["chain_validation"] == "NOT_APPLICABLE"
    finding_ids = [f.id for f in findings]
    assert "TLS_HTTP_NO_ENCRYPTION" in finding_ids


@patch("backend.app.analyzers.tls_analyzer.validator.perform_tls_handshake")
def test_valid_tls_handshake(mock_handshake, dummy_x509_cert_builder):
    """Verify valid certificate and handshake produce VALID status."""
    cert_der = dummy_x509_cert_builder(
        common_name="example.com", sans=["example.com", "www.example.com"]
    )
    mock_handshake.return_value = TLSHandshakeResult(
        der_cert=cert_der,
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        is_verified=True,
        verification_error=None,
        handshake_success=True,
    )

    res, findings = validate_tls(
        scheme="https",
        hostname="example.com",
        destination_ip="93.184.216.34",
    )

    assert res["status"] == "COMPLETED"
    assert res["chain_validation"] == "VALID"
    assert res["hostname_match"] is True
    assert res["certificate_expired"] is False
    assert res["tls_version"] == "TLSv1.3"


@patch("backend.app.analyzers.tls_analyzer.validator.perform_tls_handshake")
def test_expired_certificate(mock_handshake, dummy_x509_cert_builder):
    """Verify expired certificate is identified and flagged."""
    cert_der = dummy_x509_cert_builder(common_name="example.com", expired=True)
    mock_handshake.return_value = TLSHandshakeResult(
        der_cert=cert_der,
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        is_verified=False,
        verification_error="certificate has expired",
        handshake_success=True,
    )

    res, findings = validate_tls(
        scheme="https",
        hostname="example.com",
        destination_ip="93.184.216.34",
    )

    assert res["chain_validation"] == "EXPIRED"
    assert res["certificate_expired"] is True
    finding_ids = [f.id for f in findings]
    assert "TLS_CERTIFICATE_EXPIRED" in finding_ids


@patch("backend.app.analyzers.tls_analyzer.validator.perform_tls_handshake")
def test_hostname_mismatch(mock_handshake, dummy_x509_cert_builder):
    """Verify hostname mismatch is flagged."""
    # Certificate was issued for otherdomain.com, but host requested is example.com
    cert_der = dummy_x509_cert_builder(common_name="otherdomain.com", sans=["otherdomain.com"])
    mock_handshake.return_value = TLSHandshakeResult(
        der_cert=cert_der,
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        is_verified=True,
        handshake_success=True,
    )

    res, findings = validate_tls(
        scheme="https",
        hostname="example.com",
        destination_ip="93.184.216.34",
    )

    assert res["hostname_match"] is False
    assert res["chain_validation"] == "INVALID"
    finding_ids = [f.id for f in findings]
    assert "TLS_HOSTNAME_MISMATCH" in finding_ids


@patch("backend.app.analyzers.tls_analyzer.validator.perform_tls_handshake")
def test_tls_handshake_timeout(mock_handshake):
    """Verify TLS handshake timeout is handled gracefully."""
    mock_handshake.return_value = TLSHandshakeResult(
        handshake_success=False,
        error_type="TIMEOUT",
        verification_error="Socket timeout",
    )

    res, findings = validate_tls(
        scheme="https",
        hostname="example.com",
        destination_ip="93.184.216.34",
    )

    assert res["status"] == "UNKNOWN"
    assert res["chain_validation"] == "UNKNOWN"
    finding_ids = [f.id for f in findings]
    assert "TLS_HANDSHAKE_ERROR" in finding_ids
