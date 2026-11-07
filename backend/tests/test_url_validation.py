"""Tests for URL validation and normalization."""

import pytest
from backend.app.analyzers.url_analyzer.normalizer import normalize_url, redact_query_parameters
from backend.app.analyzers.url_analyzer.validator import URLValidationError, validate_url


def test_valid_https_url():
    """Verify valid HTTPS URLs pass validation."""
    validate_url("https://example.com")
    validate_url("https://sub.domain.org/path/to/resource?param=value")


def test_valid_http_url():
    """Verify valid HTTP URLs pass validation."""
    validate_url("http://example.com")
    validate_url("http://example.com:80/index.html")


def test_malformed_urls():
    """Verify malformed and empty URLs are rejected."""
    with pytest.raises(URLValidationError):
        validate_url("")
    with pytest.raises(URLValidationError):
        validate_url("not-a-valid-url")
    with pytest.raises(URLValidationError):
        validate_url("://missing-scheme.com")


def test_unsupported_protocols():
    """Verify non-HTTP(S) protocols are strictly rejected."""
    with pytest.raises(URLValidationError, match="Unsupported scheme 'ftp'"):
        validate_url("ftp://ftp.example.com/file.txt")
    with pytest.raises(URLValidationError, match="Unsupported scheme 'file'"):
        validate_url("file:///etc/passwd")
    with pytest.raises(URLValidationError, match="Unsupported scheme 'javascript'"):
        validate_url("javascript:alert(1)")


def test_unsupported_ports():
    """Verify ports other than 80 and 443 are rejected in Day 1."""
    with pytest.raises(URLValidationError, match="Port 8080 is not permitted"):
        validate_url("http://example.com:8080/test")
    with pytest.raises(URLValidationError, match="Port 22 is not permitted"):
        validate_url("https://example.com:22/")


def test_embedded_credentials_rejected():
    """Verify URLs with embedded username or passwords are rejected."""
    with pytest.raises(URLValidationError, match="embedded authentication credentials"):
        validate_url("http://user:password@example.com")
    with pytest.raises(URLValidationError, match="embedded authentication credentials"):
        validate_url("https://admin@example.com/dashboard")


def test_normalization_default_ports():
    """Verify default ports are stripped during normalization."""
    norm_http = normalize_url("http://example.com:80/path")
    assert norm_http.normalized_url == "http://example.com/path"

    norm_https = normalize_url("https://example.com:443/login")
    assert norm_https.normalized_url == "https://example.com/login"


def test_normalization_fragment_removal():
    """Verify URL fragments are stripped."""
    norm = normalize_url("https://example.com/docs#section-1")
    assert norm.normalized_url == "https://example.com/docs"
    assert "#" not in norm.normalized_url


def test_query_redaction():
    """Verify query parameter values are masked to protect sensitive data."""
    redacted = redact_query_parameters("token=supersecret&session=12345&user=alice")
    assert "supersecret" not in redacted
    assert "12345" not in redacted
    assert "token=%5BREDACTED%5D" in redacted or "token=[REDACTED]" in redacted


def test_punycode_identification():
    """Verify IDNA domains and punycode are detected and converted."""
    norm = normalize_url("https://xn--e1afmkfd.xn--p1ai/")
    assert norm.has_punycode is True
    assert norm.hostname.startswith("xn--")

    # International characters normalized to IDNA
    norm_unicode = normalize_url("https://münchen.de/")
    assert norm_unicode.has_punycode is True
    assert norm_unicode.hostname == "xn--mnchen-3ya.de"
