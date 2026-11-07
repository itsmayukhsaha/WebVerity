"""Tests for URL feature extraction and deterministic rule evaluation."""

from backend.app.analyzers.url_analyzer.features import (
    calculate_entropy,
    count_subdomains,
    extract_url_features,
)
from backend.app.analyzers.url_analyzer.normalizer import normalize_url


def test_subdomain_counting():
    """Verify subdomain depth calculation."""
    assert count_subdomains("example.com") == 0
    assert count_subdomains("login.example.com") == 1
    assert count_subdomains("a.b.c.example.com") == 3
    assert count_subdomains("192.168.1.1") == 0


def test_calculate_entropy():
    """Verify Shannon entropy calculation."""
    # Low entropy for repetitive strings
    assert calculate_entropy("aaaaaaa") == 0.0
    # Higher entropy for random strings
    assert calculate_entropy("a1b2c3d4e5") > 3.0


def test_ip_based_url_feature_extraction():
    """Verify IP-based hostname detection generates appropriate features and findings."""
    norm = normalize_url("http://93.184.216.34/login")
    features, findings = extract_url_features(norm, "http://93.184.216.34/login")

    assert features["has_ip_hostname"] is True
    finding_ids = [f.id for f in findings]
    assert "URL_IP_HOST" in finding_ids


def test_punycode_feature_extraction():
    """Verify punycode generates URL_PUNYCODE finding."""
    norm = normalize_url("https://xn--pple-43d.com/")
    features, findings = extract_url_features(norm, "https://xn--pple-43d.com/")

    assert features["has_punycode"] is True
    finding_ids = [f.id for f in findings]
    assert "URL_PUNYCODE" in finding_ids


def test_suspicious_keywords_detection():
    """Verify sensitive keywords are detected without falsely jumping to phishing conclusion."""
    norm = normalize_url("https://example.com/account/login?confirm=true")
    features, findings = extract_url_features(
        norm, "https://example.com/account/login?confirm=true"
    )

    assert features["contains_suspicious_keywords"] is True
    assert "login" in features["matched_keywords"]
    assert "account" in features["matched_keywords"]
    assert "confirm" in features["matched_keywords"]
    finding_ids = [f.id for f in findings]
    assert "URL_SUSPICIOUS_KEYWORDS" in finding_ids


def test_at_symbol_detection():
    """Verify embedded @ in URL generates URL_AT_SYMBOL finding."""
    norm = normalize_url("https://example.com/redirect?to=target@evil.com")
    features, findings = extract_url_features(
        norm, "https://example.com/redirect?to=target@evil.com"
    )

    assert features["has_at_symbol"] is True
    finding_ids = [f.id for f in findings]
    assert "URL_AT_SYMBOL" in finding_ids


def test_excessive_length_detection():
    """Verify excessively long URLs generate URL_EXCESSIVE_LENGTH finding."""
    long_path = "a" * 150
    raw = f"https://example.com/{long_path}"
    norm = normalize_url(raw)
    features, findings = extract_url_features(norm, raw)

    assert features["url_length"] > 100
    finding_ids = [f.id for f in findings]
    assert "URL_EXCESSIVE_LENGTH" in finding_ids
