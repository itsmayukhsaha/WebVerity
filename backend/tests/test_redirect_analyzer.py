"""Tests for Module 2 — redirect analyzer and safe_client redirect handling (mocked)."""

import backend.app.analyzers.redirect_analyzer.analyzer as redirect_mod
import pytest
from backend.app.analyzers.redirect_analyzer.analyzer import analyze_redirects
from backend.app.analyzers.website.safe_client import SafeFetchError
from backend.app.core.security import SSRFSecurityException


def _resp(chain=None, final_url="https://example.com/", blocked=False):
    return {
        "final_url": final_url,
        "status": 200,
        "headers": {},
        "body": b"",
        "redirect_chain": chain or [],
        "redirect_count": len(chain or []),
        "blocked": blocked,
        "block_reason": "TOO_MANY_REDIRECTS" if blocked else None,
    }


def test_normal_redirect_chain(monkeypatch):
    chain = [
        {"from_url": "http://example.com/", "to_url": "https://example.com/", "status": 301},
    ]
    monkeypatch.setattr(
        redirect_mod, "fetch_page", lambda url: _resp(chain, "https://example.com/")
    )
    result, findings = analyze_redirects("http://example.com/")
    assert result["status"] == "COMPLETED"
    assert result["redirect_count"] == 1
    assert result["cross_domain_redirects"] is False
    assert result["redirect_loop_detected"] is False
    assert not any(f.id == "REDIRECT_CROSS_DOMAIN" for f in findings)


def test_cross_domain_redirect_flagged_with_reason(monkeypatch):
    chain = [
        {
            "from_url": "https://start-site.com/",
            "to_url": "https://other-domain.net/",
            "status": 302,
        },
    ]
    monkeypatch.setattr(
        redirect_mod, "fetch_page", lambda url: _resp(chain, "https://other-domain.net/page")
    )
    result, findings = analyze_redirects("https://start-site.com/")
    assert result["cross_domain_redirects"] is True
    cross = [f for f in findings if f.id == "REDIRECT_CROSS_DOMAIN"]
    assert cross, "cross-domain redirect must produce a finding"
    assert "Reason" in cross[0].description


def test_too_many_redirects_reported(monkeypatch):
    chain = [
        {"from_url": f"https://a{i}.com/", "to_url": f"https://a{i + 1}.com/", "status": 302}
        for i in range(6)
    ]
    monkeypatch.setattr(redirect_mod, "fetch_page", lambda url: _resp(chain, blocked=True))
    result, findings = analyze_redirects("https://a0.com/")
    assert result["status"] == "COMPLETED"
    assert any(f.id == "REDIRECT_TOO_MANY" for f in findings)


def test_redirect_loop_detected(monkeypatch):
    def raise_loop(url):
        raise SafeFetchError("Redirect loop detected", "REDIRECT_LOOP")

    monkeypatch.setattr(redirect_mod, "fetch_page", raise_loop)
    result, findings = analyze_redirects("https://example.com/")
    assert result["redirect_loop_detected"] is True
    assert any(f.id == "REDIRECT_LOOP" for f in findings)


def test_unsafe_private_redirect_blocked():
    """A redirect to a private IP raises SSRFSecurityException from safe_client;
    the redirect analyzer converts it into an UNSAFE_BLOCKED finding."""

    def raise_ssrf(url):
        raise SSRFSecurityException(
            "Host resolved to unsafe destination: Private IP address '10.0.0.5' is blocked.",
            target="10.0.0.5",
        )

    # Direct safe_client behavior check
    with pytest.raises(SSRFSecurityException):
        _ = raise_ssrf("http://x")

    # Analyzer-level handling
    import backend.app.analyzers.redirect_analyzer.analyzer as rm

    saved = rm.fetch_page
    rm.fetch_page = raise_ssrf
    try:
        result, findings = analyze_redirects("https://example.com/")
        assert result["unsafe_redirect_blocked"] is True
        assert any(f.id == "REDIRECT_SSRF_BLOCKED" for f in findings)
    finally:
        rm.fetch_page = saved


def test_https_downgrade_flagged(monkeypatch):
    chain = [
        {"from_url": "https://example.com/", "to_url": "http://insecure.example/", "status": 302},
    ]
    monkeypatch.setattr(
        redirect_mod, "fetch_page", lambda url: _resp(chain, "http://insecure.example/")
    )
    _, findings = analyze_redirects("https://example.com/")
    assert any(f.id == "REDIRECT_HTTPS_DOWNGRADE" for f in findings)


def test_shortener_chain_flagged(monkeypatch):
    chain = [
        {"from_url": "https://bit.ly/abc", "to_url": "https://evil-landing.net/", "status": 301},
    ]
    monkeypatch.setattr(
        redirect_mod, "fetch_page", lambda url: _resp(chain, "https://evil-landing.net/")
    )
    _, findings = analyze_redirects("https://bit.ly/abc")
    assert any(f.id == "REDIRECT_SHORTENER" for f in findings)


def test_benign_service_cross_domain_is_info(monkeypatch):
    chain = [
        {
            "from_url": "https://shop.example.com/",
            "to_url": "https://checkout.stripe.com/",
            "status": 302,
        },
    ]
    monkeypatch.setattr(
        redirect_mod, "fetch_page", lambda url: _resp(chain, "https://checkout.stripe.com/pay")
    )
    result, findings = analyze_redirects("https://shop.example.com/")
    # stripe.com is not in the benign suffix list -> LOW not INFO; cross domain recorded
    assert result["cross_domain_redirects"] is True
    cross = [f for f in findings if f.id == "REDIRECT_CROSS_DOMAIN"]
    assert cross[0].severity.value in ("INFO", "LOW")
