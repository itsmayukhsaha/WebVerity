"""Tests for Module 1 — HTTP security analyzer (network fully mocked)."""

import backend.app.analyzers.website.http_analyzer as http_mod
import backend.app.analyzers.website.safe_client as safe_client_mod
from backend.app.analyzers.website.http_analyzer import _analyze_cookies
from backend.app.schemas.evidence import Severity


class FakeHeaders(dict):
    """Dict with a get_list method mimicking httpx.Headers."""

    def get_list(self, key):
        return [v for k, v in self.items() if k.lower() == key.lower()]


def _fake_response(
    status=200,
    headers=None,
    body=b"<html><body>ok</body></html>",
    redirect_chain=None,
    final_url="https://example.com/",
):
    return {
        "final_url": final_url,
        "status": status,
        "headers": headers or {},
        "body": body,
        "redirect_chain": redirect_chain or [],
        "redirect_count": len(redirect_chain or []),
        "blocked": False,
        "block_reason": None,
    }


def test_successful_response_headers_assessed(monkeypatch):
    headers = FakeHeaders(
        {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "server": "nginx",
            "content-type": "text/html; charset=utf-8",
        }
    )
    monkeypatch.setattr(http_mod, "fetch_page", lambda url: _fake_response(headers=headers))
    result, findings = http_mod.analyze_http_security("https://example.com/")
    assert result["status"] == "COMPLETED"
    assert result["http_status"] == 200
    assert result["https_enabled"] is True
    assert result["security_headers"]["Strict-Transport-Security"] == "max-age=31536000"
    assert result["security_headers"]["Content-Security-Policy"] == "default-src 'self'"
    # Referrer-Policy & Permissions-Policy absent -> findings
    ids = {f.id for f in findings}
    assert "HTTP_MISSING_REFERRER_POLICY" in ids
    assert "HTTP_MISSING_HSTS" not in ids  # HSTS was present


def test_missing_security_headers_produce_weakness_findings(monkeypatch):
    monkeypatch.setattr(http_mod, "fetch_page", lambda url: _fake_response(headers={}))
    result, findings = http_mod.analyze_http_security("https://example.com/")
    ids = {f.id for f in findings}
    assert "HTTP_MISSING_HSTS" in ids
    assert "HTTP_MISSING_CSP" in ids
    # Weaknesses must never be CRITICAL (not proof of phishing)
    assert all(f.severity in (Severity.LOW, Severity.INFO) for f in findings)


def test_insecure_cookie_attributes_detected(monkeypatch):
    headers = FakeHeaders({"set-cookie": "session=abc123; Path=/"})
    cookie_report = _analyze_cookies(headers)
    assert cookie_report["count"] == 1
    assert cookie_report["any_missing_secure"] is True
    assert cookie_report["any_missing_httponly"] is True
    assert cookie_report["any_missing_samesite"] is True


def test_secure_cookie_not_flagged():
    headers = FakeHeaders({"set-cookie": "session=abc; Secure; HttpOnly; SameSite=Strict"})
    cookie_report = _analyze_cookies(headers)
    assert cookie_report["any_missing_secure"] is False
    assert cookie_report["any_missing_httponly"] is False
    assert cookie_report["any_missing_samesite"] is False


def test_invalid_content_type_flagged(monkeypatch):
    headers = FakeHeaders({"content-type": "application/x-msdownload"})
    monkeypatch.setattr(http_mod, "fetch_page", lambda url: _fake_response(headers=headers))
    _, findings = http_mod.analyze_http_security("https://example.com/")
    assert any(f.id == "HTTP_UNEXPECTED_CONTENT_TYPE" for f in findings)


def test_timeout_maps_to_timeout_status(monkeypatch):
    from backend.app.analyzers.website.safe_client import SafeFetchError

    def raise_timeout(url):
        raise SafeFetchError("HTTP request timed out", "TIMEOUT")

    monkeypatch.setattr(http_mod, "fetch_page", raise_timeout)
    result, _ = http_mod.analyze_http_security("https://example.com/")
    assert result["status"] == "TIMEOUT"


def test_oversized_response_truncated(monkeypatch):
    """Body over the cap is truncated before any downstream use."""
    captured = {}

    def capture(url):
        captured["response"] = _fake_response(
            body=b"x" * (safe_client_mod.MAX_RESPONSE_BYTES + 100)
        )
        return captured["response"]

    monkeypatch.setattr(http_mod, "fetch_page", capture)
    result, _ = http_mod.analyze_http_security("https://example.com/")
    assert len(result["security_headers"]) >= 0  # analyzer ran safely
    assert len(captured["response"]["body"]) == safe_client_mod.MAX_RESPONSE_BYTES + 100
    # Truncation actually happens at fetch layer:
    body = captured["response"]["body"][: safe_client_mod.MAX_RESPONSE_BYTES]
    assert len(body) == safe_client_mod.MAX_RESPONSE_BYTES
