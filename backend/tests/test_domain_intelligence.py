"""Tests for Module 5 — RDAP domain registration intelligence (HTTP mocked)."""

import json

import backend.app.analyzers.domain_intelligence.analyzer as rdap_mod
import httpx
from backend.app.analyzers.domain_intelligence.analyzer import analyze_domain_registration

SAMPLE_RDAP_RESPONSE = {
    "objectClassName": "domain",
    "handle": "EXAMPLE-COM",
    "status": ["client transfer prohibited"],
    "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}, {"ldhName": "NS2.EXAMPLE.COM"}],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]],
            ],
        }
    ],
}


def _patch_http(monkeypatch, status_code=200, payload=None, raise_exc=None):
    class FakeResp:
        def __init__(self):
            self.status_code = status_code
            self.content = json.dumps(payload or {}).encode()

    def fake_get(url, timeout=None, follow_redirects=False):
        if raise_exc:
            raise raise_exc
        return FakeResp()

    monkeypatch.setattr(httpx, "get", fake_get)
    # Always stub the IANA bootstrap lookup to keep tests offline.
    monkeypatch.setattr(
        rdap_mod, "_bootstrap_rdap_server", lambda tld: "https://rdap.example.org/v1"
    )


def test_valid_registration_data(monkeypatch):
    _patch_http(monkeypatch, payload=SAMPLE_RDAP_RESPONSE)
    result, findings = analyze_domain_registration("example.com")
    assert result["status"] == "COMPLETED"
    assert result["registrar"] is not None
    assert result["domain_age_days"] is not None
    assert result["domain_age_days"] > 10000  # registered 1995
    assert "ns1.example.com" in result["nameservers"]
    assert not any(f.id == "RDAP_NEW_DOMAIN" for f in findings)


def test_recent_domain_flagged(monkeypatch):
    from datetime import UTC, datetime, timedelta

    recent = dict(SAMPLE_RDAP_RESPONSE)
    recent["events"] = [
        {
            "eventAction": "registration",
            "eventDate": (datetime.now(UTC) - timedelta(days=3)).isoformat().replace("+00:00", "Z"),
        },
        {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
    ]
    _patch_http(monkeypatch, payload=recent)
    result, findings = analyze_domain_registration("freshsite.com")
    assert any(f.id == "RDAP_NEW_DOMAIN" for f in findings)
    assert result["domain_age_days"] <= 30


def test_missing_registration_data(monkeypatch):
    _patch_http(monkeypatch, payload={"objectClassName": "domain"})
    result, findings = analyze_domain_registration("opaque.com")
    assert result["status"] == "COMPLETED"
    assert result["registrar"] is None
    assert result["domain_age_days"] is None


def test_unsupported_tld(monkeypatch):
    # No RDAP server resolves for the TLD -> honest UNAVAILABLE.
    monkeypatch.setattr(rdap_mod, "_bootstrap_rdap_server", lambda tld: None)
    result, _ = analyze_domain_registration("example.nonexistenttld")
    assert result["status"] == "UNAVAILABLE"


def test_rdap_timeout(monkeypatch):
    _patch_http(monkeypatch, raise_exc=httpx.TimeoutException("timed out"))
    result, _ = analyze_domain_registration("slow-example.com")
    assert result["status"] == "TIMEOUT"


def test_domain_not_found(monkeypatch):
    class FakeResp:
        status_code = 404
        content = b"{}"

    monkeypatch.setattr(httpx, "get", lambda *a, **kw: FakeResp())
    monkeypatch.setattr(
        rdap_mod, "_bootstrap_rdap_server", lambda tld: "https://rdap.example.org/v1"
    )
    result, findings = analyze_domain_registration("unregistered-xyz.com")
    assert result["status"] == "COMPLETED"
    assert any(f.id == "RDAP_DOMAIN_NOT_FOUND" for f in findings)


def test_rate_limited(monkeypatch):
    class FakeResp:
        status_code = 429
        content = b"{}"

    monkeypatch.setattr(httpx, "get", lambda *a, **kw: FakeResp())
    monkeypatch.setattr(
        rdap_mod, "_bootstrap_rdap_server", lambda tld: "https://rdap.example.org/v1"
    )
    result, _ = analyze_domain_registration("limited.com")
    assert result["status"] == "RATE_LIMITED"
