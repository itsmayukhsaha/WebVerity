"""Tests for Module 4 — threat intelligence providers (HTTP fully mocked)."""

import httpx
from backend.app.intelligence.base import ProviderStatus
from backend.app.intelligence.phishtank import PhishTankProvider
from backend.app.intelligence.urlhaus import URLhausProvider


def test_urlhaus_positive_match(monkeypatch):
    class FakeResp:
        status_code = 200

        def json(self):
            return {
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
                "last_online": "2026-11-01",
                "date_added": "2026-11-01",
            }

    monkeypatch.setattr(httpx, "post", lambda *a, **kw: FakeResp())
    provider = URLhausProvider(auth_key="test-key")
    result = provider.check_url("http://evil.example/payload.exe")
    assert result.match_found is True
    assert result.verified is True
    assert result.threat_type == "malware_download"
    assert result.confidence == "HIGH"
    assert result.error is None


def test_urlhaus_no_match(monkeypatch):
    class FakeResp:
        status_code = 200

        def json(self):
            return {"query_status": "no_results"}

    monkeypatch.setattr(httpx, "post", lambda *a, **kw: FakeResp())
    result = URLhausProvider(auth_key=None).check_domain("clean-example.org")
    assert result.match_found is False
    assert result.error is None


def test_urlhaus_invalid_api_key(monkeypatch):
    class FakeResp:
        status_code = 401

        def json(self):
            return {}

    monkeypatch.setattr(httpx, "post", lambda *a, **kw: FakeResp())
    result = URLhausProvider(auth_key="bad-key").check_url("http://x.example/")
    assert result.match_found is False
    assert "credentials" in (result.error or "").lower()


def test_urlhaus_timeout(monkeypatch):
    def raise_timeout(*a, **kw):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr(httpx, "post", raise_timeout)
    result = URLhausProvider().check_url("http://x.example/")
    assert result.status == "TIMEOUT"
    assert result.match_found is False


def test_urlhaus_rate_limited(monkeypatch):
    class FakeResp:
        status_code = 429

    monkeypatch.setattr(httpx, "post", lambda *a, **kw: FakeResp())
    result = URLhausProvider().check_url("http://x.example/")
    assert result.status == "RATE_LIMITED"
    assert result.match_found is False


def test_urlhaus_invalid_json(monkeypatch):
    class FakeResp:
        status_code = 200

        def json(self):
            raise ValueError("not json")

    monkeypatch.setattr(httpx, "post", lambda *a, **kw: FakeResp())
    result = URLhausProvider().check_url("http://x.example/")
    assert "invalid JSON" in (result.error or "")


def test_urlhaus_query_is_redacted():
    from backend.app.intelligence.base import redact_url_for_external_query

    redacted = redact_url_for_external_query("https://site.example/login?token=SECRET123")
    assert "SECRET123" not in redacted
    assert redacted.startswith("https://site.example/login")


def test_phishtank_unavailable_without_key():
    provider = PhishTankProvider(api_key=None)
    assert provider.get_provider_status() == ProviderStatus.UNAVAILABLE
    result = provider.check_url("http://x.example/")
    assert result.status == "SKIPPED"
    assert result.match_found is False


def test_phishtank_verified_phishing(monkeypatch):
    class FakeResp:
        status_code = 200

        def json(self):
            return {
                "results": {
                    "in_database": True,
                    "verified": True,
                    "valid": True,
                    "verified_at": "2026-11-01T00:00:00Z",
                }
            }

    monkeypatch.setattr(httpx, "post", lambda *a, **kw: FakeResp())
    result = PhishTankProvider(api_key="k").check_url("http://phish.example/")
    assert result.match_found is True
    assert result.verified is True
    assert result.threat_type == "phishing"


def test_phishtank_unverified_report_not_treated_as_verified(monkeypatch):
    class FakeResp:
        status_code = 200

        def json(self):
            return {"results": {"in_database": True, "verified": False, "valid": False}}

    monkeypatch.setattr(httpx, "post", lambda *a, **kw: FakeResp())
    result = PhishTankProvider(api_key="k").check_url("http://phish.example/")
    assert result.match_found is True
    assert result.verified is False


def test_provider_failure_never_crashes(monkeypatch):
    """check_threat_intelligence isolates provider exceptions."""
    import backend.app.intelligence as ti_mod

    class ExplodingProvider:
        def get_source_name(self):
            return "Exploding"

        def get_provider_status(self):
            return ProviderStatus.AVAILABLE

        def check_url(self, url):
            raise RuntimeError("boom")

        def check_domain(self, domain):
            raise RuntimeError("boom")

    class NormalProvider(URLhausProvider):
        def get_source_name(self):
            return "Normal"

    monkeypatch.setattr(
        ti_mod,
        "get_configured_providers",
        lambda: [ExplodingProvider(), NormalProvider(auth_key=None)],
    )
    monkeypatch.setattr(
        httpx, "post", lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError("down"))
    )

    from backend.app.analyzers.url_analyzer.normalizer import normalize_url

    normalized = normalize_url("https://example.com/")
    module_result, findings = ti_mod.check_threat_intelligence(normalized)
    # Contains an error result for the exploding provider; scan did not crash
    statuses = [r["status"] for r in module_result["results"]]
    assert "FAILED" in statuses
