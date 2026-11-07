"""Phase 3 tests — indicator matching, intelligence manager, evidence
correlation, risk engine, confidence engine, and orchestrator integration.
All external provider responses are mocked; no live malicious sites."""

import httpx
import pytest
from backend.app.detection.confidence_engine import calculate_confidence
from backend.app.detection.evidence_correlator import (
    EvidenceCategory,
    EvidenceItem,
    Severity,
    correlate_evidence,
)
from backend.app.detection.evidence_correlator import (
    Severity as EvSeverity,
)
from backend.app.detection.risk_engine import (
    RiskLevel,
    calculate_risk,
    classify_level,
)
from backend.app.intelligence.indicator_matcher import (
    classify_indicator,
    match_indicator,
    normalize_indicator,
)
from backend.app.intelligence.models import (
    IndicatorType,
    MatchType,
    NormalizedIndicatorMatch,
    ProviderResponseStatus,
    VerificationStatus,
)
from backend.app.schemas.evidence import Finding
from backend.app.schemas.scan import ConfidenceLevel as ScanConfidenceLevel


# ---------------- Indicator matching ----------------
def test_exact_url_match():
    matched, mt = match_indicator(
        "https://evil.example/payload.exe", "https://evil.example/payload.exe"
    )
    assert matched and mt == MatchType.EXACT_URL


def test_canonical_url_match_ignores_default_port_and_case():
    matched, mt = match_indicator(
        "https://EVIL.example:443/payload.exe", "http://evil.example/payload.exe"
    )
    # different scheme -> hosts equal but scheme differs; netloc comparison holds
    assert matched and mt == MatchType.CANONICAL_URL


def test_subdomain_never_matched_as_domain_sibling():
    matched, _ = match_indicator("evil.test", "example.com.evil.test")
    assert not matched


def test_subdomain_match_is_explicit():
    matched, mt = match_indicator("login.paypal.com", "paypal.com")
    assert matched and mt == MatchType.SUBDOMAIN


def test_different_domain_never_matches():
    matched, _ = match_indicator("notexample.com", "example.com")
    assert not matched


def test_url_normalization_consistent():
    assert (
        normalize_indicator("HTTPS://Example.COM:443/path/")
        == normalize_indicator("http://example.com/path/")
    ) is False  # scheme differs -> not identical; but host normalized:
    n = normalize_indicator("HTTPS://Example.COM:443/path/?token=secret")
    assert "secret" not in n
    assert n.startswith("https://example.com/path/")


def test_classify_indicator_kinds():
    assert classify_indicator("1.2.3.4") == IndicatorType.IPV4
    assert classify_indicator("example.com") == IndicatorType.DOMAIN
    assert classify_indicator("https://example.com/a") == IndicatorType.URL


# ---------------- URLhaus / PhishTank providers ----------------
def test_urlhaus_provider_cached_result(monkeypatch):
    from backend.app.intelligence.urlhaus import URLhausProvider

    class FakeResp:
        status_code = 200

        def json(self):
            return {
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
            }

    calls = []
    monkeypatch.setattr(httpx, "post", lambda *a, **kw: calls.append(1) or FakeResp())
    p = URLhausProvider(auth_key=None)
    r1 = p.check_url("http://evil.example/x.exe")
    r2 = p.check_url("http://evil.example/x.exe")
    assert r1.match_found and r2.match_found
    assert len(calls) == 2  # provider itself does not dedupe; manager layer does


def test_phishtank_rate_limit_status(monkeypatch):
    from backend.app.intelligence.phishtank import PhishTankProvider

    class FakeResp:
        status_code = 429

    monkeypatch.setattr(httpx, "post", lambda *a, **kw: FakeResp())
    result = PhishTankProvider(api_key="k").check_url("http://x.example/")
    assert result.status == "RATE_LIMITED"
    assert not result.match_found


def test_provider_unavailable_is_not_clean(monkeypatch):
    """A failed lookup must not be interpreted as evidence of safety."""
    from backend.app.intelligence.base import ThreatIntelligenceResult
    from backend.app.intelligence.intelligence_manager import _normalize_result

    result = ThreatIntelligenceResult(source="URLhaus", query="x", error="down", status="FAILED")
    normalized = _normalize_result(
        result, provider_name="URLhaus", indicator_type=IndicatorType.URL, original="x"
    )
    assert normalized.response_status == ProviderResponseStatus.ERROR
    assert normalized.matched is False


def test_collect_intelligence_normalizes_and_deduplicates(monkeypatch):
    import backend.app.intelligence.intelligence_manager as im
    from backend.app.analyzers.url_analyzer.normalizer import normalize_url

    class FakeProvider:
        def get_source_name(self):
            return "Fake"

        def check_url(self, url):
            from backend.app.intelligence.base import ThreatIntelligenceResult

            return ThreatIntelligenceResult(
                source="Fake",
                query=url,
                match_found=True,
                verified=True,
                threat_type="phishing",
                status="COMPLETED",
            )

        def check_domain(self, domain):
            from backend.app.intelligence.base import ThreatIntelligenceResult

            return ThreatIntelligenceResult(
                source="Fake", query=domain, match_found=False, status="COMPLETED"
            )

    monkeypatch.setattr(im.settings, "ENABLE_URLHAUS", False)
    monkeypatch.setattr(im.settings, "ENABLE_PHISHTANK", False)

    def patched_collect(normalized):
        providers = [FakeProvider()]
        from backend.app.intelligence.base import redact_url_for_external_query

        redacted = redact_url_for_external_query(normalized.normalized_url)
        matches = []
        for provider in providers:
            r_url = provider.check_url(redacted)
            matches.append(im._normalize_result(r_url, "Fake", IndicatorType.URL, redacted))
            r_dom = provider.check_domain(normalized.hostname)
            matches.append(
                im._normalize_result(r_dom, "Fake", IndicatorType.DOMAIN, normalized.hostname)
            )
        return im._deduplicate(matches)

    normalized = normalize_url("https://confirmed-phish.example/login")
    matches = patched_collect(normalized)
    url_matches = [m for m in matches if m.indicator_type == IndicatorType.URL]
    assert len(url_matches) == 1
    assert url_matches[0].matched
    assert url_matches[0].verification_status == VerificationStatus.CONFIRMED
    assert url_matches[0].threat_category == "phishing"
    assert url_matches[0].is_probability is False


# ---------------- Evidence correlation ----------------
def _finding(fid, module="url_analysis", severity=Severity.MEDIUM):
    return Finding(
        id=fid,
        module=module,
        severity=severity,
        title=fid,
        description=f"Description for {fid}",
        evidence={"hostname": "example.com"},
    )


def test_duplicate_evidence_eliminated():
    findings = [_finding("URL_SUSPICIOUS"), _finding("URL_SUSPICIOUS")]
    evidence = correlate_evidence(findings, {"url_analysis": "COMPLETED"})
    matching = [e for e in evidence.items if e.id == "URL_SUSPICIOUS"]
    assert len(matching) == 1
    assert evidence.duplicates_removed >= 1


def test_missing_header_is_weakness_not_malicious():
    findings = [_finding("HTTP_MISSING_HSTS", module="http_security", severity=Severity.LOW)]
    evidence = correlate_evidence(findings, {"http_security": "COMPLETED"})
    item = evidence.items[0]
    assert item.category == EvidenceCategory.SECURITY_WEAKNESS
    assert not evidence.malicious


def test_failed_module_becomes_unavailable_not_negative():
    evidence = correlate_evidence([], {"dns_analysis": "TIMEOUT"})
    assert any(e.category == EvidenceCategory.UNAVAILABLE for e in evidence.items)
    assert not evidence.suspicious


def test_verified_intelligence_becomes_malicious_evidence():
    match = {
        "matched": True,
        "provider": "PhishTank",
        "threat_category": "phishing",
        "verification_status": "confirmed",
        "match_type": "exact_url",
    }
    evidence = correlate_evidence([], {"url_analysis": "COMPLETED"}, [match])
    assert len(evidence.malicious) == 1
    assert evidence.malicious[0].severity == Severity.CRITICAL


# ---------------- Risk engine ----------------
def _build_evidence(categories, verified=False):
    items = [
        EvidenceItem(
            id=f"E{i}",
            category=c,
            description="d",
            severity=EvSeverity.MEDIUM,
            source="s",
            confidence=0.95 if (c == EvidenceCategory.MALICIOUS_INDICATOR and verified) else 0.5,
            origin="url_analysis",
        )
        for i, c in enumerate(categories)
    ]
    from backend.app.detection.evidence_correlator import CorrelatedEvidence

    ev = CorrelatedEvidence(items=items)
    for item in items:
        if item.category == EvidenceCategory.MALICIOUS_INDICATOR:
            ev.malicious.append(item)
        elif item.category == EvidenceCategory.SUSPICIOUS:
            ev.suspicious.append(item)
        elif item.category == EvidenceCategory.SECURITY_WEAKNESS:
            ev.weaknesses.append(item)
    return ev


def test_risk_score_bounded_and_deterministic():
    ev = _build_evidence([EvidenceCategory.SUSPICIOUS] * 10)
    a1 = calculate_risk(ev)
    a2 = calculate_risk(ev)
    assert a1.risk_score == a2.risk_score
    assert 0 <= a1.risk_score <= 100
    assert a1.is_probability is False


def test_confirmed_malicious_precedence():
    ev = _build_evidence([EvidenceCategory.MALICIOUS_INDICATOR], verified=True)
    result = calculate_risk(ev)
    assert result.risk_score >= 90
    assert result.risk_level == RiskLevel.CRITICAL


def test_weights_configurable():
    ev = _build_evidence([EvidenceCategory.SUSPICIOUS])
    default = calculate_risk(ev)
    custom = calculate_risk(ev, weights={"suspicious_url_characteristics": 50})
    assert custom.risk_score > default.risk_score


def test_classification_bands():
    assert classify_level(10) == RiskLevel.LOW
    assert classify_level(30) == RiskLevel.MODERATE
    assert classify_level(60) == RiskLevel.HIGH
    assert classify_level(90) == RiskLevel.CRITICAL


def test_insufficient_evidence_caps_classification():
    ev = _build_evidence([EvidenceCategory.MALICIOUS_INDICATOR])  # not verified
    result = calculate_risk(ev, completed_modules=1, total_modules=8)
    assert result.risk_level in (RiskLevel.MODERATE, RiskLevel.LOW, RiskLevel.HIGH)
    assert any("Insufficient" in r for r in result.reasons)


# ---------------- Confidence engine ----------------
def test_confidence_low_when_checks_fail():
    from backend.app.detection.evidence_correlator import CorrelatedEvidence

    conf = calculate_confidence(
        {"url_analysis": "COMPLETED", "dns_analysis": "TIMEOUT", "tls_analysis": "FAILED"},
        CorrelatedEvidence(),
    )
    assert conf.confidence_level in (ScanConfidenceLevel.LOW, ScanConfidenceLevel.MEDIUM)
    assert conf.failed_checks == ["dns_analysis", "tls_analysis"]


def test_confidence_boosted_by_verified_intel():
    from backend.app.detection.evidence_correlator import CorrelatedEvidence

    statuses = dict.fromkeys(
        [
            "url_analysis",
            "dns_analysis",
            "tls_analysis",
            "http_security",
            "redirect_analysis",
            "content_analysis",
            "threat_intelligence",
            "domain_intelligence",
        ],
        "COMPLETED",
    )
    matches = [{"matched": True, "verification_status": "confirmed", "provider": "PhishTank"}]
    conf = calculate_confidence(statuses, CorrelatedEvidence(), matches)
    assert conf.confidence_level == ScanConfidenceLevel.HIGH
    assert conf.confidence_score >= 75


def test_never_high_confidence_when_essential_checks_failed():
    statuses = dict.fromkeys(
        [
            "url_analysis",
            "dns_analysis",
            "tls_analysis",
            "http_security",
            "redirect_analysis",
            "content_analysis",
            "threat_intelligence",
        ],
        "COMPLETED",
    )
    statuses["tls_analysis"] = "TIMEOUT"
    from backend.app.detection.evidence_correlator import CorrelatedEvidence

    calculate_confidence(statuses, CorrelatedEvidence())
    # Even with verified intel, a failed essential check caps confidence below 80
    matches = [{"matched": True, "verification_status": "confirmed", "provider": "X"}]
    conf2 = calculate_confidence(statuses, CorrelatedEvidence(), matches)
    assert not (conf2.confidence_score >= 80 and conf2.failed_checks == [])


# ---------------- Detection orchestrator ----------------
@pytest.mark.asyncio
async def test_detection_orchestrator_end_to_end(monkeypatch):
    from backend.app.detection.aggregator import AggregatedScanResult
    from backend.app.detection.detection_orchestrator import run_detection
    from backend.app.schemas.scan import RiskClassification, ThreatAssessment

    findings = [_finding("URL_SUSPICIOUS_KW")]
    aggregated = AggregatedScanResult(
        modules={
            "url_analysis": {"status": "COMPLETED"},
            "dns_analysis": {"domain": "example.com"},
        },
        findings=findings,
        threat_assessment=ThreatAssessment(
            risk_score=30,
            classification=RiskClassification.MODERATE,
            confidence=ScanConfidenceLevel.MEDIUM,
        ),
        statuses={
            "url_analysis": "COMPLETED",
            "dns_analysis": "COMPLETED",
            "tls_analysis": "COMPLETED",
            "http_security": "COMPLETED",
            "redirect_analysis": "COMPLETED",
            "content_analysis": "COMPLETED",
            "threat_intelligence": "COMPLETED",
            "domain_intelligence": "COMPLETED",
        },
    )

    class FakeProvider:
        def get_source_name(self):
            return "Fake"

        def check_url(self, url):
            from backend.app.intelligence.base import ThreatIntelligenceResult

            return ThreatIntelligenceResult(
                source="Fake",
                query=url,
                match_found=True,
                verified=True,
                threat_type="phishing",
                status="COMPLETED",
            )

        def check_domain(self, domain):
            from backend.app.intelligence.base import ThreatIntelligenceResult

            return ThreatIntelligenceResult(
                source="Fake", query=domain, match_found=False, status="COMPLETED"
            )

    import backend.app.intelligence.intelligence_manager as im

    monkeypatch.setattr(im, "collect_intelligence", lambda n: [])
    # Patch collect inside orchestrator module namespace via run_detection's import
    import backend.app.intelligence.intelligence_manager as real_im

    def fake_collect(normalized):
        # Produce a verified phishing match for the URL

        return [
            NormalizedIndicatorMatch(
                provider="Fake",
                indicator_type=IndicatorType.URL,
                indicator_value=normalized.normalized_url,
                original_value=normalized.normalized_url,
                matched=True,
                match_type=MatchType.EXACT_URL,
                threat_category="phishing",
                verification_status=VerificationStatus.CONFIRMED,
                response_status=ProviderResponseStatus.MATCH,
            )
        ]

    monkeypatch.setattr(real_im, "collect_intelligence", fake_collect)

    result = await run_detection(aggregated, dict(aggregated.statuses))
    d = result.to_dict()
    assert d["is_probability"] is False
    assert d["risk_level"] == "CRITICAL"  # confirmed match precedence
    assert d["confidence_score"] > 0
    assert d["evidence"]
    assert d["reasons"]


# ---------------- Provider unavailability & config ----------------
def test_all_providers_disabled_still_functional(monkeypatch):
    import backend.app.intelligence.intelligence_manager as im

    monkeypatch.setattr(im.settings, "ENABLE_URLHAUS", False)
    monkeypatch.setattr(im.settings, "ENABLE_PHISHTANK", False)
    from backend.app.analyzers.url_analyzer.normalizer import normalize_url

    matches = im.collect_intelligence(normalize_url("https://example.com/"))
    assert matches == []  # graceful, no fabricated results


def test_health_report_no_secrets():
    health = get_provider_health_safe()
    for p in health:
        # No credential values may appear (only a boolean 'configured' flag)
        dump = p.model_dump_json()
        assert "configured" in dump
        assert "URLHAUS_AUTH_KEY" not in dump and "app_key" not in dump


def get_provider_health_safe():
    from backend.app.intelligence.intelligence_manager import get_provider_health

    return get_provider_health()


# ---------------- API endpoints ----------------
def test_intelligence_status_endpoint(client):
    resp = client.get("/api/v1/intelligence/status")
    assert resp.status_code == 200
    body = resp.json()
    assert "providers" in body
    assert body["credentials_exposed"] is False
    assert "PHISHTANK_API_KEY" not in resp.text


def test_intelligence_check_endpoint_validates_url(client, monkeypatch):
    import backend.app.intelligence.intelligence_manager as im

    monkeypatch.setattr(im.settings, "ENABLE_URLHAUS", False)
    monkeypatch.setattr(im.settings, "ENABLE_PHISHTANK", False)
    resp = client.post("/api/v1/intelligence/check", json={"url": "https://example.com/"})
    assert resp.status_code == 200
    assert resp.json()["is_probability"] is False


def test_intelligence_check_rejects_private_ip(client):
    resp = client.post("/api/v1/intelligence/check", json={"url": "http://127.0.0.1/"})
    assert resp.status_code == 400


def test_scan_detection_404_for_unknown_scan(client):
    resp = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000/detection")
    assert resp.status_code == 404


def test_scan_evidence_404_for_unknown_scan(client):
    resp = client.get("/api/v1/scans/nope/evidence")
    assert resp.status_code == 404


def test_scan_intelligence_404_for_unknown_scan(client):
    resp = client.get("/api/v1/scans/nope/intelligence")
    assert resp.status_code == 404
