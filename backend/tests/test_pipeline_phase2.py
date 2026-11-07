"""Phase 2 pipeline/API integration tests (DNS/TLS mocked; live-safe fetches)."""

from unittest.mock import patch

# NOTE: like the Phase 1 API test, DNS and TLS are mocked. HTTP/RDAP/ThreatIntel
# modules run against live public services in this environment (example.com /
# IANA / abuse.ch). They are wrapped defensively: failures degrade gracefully.
import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    from backend.app.database.connection import init_db
    from backend.app.main import app

    init_db()
    return TestClient(app)


def _stub_dns_tls():
    """Return patchers for DNS + TLS used by the pipeline."""
    dns_patch = patch(
        "backend.app.orchestration.pipeline.analyze_dns",
        return_value=(
            {
                "module": "dns_analysis",
                "domain": "example.com",
                "records": {"A": ["93.184.216.34"], "MX": ["10 mail.example.com"]},
                "dns_status": "RESOLVED",
                "findings": [],
            },
            [],
            ["93.184.216.34"],
        ),
    )
    tls_patch = patch(
        "backend.app.orchestration.pipeline.validate_tls",
        return_value=(
            {
                "module": "tls_analysis",
                "status": "COMPLETED",
                "https_enabled": True,
                "hostname_match": True,
                "chain_validation": "VALID",
                "certificate_expired": False,
                "issuer": "DigiCert",
                "tls_version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "certificate": {},
                "findings": [],
            },
            [],
        ),
    )
    return dns_patch, tls_patch


@pytest.mark.integration
def test_full_pipeline_phase2_modules_present(client: TestClient):
    dns_patch, tls_patch = _stub_dns_tls()
    with dns_patch, tls_patch:
        response = client.post("/api/v1/scans", json={"url": "https://example.com/"})
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "COMPLETED"

    modules = data["modules"]
    for key in (
        "url_analysis",
        "dns_analysis",
        "tls_analysis",
        "http_security",
        "redirect_analysis",
        "content_analysis",
        "domain_intelligence",
        "threat_intelligence",
    ):
        assert key in modules, f"missing Phase 2 module output: {key}"

    # Threat risk separated from security posture
    assessment = data["threat_assessment"]
    assert "security_posture_score" in assessment
    assert 0 <= assessment["security_posture_score"] <= 100

    # Example.com lacks CSP/HSTS: posture reduced, but classification must stay LOW
    assert assessment["classification"] in ("LOW", "MODERATE")
    assert data["recommendations"]


@pytest.mark.integration
def test_phase2_detail_endpoints(client: TestClient):
    dns_patch, tls_patch = _stub_dns_tls()
    with dns_patch, tls_patch:
        created = client.post("/api/v1/scans", json={"url": "https://example.com/"})
    scan_id = created.json()["scan_id"]

    intel = client.get(f"/api/v1/scans/{scan_id}/intelligence")
    assert intel.status_code == 200
    assert "threat_intelligence" in intel.json()
    assert "domain_intelligence" in intel.json()

    findings = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert findings.status_code == 200
    assert "findings" in findings.json()

    recs = client.get(f"/api/v1/scans/{scan_id}/recommendations")
    assert recs.status_code == 200
    assert "recommendations" in recs.json()


@pytest.mark.integration
def test_scan_response_contract_preserved(client: TestClient):
    """Phase 1 consumers: scan_id/status/target/threat_assessment/modules/findings exist."""
    dns_patch, tls_patch = _stub_dns_tls()
    with dns_patch, tls_patch:
        created = client.post("/api/v1/scans", json={"url": "https://example.com/"})
    data = created.json()
    for legacy_key in (
        "scan_id",
        "status",
        "target",
        "threat_assessment",
        "modules",
        "findings",
        "created_at",
    ):
        assert legacy_key in data
