"""Integration tests for Scan API endpoints."""

from unittest.mock import patch

from fastapi.testclient import TestClient


@patch("backend.app.orchestration.pipeline.analyze_dns")
@patch("backend.app.orchestration.pipeline.validate_tls")
def test_submit_valid_scan_success(mock_validate_tls, mock_analyze_dns, client: TestClient):
    """Verify POST /api/v1/scans creates, executes, and returns a completed scan."""
    mock_analyze_dns.return_value = (
        {
            "module": "dns_analysis",
            "domain": "example.com",
            "records": {"A": ["93.184.216.34"], "MX": []},
            "dns_status": "RESOLVED",
            "findings": [],
        },
        [],
        ["93.184.216.34"],
    )

    mock_validate_tls.return_value = (
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
    )

    payload = {"url": "https://example.com/test-path?ref=123"}
    response = client.post("/api/v1/scans", json=payload)

    assert response.status_code == 201
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "COMPLETED"
    assert data["target"] == "example.com"
    assert "threat_assessment" in data
    assert data["threat_assessment"]["classification"] == "LOW"
    assert "modules" in data
    assert "url_analysis" in data["modules"]
    assert "dns_analysis" in data["modules"]
    assert "tls_analysis" in data["modules"]

    # Verify retrieval by scan ID
    scan_id = data["scan_id"]
    get_response = client.get(f"/api/v1/scans/{scan_id}")
    assert get_response.status_code == 200
    retrieved = get_response.json()
    assert retrieved["scan_id"] == scan_id
    assert retrieved["target"] == "example.com"


def test_submit_invalid_url_rejected(client: TestClient):
    """Verify invalid URL returns 400 Bad Request."""
    response = client.post("/api/v1/scans", json={"url": "invalid-url-without-scheme"})
    assert response.status_code == 400
    assert "detail" in response.json()


def test_submit_unsupported_port_rejected(client: TestClient):
    """Verify unsupported port returns 400 Bad Request."""
    response = client.post("/api/v1/scans", json={"url": "http://example.com:8080"})
    assert response.status_code == 400
    assert "Port 8080 is not permitted" in response.json()["detail"]


def test_submit_ssrf_target_rejected(client: TestClient):
    """Verify submission of localhost or private IP is rejected by SSRF guard."""
    response_lh = client.post("/api/v1/scans", json={"url": "http://localhost/admin"})
    assert response_lh.status_code == 400
    assert "SSRF Security Violation" in response_lh.json()["detail"]

    response_priv = client.post("/api/v1/scans", json={"url": "http://192.168.1.1/setup"})
    assert response_priv.status_code == 400
    assert "SSRF Security Violation" in response_priv.json()["detail"]


def test_get_nonexistent_scan_returns_404(client: TestClient):
    """Verify querying an unknown scan ID returns 404."""
    response = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()
