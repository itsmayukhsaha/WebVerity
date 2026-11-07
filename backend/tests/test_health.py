"""Tests for API health check endpoint."""

from fastapi.testclient import TestClient


def test_health_check_endpoint(client: TestClient):
    """Test GET /api/v1/health returns healthy operational status."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "WebVerity"
    assert "version" in data
    assert "environment" in data
