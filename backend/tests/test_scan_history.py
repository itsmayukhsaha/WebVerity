"""Tests for the scan-history listing endpoint (frontend integration)."""

import pytest
from backend.app.models.scan import Scan
from sqlalchemy import delete


@pytest.fixture(autouse=True)
def clean_scans(db_session):
    """Ensure a deterministic scan table.

    The shared in-memory test database is committed to by the scan pipeline,
    so rows persist across tests; clear before each history test.
    """
    db_session.execute(delete(Scan))
    db_session.commit()


def _persist_scan(db_session, scan_id, domain, risk_level, risk_score, status="COMPLETED"):
    from datetime import UTC, datetime

    from backend.app.models.scan import Scan

    scan = Scan(
        id=scan_id,
        submitted_url_redacted=f"https://{domain}",
        normalized_url=f"https://{domain}",
        domain=domain,
        status=status,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence="MEDIUM",
        security_posture_score=80,
        results_json={},
        created_at=datetime.now(UTC),
        completed_at=datetime.now(UTC) if status == "COMPLETED" else None,
    )
    db_session.add(scan)
    db_session.commit()


def test_list_scans_empty(client):
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 0
    assert body["scans"] == []


def test_list_scans_filters(client, db_session):
    _persist_scan(db_session, "11111111-1111-1111-1111-111111111111", "example.com", "LOW", 5)
    _persist_scan(db_session, "22222222-2222-2222-2222-222222222222", "evil-test.net", "HIGH", 80)

    resp = client.get("/api/v1/scans")
    assert resp.status_code == 200
    assert resp.json()["total"] == 2

    resp = client.get("/api/v1/scans", params={"risk_level": "HIGH"})
    body = resp.json()
    assert body["total"] == 1
    assert body["scans"][0]["target"] == "evil-test.net"

    resp = client.get("/api/v1/scans", params={"search": "example"})
    body = resp.json()
    assert body["total"] == 1
    assert body["scans"][0]["target"] == "example.com"

    resp = client.get("/api/v1/scans", params={"limit": 1, "offset": 1})
    assert resp.json()["count"] == 1
