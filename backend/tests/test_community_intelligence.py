"""Phase 5 — collaborative threat intelligence tests (offline, mocked)."""

import pytest
from backend.app.core.config import settings
from backend.app.models.community import CommunitySubmission
from backend.app.services import community_service as cs
from sqlalchemy import delete

ADMIN = {"Authorization": "Bearer test-admin-token"}


@pytest.fixture(autouse=True)
def _clean(db_session):
    db_session.execute(delete(CommunitySubmission))
    db_session.commit()
    settings.WEBVERITY_ADMIN_TOKEN = "test-admin-token"
    yield
    settings.WEBVERITY_ADMIN_TOKEN = ""


VALID = {
    "indicator_type": "domain",
    "indicator_value": "evil-test.net",
    "threat_category": "phishing",
    "description": "Typosquatting domain observed in a phishing campaign.",
    "source_name": "unit-test",
}


# ---------------------------------------------------------------- validation
def test_validate_rejects_private_targets():
    with pytest.raises(cs.SubmissionValidationError):
        cs.validate_submission("domain", "localhost", "phishing", "x" * 20)
    with pytest.raises(cs.SubmissionValidationError):
        cs.validate_submission("url", "http://127.0.0.1/admin", "phishing", "x" * 20)
    with pytest.raises(cs.SubmissionValidationError):
        cs.validate_submission("ip", "10.0.0.1", "c2", "x" * 20)
    with pytest.raises(cs.SubmissionValidationError):
        cs.validate_submission("ip", "169.254.169.254", "c2", "x" * 20)


def test_validate_rejects_bad_category_and_type():
    with pytest.raises(cs.SubmissionValidationError):
        cs.validate_submission("domain", "evil-test.net", "not-a-category", "x" * 20)
    with pytest.raises(cs.SubmissionValidationError):
        cs.validate_submission("carrier-pigeon", "evil-test.net", "phishing", "x" * 20)


def test_normalize_indicator_url_canonicalization():
    a = cs.normalize_indicator("url", "https://EVIL-test.net/login/")
    b = cs.normalize_indicator("url", "https://evil-test.net/login")
    assert a == b


# ---------------------------------------------------------------- submission API
def test_submit_and_duplicate(client):
    r = client.post("/api/v1/community/submissions", json=VALID)
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "PENDING"

    dup = client.post("/api/v1/community/submissions", json=VALID)
    assert dup.status_code == 409


def test_submit_invalid_input(client):
    r = client.post(
        "/api/v1/community/submissions",
        json={**VALID, "indicator_value": "localhost"},
    )
    assert r.status_code == 400


def test_submission_not_in_verified_intel(db_session):
    """Community submissions stay quarantined from the verified table."""
    from backend.app.models.threat import ThreatIndicator

    # submit then approve via service directly with admin role
    s = CommunitySubmission(
        indicator_type="domain",
        indicator_value="approved-test.net",
        indicator_key="approved-test.net",
        threat_category="phishing",
        description="long enough description for validation.",
        source_name="t",
    )
    db_session.add(s)
    db_session.commit()
    assert (
        db_session.query(ThreatIndicator).filter_by(indicator_value="approved-test.net").count()
        == 0
    )
    cs.review_submission(db_session, s, "APPROVED", "admin-1", "ADMIN", "verified by test")
    assert (
        db_session.query(ThreatIndicator).filter_by(indicator_value="approved-test.net").count()
        == 1
    )
    # rejected submissions never promote
    s2 = CommunitySubmission(
        indicator_type="domain",
        indicator_value="rejected-test.net",
        indicator_key="rejected-test.net",
        threat_category="scam",
        description="another long enough description here.",
        source_name="t",
    )
    db_session.add(s2)
    db_session.commit()
    cs.review_submission(db_session, s2, "REJECTED", "admin-1", "ADMIN", None)
    assert (
        db_session.query(ThreatIndicator).filter_by(indicator_value="rejected-test.net").count()
        == 0
    )


def test_review_requires_analyst_or_admin(client, db_session):
    s = CommunitySubmission(
        indicator_type="domain",
        indicator_value="rbac-test.net",
        indicator_key="rbac-test.net",
        threat_category="phishing",
        description="long enough description for validation.",
        source_name="t",
    )
    db_session.add(s)
    db_session.commit()

    r = client.post(
        f"/api/v1/community/submissions/{s.id}/review",
        json={"decision": "APPROVED"},
    )
    assert r.status_code == 403  # anonymous caller

    r = client.post(
        f"/api/v1/community/submissions/{s.id}/review",
        json={"decision": "APPROVED", "notes": "verified"},
        headers=ADMIN,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "APPROVED"

    # double-review of a final decision is rejected
    r = client.post(
        f"/api/v1/community/submissions/{s.id}/review",
        json={"decision": "REJECTED"},
        headers=ADMIN,
    )
    assert r.status_code == 400


def test_review_creates_audit_log(client, db_session):
    from backend.app.models.community import AuditLog

    s = CommunitySubmission(
        indicator_type="domain",
        indicator_value="audit-test.net",
        indicator_key="audit-test.net",
        threat_category="malware",
        description="long enough description for validation.",
        source_name="t",
    )
    db_session.add(s)
    db_session.commit()
    client.post(
        f"/api/v1/community/submissions/{s.id}/review",
        json={"decision": "REJECTED", "notes": "no evidence"},
        headers=ADMIN,
    )
    logs = db_session.query(AuditLog).filter_by(resource_id=s.id).all()
    assert any(entry.action == "submission_rejected" for entry in logs)
    db_session.execute(delete(AuditLog))
    db_session.commit()


def test_audit_logs_admin_only(client):
    assert client.get("/api/v1/community/audit-logs").status_code == 403
    assert client.get("/api/v1/community/audit-logs", headers=ADMIN).status_code == 200


def test_rate_limiting(client, db_session, monkeypatch):
    from backend.app.models.community import SubmissionRateLimit

    db_session.execute(delete(SubmissionRateLimit))
    db_session.commit()
    monkeypatch.setattr(settings, "SUBMISSION_RATE_LIMIT", 2)
    r1 = client.post("/api/v1/community/submissions", json={**VALID, "indicator_value": "rate-a.net"})
    r2 = client.post("/api/v1/community/submissions", json={**VALID, "indicator_value": "rate-b.net"})
    r3 = client.post("/api/v1/community/submissions", json={**VALID, "indicator_value": "rate-c.net"})
    assert (r1.status_code, r2.status_code, r3.status_code) == (201, 201, 429)


def test_public_listing_hides_rejected(client, db_session):
    db_session.add(
        CommunitySubmission(
            indicator_type="domain",
            indicator_value="hidden-test.net",
            indicator_key="hidden-test.net",
            threat_category="spam",
            description="long enough description for validation.",
            source_name="t",
            status="REJECTED",
        )
    )
    db_session.commit()
    body = client.get("/api/v1/community/submissions").json()
    assert all(x["indicator_value"] != "hidden-test.net" for x in body["submissions"])


def test_meta_endpoint(client):
    body = client.get("/api/v1/community/meta").json()
    assert "phishing" in body["threat_categories"]
    assert "url" in body["indicator_types"]
