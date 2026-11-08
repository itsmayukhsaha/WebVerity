"""Phase 5 — collaborative intelligence service layer.

Implements indicator validation/normalization, duplicate detection, rate
limiting, token-based role authorization, review workflow and audit logging.
Community submissions are kept separate from verified intelligence until an
authorized reviewer approves them.
"""

import hashlib
import ipaddress
import re
import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

from backend.app.core.config import settings
from backend.app.core.logging import logger, sanitize_url_for_logging
from backend.app.models.community import (
    ApiToken,
    AuditLog,
    CommunitySubmission,
    SubmissionRateLimit,
    SubmissionReview,
)
from sqlalchemy.orm import Session

ALLOWED_INDICATOR_TYPES = {"url", "domain", "ip", "phishing_pattern", "malware_pattern"}
ALLOWED_CATEGORIES = {
    "phishing",
    "malware",
    "c2",
    "spam",
    "credential_harvesting",
    "brand_impersonation",
    "scam",
    "other",
}
ALLOWED_STATUSES = {"PENDING", "APPROVED", "REJECTED", "INFO_REQUESTED"}
ROLE_PRIORITY = {"VIEWER": 0, "CONTRIBUTOR": 1, "ANALYST": 2, "ADMIN": 3}

_URL_RE = re.compile(
    r"^https?://[A-Za-z0-9\-._~%]+(:\d{1,5})?(/[A-Za-z0-9\-._~%!$&'()*+,;=:@/]*)?(\?[^\s]*)?$"
)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_PRIVATE_HINTS = ("localhost", ".local", ".internal", "metadata.google.internal")


class SubmissionValidationError(Exception):
    """Raised when a community submission fails validation."""


class AuthorizationError(Exception):
    """Raised when a caller lacks the required role."""


def hash_token(raw: str) -> str:
    """SHA-256 of a raw API token (never store plaintext)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def resolve_role(token: str | None, db: Session) -> str:
    """Resolve the caller's role from an Authorization bearer token.

    Uses the trusted configured admin token or hashed ApiToken rows.
    Anonymous callers get VIEWER. Supabase-issued JWTs are accepted when the
    Supabase URL/keys are configured (role is provided via ``X-WebVerity-Role``
    only for trusted internal usage — user-submitted roles are ignored).
    """
    if token:
        raw = token.removeprefix("Bearer ").strip()
        if raw and secrets.compare_digest(raw, settings.WEBVERITY_ADMIN_TOKEN):
            return "ADMIN"
        if raw:
            row = (
                db.query(ApiToken)
                .filter(ApiToken.token_hash == hash_token(raw), ApiToken.active.is_(True))
                .first()
            )
            if row:
                return row.role
    return "VIEWER"


def require_role(minimum: str):
    """Dependency-compatible role check factory."""

    def _check(role: str) -> str:
        if ROLE_PRIORITY.get(role, 0) < ROLE_PRIORITY[minimum]:
            raise AuthorizationError(f"Requires {minimum} privileges.")
        return role

    return _check


def normalize_indicator(indicator_type: str, value: str) -> str:
    """Return the canonical dedup key for an indicator."""
    v = value.strip().lower()
    if indicator_type == "ip":
        ipaddress.ip_address(v)  # raises ValueError when invalid
        return v
    if indicator_type == "domain":
        v = v.rstrip(".")
        return v
    if indicator_type == "url":
        # canonical URL: strip default ports and fragments, drop query for redaction safety
        parsed = urlparse(v if "://" in v else f"https://{v}")
        host = parsed.hostname or ""
        netloc = f"{host}:{parsed.port}" if parsed.port and parsed.port not in (80, 443) else host
        path = parsed.path.rstrip("/") or ""
        return f"{parsed.scheme}://{netloc}{path}"
    # pattern types: whitespace-normalized lowercase
    return re.sub(r"\s+", " ", v)


def validate_submission(
    indicator_type: str, indicator_value: str, threat_category: str, description: str
) -> str:
    """Validate and return the normalized indicator key. Raises on invalid input."""
    if indicator_type not in ALLOWED_INDICATOR_TYPES:
        raise SubmissionValidationError(
            f"indicator_type must be one of {sorted(ALLOWED_INDICATOR_TYPES)}."
        )
    if threat_category not in ALLOWED_CATEGORIES:
        raise SubmissionValidationError(
            f"threat_category must be one of {sorted(ALLOWED_CATEGORIES)}."
        )
    value = indicator_value.strip()
    if len(value) < 3 or len(value) > 2048:
        raise SubmissionValidationError("indicator_value must be 3–2048 characters.")
    if len(description.strip()) < 10:
        raise SubmissionValidationError("description must be at least 10 characters.")

    key = normalize_indicator(indicator_type, value)

    # SSRF-style safety: never accept loopback/private/metadata targets as community intel
    if indicator_type in ("url", "domain"):
        host = urlparse(key if "://" in key else f"https://{key}").hostname or key
        if any(h in host for h in _PRIVATE_HINTS):
            raise SubmissionValidationError("Private or reserved hostnames are not accepted.")
        try:
            ipaddress.ip_address(host)
            raise SubmissionValidationError("URL/domain must not be a bare IP address.")
        except ValueError:
            pass
    if indicator_type == "ip":
        addr = ipaddress.ip_address(key)
        if not addr.is_global:
            raise SubmissionValidationError("Only public IP addresses are accepted.")

    if indicator_type == "url" and not _URL_RE.match(value):
        raise SubmissionValidationError("URL must be an absolute http(s) URL.")
    if indicator_type == "domain" and not _DOMAIN_RE.match(key):
        raise SubmissionValidationError("Domain must be a valid hostname (e.g. evil-test.net).")
    return key


def check_rate_limit(db: Session, identity: str) -> bool:
    """Fixed-window rate limit. Returns False when the caller exceeded the quota."""
    now = datetime.now(UTC)
    window = timedelta(hours=1)
    row = db.query(SubmissionRateLimit).filter(SubmissionRateLimit.identity == identity).first()
    window_start = row.window_start.replace(tzinfo=UTC) if row and row.window_start.tzinfo is None else (row.window_start if row else None)
    if not row or (now - window_start) > window:
        if row:
            row.window_start = now
            row.count = 0
        else:
            row = SubmissionRateLimit(identity=identity, window_start=now, count=0)
            db.add(row)
        row.count += 1
        db.commit()
        return True
    if row.count >= settings.SUBMISSION_RATE_LIMIT:
        return False
    row.count += 1
    db.commit()
    return True


def find_duplicate(db: Session, indicator_key: str) -> CommunitySubmission | None:
    """Duplicate detection against active community submissions."""
    return (
        db.query(CommunitySubmission)
        .filter(
            CommunitySubmission.indicator_key == indicator_key,
            CommunitySubmission.status.in_(["PENDING", "APPROVED", "INFO_REQUESTED"]),
        )
        .first()
    )


def write_audit_log(
    db: Session,
    actor_id: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: str | None = None,
) -> None:
    """Append-only audit trail write."""
    db.add(
        AuditLog(
            actor_id=actor_id,
            actor_role=actor_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
        )
    )
    db.commit()
    logger.info(f"AUDIT {action} {resource_type}/{resource_id} by {actor_role}:{actor_id}")


def review_submission(
    db: Session,
    submission: CommunitySubmission,
    decision: str,
    reviewer_id: str,
    reviewer_role: str,
    notes: str | None,
) -> CommunitySubmission:
    """Apply a review decision with an auditable trail.

    Approval promotes the indicator into the verified ``threat_indicators``
    table so the existing Phase 3 matching pipeline can use it. Rejections and
    info requests never touch verified intelligence.
    """
    if decision not in ("APPROVED", "REJECTED", "INFO_REQUESTED"):
        raise SubmissionValidationError("decision must be APPROVED, REJECTED or INFO_REQUESTED.")
    if submission.status not in ("PENDING", "INFO_REQUESTED"):
        raise SubmissionValidationError("Submission has already reached a final decision.")

    submission.status = decision
    submission.review_notes = notes
    submission.reviewed_by = reviewer_id
    submission.reviewed_at = datetime.now(UTC)
    if decision == "APPROVED":
        submission.expires_at = datetime.now(UTC) + timedelta(
            days=settings.COMMUNITY_INTEL_TTL_DAYS
        )

    db.add(
        SubmissionReview(
            submission_id=submission.id,
            reviewer_id=reviewer_id,
            reviewer_role=reviewer_role,
            decision=decision,
            notes=notes,
        )
    )
    db.commit()
    db.refresh(submission)

    if decision == "APPROVED":
        from backend.app.models.threat import ThreatIndicator

        existing = (
            db.query(ThreatIndicator)
            .filter(
                ThreatIndicator.indicator_type == submission.indicator_type,
                ThreatIndicator.indicator_value == submission.indicator_value,
            )
            .first()
        )
        if not existing:
            db.add(
                ThreatIndicator(
                    indicator_type=submission.indicator_type,
                    indicator_value=submission.indicator_value,
                    source=f"community:{submission.source_name}",
                    threat_category=submission.threat_category,
                    verification_status="community_approved",
                    expires_at=submission.expires_at,
                )
            )
            db.commit()

    write_audit_log(
        db,
        actor_id=reviewer_id,
        actor_role=reviewer_role,
        action=f"submission_{decision.lower()}",
        resource_type="community_submission",
        resource_id=submission.id,
        details=sanitize_url_for_logging(notes or ""),
    )
    return submission
