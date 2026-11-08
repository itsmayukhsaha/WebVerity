"""Phase 5 — collaborative threat intelligence database entities.

Community-submitted indicators live in their own tables, strictly separate from
the verified Phase 3 ``threat_indicators`` until an authorized reviewer approves
them. Reuses the existing SQLAlchemy ``Base``/``init_db()`` infrastructure.
"""

import uuid
from datetime import UTC, datetime

from backend.app.models.scan import Base
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


class CommunitySubmission(Base):
    """A user-submitted threat indicator awaiting (or past) review.

    Submissions are NEVER auto-promoted to verified intelligence; the
    ``status`` column gates promotion and only the review workflow can change
    it (with an audit record).
    """

    __tablename__ = "community_submissions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    indicator_type: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    indicator_value: Mapped[str] = mapped_column(String(2048), index=True, nullable=False)
    # canonical form used for duplicate detection (lowercased host, no port/query)
    indicator_key: Mapped[str] = mapped_column(String(2048), index=True, nullable=False)
    threat_category: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_name: Mapped[str] = mapped_column(String(128), nullable=False)
    # identity of submitter — Supabase user id when available, else redacted ip hash
    submitter_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    submitter_role: Mapped[str] = mapped_column(String(16), default="CONTRIBUTOR")
    status: Mapped[str] = mapped_column(String(24), default="PENDING", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False, index=True
    )

    def __repr__(self) -> str:
        return f"<CommunitySubmission id={self.id} type={self.indicator_type} status={self.status}>"


class SubmissionReview(Base):
    """Immutable record of one review decision on a submission."""

    __tablename__ = "submission_reviews"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    submission_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("community_submissions.id"), index=True, nullable=False
    )
    reviewer_id: Mapped[str] = mapped_column(String(128), nullable=False)
    reviewer_role: Mapped[str] = mapped_column(String(16), nullable=False)
    decision: Mapped[str] = mapped_column(String(24), nullable=False)  # APPROVED/REJECTED/INFO_REQUESTED
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


class AuditLog(Base):
    """Append-only audit trail for sensitive security-relevant actions."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    actor_role: Mapped[str] = mapped_column(String(16), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Serialized details must never contain credentials or unredacted URLs with tokens
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False, index=True
    )


class ApiToken(Base):
    """Hashed API tokens for authorized roles (admin/analyst).

    Only the SHA-256 hash of a token is stored; the raw token is shown once to
    the operator who configures it via environment/bootstrap. No plaintext
    token is ever persisted or returned by the API.
    """

    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False)  # ADMIN / ANALYST
    label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


class SubmissionRateLimit(Base):
    """Simple fixed-window rate limiting per submitter identity."""

    __tablename__ = "submission_rate_limits"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    identity: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    count: Mapped[int] = mapped_column(Integer, default=0)
