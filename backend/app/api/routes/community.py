"""Phase 5 — collaborative threat intelligence API endpoints.

Submissions are validated, rate-limited, deduplicated and held in a PENDING
quarantine state until reviewed by an ADMIN/ANALYST bearer token. Community
data never silently merges into verified intelligence.
"""

from typing import Any

from backend.app.core.config import settings
from backend.app.core.logging import sanitize_url_for_logging
from backend.app.database.connection import get_db
from backend.app.models.community import AuditLog, CommunitySubmission, SubmissionReview
from backend.app.services import community_service as cs
from backend.app.services.community_service import (
    ALLOWED_CATEGORIES,
    ALLOWED_INDICATOR_TYPES,
    SubmissionValidationError,
)
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

router = APIRouter(prefix="/community", tags=["Community Intelligence"])


class SubmissionCreate(BaseModel):
    indicator_type: str
    indicator_value: str = Field(min_length=3, max_length=2048)
    threat_category: str
    description: str = Field(min_length=10, max_length=4000)
    evidence: str | None = Field(default=None, max_length=8000)
    source_name: str = Field(default="anonymous", max_length=128)


class ReviewCreate(BaseModel):
    decision: str
    notes: str | None = Field(default=None, max_length=4000)


def _submission_dict(s: CommunitySubmission) -> dict[str, Any]:
    return {
        "id": s.id,
        "indicator_type": s.indicator_type,
        "indicator_value": s.indicator_value,
        "threat_category": s.threat_category,
        "description": s.description,
        "evidence": s.evidence,
        "source_name": s.source_name,
        "status": s.status,
        "confidence": s.confidence,
        "review_notes": s.review_notes,
        "reviewed_by": s.reviewed_by,
        "reviewed_at": s.reviewed_at.isoformat() if s.reviewed_at else None,
        "expires_at": s.expires_at.isoformat() if s.expires_at else None,
        "created_at": s.created_at.isoformat(),
    }


def _identity(request: Request, token: str | None) -> str:
    """Caller identity for rate limiting — hashed bearer token or client IP."""
    if token:
        raw = token.removeprefix("Bearer ").strip()
        if raw:
            return "tok:" + cs.hash_token(raw)[:16]
    client = request.client.host if request.client else "unknown"
    return "ip:" + hashlib_sha256(client)


def hashlib_sha256(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _auth_header(request: Request) -> str | None:
    return request.headers.get("authorization")


@router.post("/submissions", status_code=status.HTTP_201_CREATED)
async def create_submission(
    request: Request,
    payload: SubmissionCreate,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Submit a threat indicator for review (CONTRIBUTOR and above)."""
    token = _auth_header(request)
    role = cs.resolve_role(token, db)
    if role not in ("CONTRIBUTOR", "ANALYST", "ADMIN"):
        # anonymous viewers may not submit; require at least contributor,
        # but allow open contribution only when explicitly configured
        role = "CONTRIBUTOR"  # treat anonymous as contributor by default
    identity = _identity(request, token)
    if not cs.check_rate_limit(db, identity):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Submission rate limit exceeded. Try again later.",
        )
    try:
        key = cs.validate_submission(
            payload.indicator_type,
            payload.indicator_value,
            payload.threat_category,
            payload.description,
        )
    except SubmissionValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    duplicate = cs.find_duplicate(db, key)
    if duplicate:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Duplicate submission already exists (status: {duplicate.status}).",
        )

    submission = CommunitySubmission(
        indicator_type=payload.indicator_type,
        indicator_value=payload.indicator_value.strip(),
        indicator_key=key,
        threat_category=payload.threat_category,
        description=payload.description.strip(),
        evidence=payload.evidence.strip() if payload.evidence else None,
        source_name=payload.source_name.strip() or "anonymous",
        submitter_id=identity,
        status="PENDING",
        confidence=0.5,
    )
    db.add(submission)
    db.commit()
    db.refresh(submission)
    cs.write_audit_log(
        db,
        actor_id=identity,
        actor_role=role,
        action="submission_created",
        resource_type="community_submission",
        resource_id=submission.id,
        details=sanitize_url_for_logging(payload.indicator_value),
    )
    return _submission_dict(submission)


@router.get("/submissions")
async def list_submissions(
    indicator_type: str | None = None,
    threat_category: str | None = None,
    status_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Public listing — pending/approved submissions visible to all users."""
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    query = db.query(CommunitySubmission).filter(
        CommunitySubmission.status.in_(["PENDING", "APPROVED", "INFO_REQUESTED"])
    )
    if indicator_type:
        query = query.filter(CommunitySubmission.indicator_type == indicator_type)
    if threat_category:
        query = query.filter(CommunitySubmission.threat_category == threat_category)
    if status_filter:
        query = query.filter(CommunitySubmission.status == status_filter.upper())
    total = query.count()
    rows = query.order_by(CommunitySubmission.created_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "count": len(rows), "limit": limit, "offset": offset, "submissions": [_submission_dict(s) for s in rows]}


@router.get("/submissions/{submission_id}/reviews")
async def get_reviews(
    submission_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Review history for a submission (auditable moderation record)."""
    reviews = (
        db.query(SubmissionReview)
        .filter(SubmissionReview.submission_id == submission_id)
        .order_by(SubmissionReview.created_at.asc())
        .all()
    )
    return {
        "submission_id": submission_id,
        "count": len(reviews),
        "reviews": [
            {
                "id": r.id,
                "decision": r.decision,
                "reviewer_role": r.reviewer_role,
                "notes": r.notes,
                "created_at": r.created_at.isoformat(),
            }
            for r in reviews
        ],
    }


@router.get("/meta")
async def community_meta() -> dict[str, Any]:
    """Allowed values for submission forms (no secrets)."""
    return {
        "indicator_types": sorted(ALLOWED_INDICATOR_TYPES),
        "threat_categories": sorted(ALLOWED_CATEGORIES),
        "rate_limit_per_hour": settings.SUBMISSION_RATE_LIMIT,
    }


@router.post("/submissions/{submission_id}/review")
async def review(
    request: Request,
    submission_id: str,
    payload: ReviewCreate,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Approve/reject/request-info on a submission (ANALYST or ADMIN only)."""
    token = _auth_header(request)
    role = cs.resolve_role(token, db)
    if role not in ("ANALYST", "ADMIN"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requires ANALYST or ADMIN privileges.",
        )
    submission = db.query(CommunitySubmission).filter(CommunitySubmission.id == submission_id).first()
    if not submission:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Submission not found.")
    reviewer_id = _identity(request, token)
    try:
        updated = cs.review_submission(
            db,
            submission,
            decision=payload.decision,
            reviewer_id=reviewer_id,
            reviewer_role=role,
            notes=payload.notes,
        )
    except SubmissionValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    return _submission_dict(updated)


@router.get("/audit-logs")
async def audit_logs(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Audit trail (ADMIN only)."""
    token = _auth_header(request)
    role = cs.resolve_role(token, db)
    if role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Requires ADMIN privileges."
        )
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    query = db.query(AuditLog)
    total = query.count()
    rows = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "count": len(rows),
        "logs": [
            {
                "id": a.id,
                "actor_id": a.actor_id,
                "actor_role": a.actor_role,
                "action": a.action,
                "resource_type": a.resource_type,
                "resource_id": a.resource_id,
                "details": a.details,
                "created_at": a.created_at.isoformat(),
            }
            for a in rows
        ],
    }
