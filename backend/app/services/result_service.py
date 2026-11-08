"""Database persistence and retrieval service for scan results."""

from datetime import UTC, datetime

from backend.app.models.scan import Scan
from sqlalchemy.orm import Session


class ResultService:
    """Encapsulates database operations for scan records."""

    @staticmethod
    def create_scan_record(
        db: Session,
        scan_id: str,
        submitted_url_redacted: str,
        normalized_url: str,
        domain: str,
    ) -> Scan:
        """Create an initial pending scan record."""
        scan = Scan(
            id=scan_id,
            submitted_url_redacted=submitted_url_redacted,
            normalized_url=normalized_url,
            domain=domain,
            status="PROCESSING",
            risk_score=0,
            risk_level="LOW",
            confidence="LOW",
            security_posture_score=100,
            results_json={},
            created_at=datetime.now(UTC),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    @staticmethod
    def save_scan_result(
        db: Session,
        scan_id: str,
        status: str,
        risk_score: int,
        risk_level: str,
        confidence: str,
        results_json: dict,
        security_posture_score: int = 100,
    ) -> Scan | None:
        """Update scan record with final assessment results."""
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None

        scan.status = status
        scan.risk_score = risk_score
        scan.risk_level = risk_level
        scan.confidence = confidence
        scan.security_posture_score = security_posture_score
        scan.results_json = results_json
        scan.completed_at = datetime.now(UTC)

        db.commit()
        db.refresh(scan)
        return scan

    @staticmethod
    def get_scan_by_id(db: Session, scan_id: str) -> Scan | None:
        """Retrieve a stored scan by its UUID."""
        return db.query(Scan).filter(Scan.id == scan_id).first()

    @staticmethod
    def list_scans(
        db: Session,
        search: str | None = None,
        risk_level: str | None = None,
        status_filter: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Scan], int]:
        """List completed scan records with optional search and filters.

        Returns (scans, total_matching) ordered by newest first.
        """
        query = db.query(Scan)
        if search:
            like = f"%{search}%"
            query = query.filter(
                (Scan.domain.ilike(like)) | (Scan.submitted_url_redacted.ilike(like))
            )
        if risk_level:
            query = query.filter(Scan.risk_level == risk_level.upper())
        if status_filter:
            query = query.filter(Scan.status == status_filter.upper())

        total = query.count()
        scans = query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
        return scans, total
