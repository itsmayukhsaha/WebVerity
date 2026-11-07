"""Phase 3 intelligence and detection endpoints.

Integrates with the existing API conventions (APIRouter, structured HTTP
errors, 404 for unknown scan ids). No API credentials are ever returned.
"""

from typing import Any

from backend.app.database.connection import get_db
from backend.app.intelligence.base import redact_url_for_external_query
from backend.app.intelligence.intelligence_manager import get_provider_health
from backend.app.services.result_service import ResultService
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

router = APIRouter(tags=["Intelligence"])


class IntelligenceCheckRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)


class IntelligenceCheckResponse(BaseModel):
    url: str
    providers_checked: int
    matches_found: int
    verified_matches: int
    matches: list[dict[str, Any]]
    is_probability: bool = Field(
        False, description="Threat-feed matching is not a probability estimate"
    )
    disclaimer: str = "Provider unavailability or absence of matches does not imply safety."


@router.get("/intelligence/status")
async def intelligence_status() -> dict[str, Any]:
    """Report configuration state of every threat-intelligence provider."""
    providers = get_provider_health()
    return {
        "providers": [p.model_dump() for p in providers],
        "credentials_exposed": False,
    }


@router.post("/intelligence/check", response_model=IntelligenceCheckResponse)
async def intelligence_check(request: IntelligenceCheckRequest) -> IntelligenceCheckResponse:
    """Check a URL/domain against all enabled threat-intelligence providers.

    Passive lookup only: no connection to the target is made. Query strings
    are redacted before any external submission.
    """
    from backend.app.analyzers.url_analyzer.normalizer import normalize_url
    from backend.app.analyzers.url_analyzer.validator import URLValidationError, validate_url
    from backend.app.core.security import is_safe_hostname
    from backend.app.intelligence.intelligence_manager import collect_intelligence

    try:
        validate_url(request.url)
        normalized = normalize_url(request.url)
    except URLValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    safe, reason = is_safe_hostname(normalized.hostname)
    if not safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security rejection: {reason}",
        )

    matches = collect_intelligence(normalized)
    matched_only = [m.model_dump() for m in matches if m.matched]
    return IntelligenceCheckResponse(
        url=redact_url_for_external_query(normalized.normalized_url),
        providers_checked=len(matches),
        matches_found=len(matched_only),
        verified_matches=sum(
            1 for m in matches if m.matched and m.verification_status == "confirmed"
        ),
        matches=matched_only,
    )


@router.get("/scans/{scan_id}/detection")
async def get_scan_detection(scan_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve the unified Phase 3 detection result for a scan."""
    scan = ResultService.get_scan_by_id(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found.",
        )
    results = scan.results_json or {}
    detection = results.get("detection")
    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No detection result stored for scan '{scan_id}'.",
        )
    return {"scan_id": scan.id, "detection": detection}


@router.get("/scans/{scan_id}/evidence")
async def get_scan_evidence(scan_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve deduplicated correlated evidence for a scan."""
    scan = ResultService.get_scan_by_id(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found.",
        )
    detection = (scan.results_json or {}).get("detection") or {}
    evidence = detection.get("evidence", [])
    return {
        "scan_id": scan.id,
        "count": len(evidence),
        "duplicates_removed": detection.get("duplicates_removed", 0),
        "evidence": evidence,
    }


@router.get("/scans/{scan_id}/intelligence")
async def get_scan_intelligence_detail(
    scan_id: str, db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Retrieve normalized intelligence matches recorded for a scan."""
    scan = ResultService.get_scan_by_id(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found.",
        )
    detection = (scan.results_json or {}).get("detection") or {}
    matches = detection.get("intelligence_matches", [])
    return {
        "scan_id": scan.id,
        "count": len(matches),
        "intelligence_matches": matches,
    }
