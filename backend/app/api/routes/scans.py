"""Scan submission and retrieval endpoints (Phase 2 extended)."""

from typing import Any

from backend.app.analyzers.url_analyzer.validator import URLValidationError
from backend.app.core.logging import logger, sanitize_url_for_logging
from backend.app.core.security import SSRFSecurityException
from backend.app.database.connection import get_db
from backend.app.orchestration.scan_manager import ScanManager
from backend.app.schemas.evidence import Finding
from backend.app.schemas.scan import (
    ConfidenceLevel,
    ModuleResults,
    RiskClassification,
    ScanCreateRequest,
    ScanResponse,
    ScanStatus,
    ThreatAssessment,
)
from backend.app.services.result_service import ResultService
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def submit_scan(
    request: ScanCreateRequest,
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Submit a URL for comprehensive phishing detection and trust assessment."""
    sanitized = sanitize_url_for_logging(request.url)
    logger.info(f"Received scan request for URL: {sanitized}")

    try:
        scan_response = await ScanManager.process_scan(raw_url=request.url, db=db)
        logger.info(
            f"Scan {scan_response.scan_id} completed for target '{scan_response.target}' "
            f"with risk score {scan_response.threat_assessment.risk_score} ({scan_response.threat_assessment.classification})"
        )
        return scan_response
    except URLValidationError as e:
        logger.warning(f"URL validation rejected for '{sanitized}': {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except SSRFSecurityException as e:
        logger.warning(f"SSRF violation blocked for '{sanitized}': {e.message}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security rejection: {e.message}",
        ) from e
    except Exception as e:
        logger.error(f"Unexpected scan processing error for '{sanitized}': {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected internal error occurred while processing the scan.",
        ) from e


def _load_scan_response(scan: Any) -> ScanResponse:
    """Reconstruct the ScanResponse contract from a stored scan record."""
    results_data: dict[str, Any] = scan.results_json or {}
    modules_data = results_data.get("modules", {})
    findings_data = results_data.get("findings", [])
    threat_data = results_data.get("threat_assessment", {})

    threat_assessment = ThreatAssessment(
        risk_score=scan.risk_score,
        classification=RiskClassification(scan.risk_level),
        confidence=ConfidenceLevel(scan.confidence),
        is_probability=threat_data.get("is_probability", False),
        explanation=threat_data.get("explanation"),
        security_posture_score=getattr(scan, "security_posture_score", None)
        or threat_data.get("security_posture_score", 100),
    )

    findings: list[Finding] = [Finding(**f) for f in findings_data]

    return ScanResponse(
        scan_id=scan.id,
        status=ScanStatus(scan.status),
        target=scan.domain,
        threat_assessment=threat_assessment,
        modules=ModuleResults(
            url_analysis=modules_data.get("url_analysis", {}),
            dns_analysis=modules_data.get("dns_analysis", {}),
            tls_analysis=modules_data.get("tls_analysis", {}),
            http_security=modules_data.get("http_security", {}),
            redirect_analysis=modules_data.get("redirect_analysis", {}),
            content_analysis=modules_data.get("content_analysis", {}),
            domain_intelligence=modules_data.get("domain_intelligence", {}),
            threat_intelligence=modules_data.get("threat_intelligence", {}),
        ),
        findings=findings,
        recommendations=results_data.get("recommendations", []),
        scan_metadata=results_data.get("scan_metadata", {}),
        created_at=scan.created_at.isoformat(),
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_by_id(
    scan_id: str,
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Retrieve stored scan findings and risk assessment by scan UUID."""
    scan = ResultService.get_scan_by_id(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found.",
        )
    return _load_scan_response(scan)


@router.get("/{scan_id}/intelligence")
async def get_scan_intelligence(
    scan_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve the threat intelligence and domain registration (RDAP) module outputs."""
    scan = ResultService.get_scan_by_id(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found.",
        )
    modules = (scan.results_json or {}).get("modules", {})
    return {
        "scan_id": scan.id,
        "threat_intelligence": modules.get("threat_intelligence", {}),
        "domain_intelligence": modules.get("domain_intelligence", {}),
    }


@router.get("/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve the full deduplicated findings list for a scan."""
    scan = ResultService.get_scan_by_id(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found.",
        )
    findings = (scan.results_json or {}).get("findings", [])
    return {"scan_id": scan.id, "count": len(findings), "findings": findings}


@router.get("/{scan_id}/recommendations")
async def get_scan_recommendations(
    scan_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve the actionable recommendations generated for a scan."""
    scan = ResultService.get_scan_by_id(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found.",
        )
    recommendations = (scan.results_json or {}).get("recommendations", [])
    return {"scan_id": scan.id, "count": len(recommendations), "recommendations": recommendations}
