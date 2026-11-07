"""High-level scan manager coordinating validation, orchestration, and persistence."""

import uuid
from datetime import UTC, datetime

from backend.app.analyzers.url_analyzer.normalizer import normalize_url
from backend.app.analyzers.url_analyzer.validator import validate_url
from backend.app.core.security import SSRFSecurityException, is_safe_hostname
from backend.app.orchestration.pipeline import execute_scan_pipeline
from backend.app.schemas.scan import (
    ModuleResults,
    ScanResponse,
    ScanStatus,
)
from backend.app.services.result_service import ResultService
from sqlalchemy.orm import Session


class ScanManager:
    """Manager for full scan lifecycle execution."""

    @staticmethod
    async def process_scan(raw_url: str, db: Session) -> ScanResponse:
        """Execute complete scan lifecycle.

        Args:
            raw_url: Submitted URL.
            db: Database session.

        Returns:
            ScanResponse populated with scan results.

        Raises:
            URLValidationError: If URL structure is invalid.
            SSRFSecurityException: If target hostname violates SSRF policy.
        """
        # Step 1: URL validation
        validate_url(raw_url)

        # Step 2: URL normalization
        normalized = normalize_url(raw_url)

        # Step 3: SSRF pre-check on target hostname
        safe_host, reason = is_safe_hostname(normalized.hostname)
        if not safe_host:
            raise SSRFSecurityException(
                message=f"SSRF Security Violation: {reason}",
                target=normalized.hostname,
            )

        # Step 4: Generate unique scan identifier
        scan_id = str(uuid.uuid4())
        created_at_dt = datetime.now(UTC)
        created_at_str = created_at_dt.isoformat()

        # Step 5: Initialize scan record in database
        ResultService.create_scan_record(
            db=db,
            scan_id=scan_id,
            submitted_url_redacted=normalized.redacted_url,
            normalized_url=normalized.normalized_url,
            domain=normalized.hostname,
        )

        # Step 6: Asynchronously execute analysis pipeline
        aggregated = await execute_scan_pipeline(normalized=normalized, raw_url=raw_url)

        completed_at_dt = datetime.now(UTC)
        completed_at_str = completed_at_dt.isoformat()

        # Step 7: Serialize modules, findings, and recommendations for storage
        from backend.app.detection.recommendations import generate_recommendations

        recommendations = generate_recommendations(aggregated)
        results_data = {
            "modules": aggregated.modules,
            "findings": [f.model_dump() for f in aggregated.findings],
            "threat_assessment": aggregated.threat_assessment.model_dump(),
            "recommendations": recommendations,
            "scan_metadata": {
                "modules_completed": sum(
                    1 for s in aggregated.statuses.values() if s in ("COMPLETED", "RESOLVED")
                ),
                "modules_total": len(aggregated.statuses),
                "module_statuses": aggregated.statuses,
            },
        }

        # Step 8: Update database record
        from backend.app.detection.risk_scoring import calculate_security_posture

        ResultService.save_scan_result(
            db=db,
            scan_id=scan_id,
            status=ScanStatus.COMPLETED.value,
            risk_score=aggregated.threat_assessment.risk_score,
            risk_level=aggregated.threat_assessment.classification.value,
            confidence=aggregated.threat_assessment.confidence.value,
            security_posture_score=calculate_security_posture(aggregated.findings),
            results_json=results_data,
        )

        # Step 9: Build and return ScanResponse contract
        from backend.app.detection.risk_scoring import calculate_security_posture as _posture

        threat_assessment = aggregated.threat_assessment.model_copy(
            update={"security_posture_score": _posture(aggregated.findings)}
        )
        return ScanResponse(
            scan_id=scan_id,
            status=ScanStatus.COMPLETED,
            target=normalized.hostname,
            threat_assessment=threat_assessment,
            modules=ModuleResults(
                url_analysis=aggregated.modules.get("url_analysis", {}),
                dns_analysis=aggregated.modules.get("dns_analysis", {}),
                tls_analysis=aggregated.modules.get("tls_analysis", {}),
                http_security=aggregated.modules.get("http_security", {}),
                redirect_analysis=aggregated.modules.get("redirect_analysis", {}),
                content_analysis=aggregated.modules.get("content_analysis", {}),
                domain_intelligence=aggregated.modules.get("domain_intelligence", {}),
                threat_intelligence=aggregated.modules.get("threat_intelligence", {}),
            ),
            findings=aggregated.findings,
            recommendations=recommendations,
            scan_metadata=results_data["scan_metadata"],
            created_at=created_at_str,
            completed_at=completed_at_str,
        )
