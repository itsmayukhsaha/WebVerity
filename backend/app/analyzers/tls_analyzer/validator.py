"""TLS certificate and transport security validator."""

from typing import Any

from backend.app.analyzers.tls_analyzer.certificate import parse_x509_certificate
from backend.app.analyzers.tls_analyzer.handshake import perform_tls_handshake
from backend.app.schemas.evidence import Finding, Severity


def match_hostname(hostname: str, san_or_cn_list: list[str]) -> bool:
    """Validate whether a hostname matches any SAN or Common Name entry according to RFC 6125.

    Supports wildcard certificates (e.g. *.example.com matches foo.example.com).
    """
    host = hostname.lower().strip()
    for pattern in san_or_cn_list:
        p = pattern.lower().strip()
        if p == host:
            return True
        if p.startswith("*."):
            # Wildcard applies to a single subdomain level
            suffix = p[2:]
            if host.endswith("." + suffix):
                prefix = host[: -(len(suffix) + 1)]
                if "." not in prefix and prefix:
                    return True
    return False


def validate_tls(
    scheme: str,
    hostname: str,
    destination_ip: str | None = None,
    port: int = 443,
    timeout: float | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Perform comprehensive TLS inspection, chain validation, and security evaluation.

    Args:
        scheme: Protocol scheme ('http' or 'https').
        hostname: Original target hostname.
        destination_ip: Safe, pinned public IP to connect to.
        port: Destination port (default 443).
        timeout: Socket timeout.

    Returns:
        Tuple of (tls_module_dict, findings_list).
    """
    findings: list[Finding] = []

    # Case 1: Plaintext HTTP
    if scheme == "http":
        findings.append(
            Finding(
                id="TLS_HTTP_NO_ENCRYPTION",
                module="tls_analysis",
                severity=Severity.MEDIUM,
                title="Unencrypted HTTP Transport",
                description="The target site utilizes plaintext HTTP. Credentials, session tokens, and data in transit are exposed to interception and tampering.",
                evidence={"scheme": "http", "port": port},
            )
        )
        result = {
            "module": "tls_analysis",
            "status": "NOT_APPLICABLE",
            "https_enabled": False,
            "hostname_match": None,
            "chain_validation": "NOT_APPLICABLE",
            "certificate_expired": None,
            "issuer": None,
            "tls_version": None,
            "cipher": None,
            "certificate": None,
            "findings": [f.model_dump() for f in findings],
        }
        return result, findings

    # Case 2: Missing destination IP (e.g. DNS resolution failed or was blocked)
    if not destination_ip:
        result = {
            "module": "tls_analysis",
            "status": "UNKNOWN",
            "https_enabled": True,
            "hostname_match": None,
            "chain_validation": "UNKNOWN",
            "certificate_expired": None,
            "issuer": None,
            "tls_version": None,
            "cipher": None,
            "certificate": None,
            "findings": [f.model_dump() for f in findings],
        }
        return result, findings

    # Case 3: Execute TLS handshake against pinned public IP
    handshake = perform_tls_handshake(
        destination_ip=destination_ip,
        hostname=hostname,
        port=port,
        timeout=timeout,
    )

    if not handshake.handshake_success or handshake.der_cert is None:
        error_title = "TLS Handshake Failed"
        severity = Severity.HIGH
        if handshake.error_type == "TIMEOUT":
            error_title = "TLS Handshake Timeout"
            severity = Severity.LOW

        findings.append(
            Finding(
                id="TLS_HANDSHAKE_ERROR",
                module="tls_analysis",
                severity=severity,
                title=error_title,
                description=f"Failed to complete TLS negotiation: {handshake.verification_error or 'Unknown error'}",
                evidence={
                    "destination_ip": destination_ip,
                    "error_type": handshake.error_type,
                    "detail": handshake.verification_error,
                },
            )
        )

        result = {
            "module": "tls_analysis",
            "status": "UNKNOWN" if handshake.error_type == "TIMEOUT" else "FAILED",
            "https_enabled": True,
            "hostname_match": None,
            "chain_validation": "UNKNOWN",
            "certificate_expired": None,
            "issuer": None,
            "tls_version": None,
            "cipher": None,
            "certificate": None,
            "findings": [f.model_dump() for f in findings],
        }
        return result, findings

    # Parse leaf certificate
    try:
        cert_info = parse_x509_certificate(handshake.der_cert)
    except Exception as e:
        findings.append(
            Finding(
                id="TLS_CERT_PARSE_ERROR",
                module="tls_analysis",
                severity=Severity.HIGH,
                title="Certificate Parsing Failure",
                description=f"Received certificate data could not be parsed: {e}",
                evidence={"error": str(e)},
            )
        )
        result = {
            "module": "tls_analysis",
            "status": "FAILED",
            "https_enabled": True,
            "hostname_match": None,
            "chain_validation": "INVALID",
            "certificate_expired": None,
            "issuer": None,
            "tls_version": handshake.tls_version,
            "cipher": handshake.cipher,
            "certificate": None,
            "findings": [f.model_dump() for f in findings],
        }
        return result, findings

    # Check hostname match
    san_list = cert_info.get("subject_alternative_names", [])
    subject_cn = cert_info.get("subject", {}).get("common_name")
    match_targets = list(san_list)
    if subject_cn:
        match_targets.append(subject_cn)

    is_hostname_match = match_hostname(hostname, match_targets)
    is_expired = cert_info.get("is_expired", False)
    is_not_yet_valid = cert_info.get("is_not_yet_valid", False)
    days_until_expiry = cert_info.get("days_until_expiry", 0)

    # Determine chain validation status
    if is_expired:
        chain_validation = "EXPIRED"
        findings.append(
            Finding(
                id="TLS_CERTIFICATE_EXPIRED",
                module="tls_analysis",
                severity=Severity.HIGH,
                title="Expired TLS Certificate",
                description=f"Certificate expired on {cert_info.get('validity_expiry')}.",
                evidence={
                    "expiry": cert_info.get("validity_expiry"),
                    "days_expired": abs(days_until_expiry),
                },
            )
        )
    elif is_not_yet_valid:
        chain_validation = "INVALID"
        findings.append(
            Finding(
                id="TLS_CERTIFICATE_NOT_YET_VALID",
                module="tls_analysis",
                severity=Severity.HIGH,
                title="Certificate Not Yet Valid",
                description=f"Certificate validity start date is in the future: {cert_info.get('validity_start')}.",
                evidence={"validity_start": cert_info.get("validity_start")},
            )
        )
    elif not is_hostname_match:
        chain_validation = "INVALID"
        findings.append(
            Finding(
                id="TLS_HOSTNAME_MISMATCH",
                module="tls_analysis",
                severity=Severity.HIGH,
                title="Certificate Hostname Mismatch",
                description=f"Hostname '{hostname}' does not match certificate SANs ({san_list}) or Common Name ('{subject_cn}').",
                evidence={"hostname": hostname, "subject_cn": subject_cn, "sans": san_list},
            )
        )
    elif not handshake.is_verified:
        chain_validation = "INVALID"
        findings.append(
            Finding(
                id="TLS_UNTRUSTED_CHAIN",
                module="tls_analysis",
                severity=Severity.HIGH,
                title="Untrusted Certificate Chain",
                description=f"Certificate could not be verified by system trust store: {handshake.verification_error}. May be self-signed or from an untrusted CA.",
                evidence={"detail": handshake.verification_error},
            )
        )
    else:
        chain_validation = "VALID"

    # Additional cryptographic and hygiene checks
    if not is_expired and not is_not_yet_valid and 0 <= days_until_expiry <= 7:
        findings.append(
            Finding(
                id="TLS_EXPIRING_SOON",
                module="tls_analysis",
                severity=Severity.LOW,
                title="Certificate Expiring Soon",
                description=f"Certificate will expire in {days_until_expiry} days.",
                evidence={"days_until_expiry": days_until_expiry},
            )
        )

    # Check key size
    pub_key = cert_info.get("public_key", {})
    if pub_key.get("algorithm") == "RSA" and pub_key.get("key_size", 0) < 2048:
        findings.append(
            Finding(
                id="TLS_WEAK_KEY_SIZE",
                module="tls_analysis",
                severity=Severity.MEDIUM,
                title="Weak Cryptographic Key Size",
                description=f"RSA key size of {pub_key.get('key_size')} bits is insecure and vulnerable to factorization.",
                evidence=pub_key,
            )
        )

    # Check signature algorithm
    sig_algo = cert_info.get("signature_algorithm", "").lower()
    if "sha1" in sig_algo or "md5" in sig_algo:
        findings.append(
            Finding(
                id="TLS_WEAK_SIGNATURE_ALGO",
                module="tls_analysis",
                severity=Severity.HIGH,
                title="Weak Certificate Signature Algorithm",
                description=f"Certificate is signed with deprecated algorithm '{cert_info.get('signature_algorithm')}', vulnerable to collision attacks.",
                evidence={"signature_algorithm": cert_info.get("signature_algorithm")},
            )
        )

    # Check TLS version
    if handshake.tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append(
            Finding(
                id="TLS_DEPRECATED_PROTOCOL",
                module="tls_analysis",
                severity=Severity.MEDIUM,
                title="Deprecated TLS Protocol Version",
                description=f"Negotiated protocol version '{handshake.tls_version}' is deprecated and lacks modern cipher suites.",
                evidence={"tls_version": handshake.tls_version},
            )
        )

    issuer_cn = cert_info.get("issuer", {}).get("common_name") or cert_info.get("issuer", {}).get(
        "rfc4514"
    )

    result = {
        "module": "tls_analysis",
        "status": "COMPLETED",
        "https_enabled": True,
        "hostname_match": is_hostname_match,
        "chain_validation": chain_validation,
        "certificate_expired": is_expired,
        "issuer": issuer_cn,
        "tls_version": handshake.tls_version,
        "cipher": handshake.cipher,
        "certificate": cert_info,
        "findings": [f.model_dump() for f in findings],
    }
    return result, findings
