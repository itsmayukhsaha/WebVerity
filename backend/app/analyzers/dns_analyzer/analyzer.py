"""DNS analysis engine.

Coordinates DNS queries, checks for SSRF-unsafe destinations in resolved records,
and evaluates infrastructure indicators.
"""

from typing import Any

from backend.app.analyzers.dns_analyzer.resolver import query_dns
from backend.app.core.security import is_ip_address, is_safe_public_ip
from backend.app.schemas.evidence import Finding, Severity


def analyze_dns(domain: str) -> tuple[dict[str, Any], list[Finding], list[str]]:
    """Perform full DNS infrastructure analysis for a domain or IP.

    Args:
        domain: Target domain or IP address string.

    Returns:
        Tuple of:
            - DNS module output dictionary
            - List of security findings
            - List of validated safe public destination IPs (for pinned TLS connection)
    """
    findings: list[Finding] = []
    validated_public_ips: list[str] = []

    # Handle direct IP targets
    if is_ip_address(domain):
        clean_ip = domain.strip("[]")
        safe, reason = is_safe_public_ip(clean_ip)
        records: dict[str, list[str]] = {
            "A": [clean_ip] if ":" not in clean_ip else [],
            "AAAA": [clean_ip] if ":" in clean_ip else [],
            "CNAME": [],
            "NS": [],
            "MX": [],
            "TXT": [],
        }

        if not safe:
            findings.append(
                Finding(
                    id="DNS_SSRF_UNSAFE_IP",
                    module="dns_analysis",
                    severity=Severity.CRITICAL,
                    title="Direct Target is an Unsafe/Private Address",
                    description=f"Destination IP '{clean_ip}' violates SSRF boundaries: {reason}",
                    evidence={"ip": clean_ip, "reason": reason},
                )
            )
            status = "SSRF_BLOCKED"
        else:
            validated_public_ips.append(clean_ip)
            status = "RESOLVED"

        result = {
            "module": "dns_analysis",
            "domain": domain,
            "records": records,
            "dns_status": status,
            "findings": [f.model_dump() for f in findings],
        }
        return result, findings, validated_public_ips

    # Standard domain name resolution
    dns_res = query_dns(domain)
    records = dns_res.records
    status = dns_res.status

    # Check for resolution outcomes
    if status == "NXDOMAIN":
        findings.append(
            Finding(
                id="DNS_NXDOMAIN",
                module="dns_analysis",
                severity=Severity.HIGH,
                title="Non-Existent Domain (NXDOMAIN)",
                description=f"The domain '{domain}' does not exist in authoritative DNS. Common with abandoned, taken-down, or newly minted phishing domains.",
                evidence={"domain": domain},
            )
        )
    elif status == "TIMEOUT":
        findings.append(
            Finding(
                id="DNS_TIMEOUT",
                module="dns_analysis",
                severity=Severity.INFO,
                title="DNS Resolution Timeout",
                description="Nameserver queries timed out before completing. Analysis reflects partial or unavailable information.",
                evidence={"domain": domain},
            )
        )
    elif status == "NO_RECORDS":
        findings.append(
            Finding(
                id="DNS_NO_RECORDS",
                module="dns_analysis",
                severity=Severity.MEDIUM,
                title="Missing Address Records",
                description=f"Domain '{domain}' resolved with no active A or AAAA address records, indicating inactive or staging infrastructure.",
                evidence={"domain": domain},
            )
        )
    elif status == "RESOLVED":
        # SSRF Validation: inspect every resolved A and AAAA address
        all_resolved_ips = records.get("A", []) + records.get("AAAA", [])
        has_unsafe_ip = False

        for ip in all_resolved_ips:
            safe, reason = is_safe_public_ip(ip)
            if not safe:
                has_unsafe_ip = True
                findings.append(
                    Finding(
                        id="DNS_SSRF_UNSAFE_IP",
                        module="dns_analysis",
                        severity=Severity.CRITICAL,
                        title="Domain Resolves to Unsafe/Internal IP",
                        description=f"Host resolved to forbidden destination '{ip}': {reason}. Blocked to protect internal infrastructure against SSRF/DNS rebinding.",
                        evidence={"domain": domain, "resolved_ip": ip, "reason": reason},
                    )
                )
            else:
                validated_public_ips.append(ip)

        if has_unsafe_ip:
            status = "SSRF_BLOCKED"
            # Purge unsafe records to prevent accidental connection
            validated_public_ips.clear()

        # Check for MX records (absence in business domains is informative, but not inherently malicious)
        if not records.get("MX"):
            findings.append(
                Finding(
                    id="DNS_NO_MX_RECORDS",
                    module="dns_analysis",
                    severity=Severity.INFO,
                    title="No Mail Exchange (MX) Records",
                    description="The domain does not publish mail exchanger records. Common for disposable landing pages, though not malicious on its own.",
                    evidence={"domain": domain},
                )
            )

    result = {
        "module": "dns_analysis",
        "domain": domain,
        "records": records,
        "dns_status": status,
        "findings": [f.model_dump() for f in findings],
    }
    return result, findings, validated_public_ips
