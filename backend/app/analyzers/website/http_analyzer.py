"""Module 1 — HTTP security header and transport posture analyzer.

Passive assessment of HTTP response headers, cookie attributes, and server
information disclosure. Missing security headers are recorded as SECURITY
CONFIGURATION WEAKNESSES, never as phishing proof.
"""

from typing import Any
from urllib.parse import urlsplit

from backend.app.analyzers.website.safe_client import SafeFetchError, fetch_page
from backend.app.core.logging import logger
from backend.app.core.security import SSRFSecurityException
from backend.app.schemas.evidence import Finding, Severity

MODULE_NAME = "http_security"

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "id": "HTTP_MISSING_HSTS",
        "title": "Missing Strict-Transport-Security Header",
        "description": (
            "The site does not advertise HSTS, allowing downgrade attacks to strip "
            "HTTPS. This is a security configuration weakness, not phishing evidence."
        ),
        "severity": Severity.LOW,
    },
    "Content-Security-Policy": {
        "id": "HTTP_MISSING_CSP",
        "title": "Missing Content-Security-Policy Header",
        "description": (
            "No CSP is declared, leaving the page without script-injection controls. "
            "Security configuration weakness only."
        ),
        "severity": Severity.LOW,
    },
    "X-Content-Type-Options": {
        "id": "HTTP_MISSING_XCONTENTTYPE",
        "title": "Missing X-Content-Type-Options Header",
        "description": (
            "Responses may be MIME-sniffed by browsers. Security configuration weakness."
        ),
        "severity": Severity.LOW,
    },
    "X-Frame-Options": {
        "id": "HTTP_MISSING_XFRAMEOPTIONS",
        "title": "Missing X-Frame-Options / frame-ancestors",
        "description": (
            "Page can potentially be framed (clickjacking exposure). Note: CSP "
            "frame-ancestors satisfies this. Security configuration weakness."
        ),
        "severity": Severity.LOW,
    },
    "Referrer-Policy": {
        "id": "HTTP_MISSING_REFERRER_POLICY",
        "title": "Missing Referrer-Policy Header",
        "description": (
            "Referrer data may leak full URLs to third parties. Security configuration weakness."
        ),
        "severity": Severity.INFO,
    },
    "Permissions-Policy": {
        "id": "HTTP_MISSING_PERMISSIONS_POLICY",
        "title": "Missing Permissions-Policy Header",
        "description": (
            "No browser feature restrictions declared. Security configuration weakness."
        ),
        "severity": Severity.INFO,
    },
}

SUSPICIOUS_SERVER_PATTERNS = ("nginx/0.", "apache/1.", "iis/5.", "iis/6.")


def _analyze_cookies(headers: dict[str, str]) -> dict[str, Any]:
    """Inspect Set-Cookie attributes for Secure/HttpOnly/SameSite flags."""
    raw_cookies = headers.get_list("set-cookie") if hasattr(headers, "get_list") else []
    if not raw_cookies:
        raw_cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]

    cookie_report: dict[str, Any] = {
        "count": len(raw_cookies),
        "cookies": [],
        "any_missing_secure": False,
        "any_missing_httponly": False,
        "any_missing_samesite": False,
    }

    for raw in raw_cookies[:20]:  # cap analysis volume
        name = raw.split("=", 1)[0].strip()
        parts = [p.strip().lower() for p in raw.split(";")][1:]
        entry = {
            "name": name,
            "secure": "secure" in parts,
            "httponly": "httponly" in parts,
            "samesite": None,
        }
        for part in parts:
            if part.startswith("samesite"):
                entry["samesite"] = part.split("=", 1)[-1].strip()
        if not entry["secure"]:
            cookie_report["any_missing_secure"] = True
        if not entry["httponly"]:
            cookie_report["any_missing_httponly"] = True
        if entry["samesite"] is None:
            cookie_report["any_missing_samesite"] = True
        cookie_report["cookies"].append(entry)

    return cookie_report


def analyze_http_security(start_url: str) -> tuple[dict[str, Any], list[Finding]]:
    """Fetch the target page safely and assess its HTTP security posture.

    Args:
        start_url: Target URL to fetch.

    Returns:
        Tuple of (module_result_dict, findings_list).
    """
    parsed = urlsplit(start_url)
    submitted_scheme = parsed.scheme or "http"

    findings: list[Finding] = []
    security_headers: dict[str, Any] = {}
    server_information: dict[str, Any] = {}
    http_status: int | None = None
    https_enabled = submitted_scheme == "https"
    status = "COMPLETED"
    content_type = None
    content_length = None

    try:
        response = fetch_page(start_url)
    except SSRFSecurityException:
        # Unsafe redirect/IP: the redirect analyzer records the block; this module skips.
        return {
            "module": MODULE_NAME,
            "status": "SKIPPED",
            "http_status": None,
            "https_enabled": https_enabled,
            "security_headers": {},
            "cookie_analysis": {},
            "server_information": {},
            "findings": [],
        }, findings
    except SafeFetchError as e:
        logger.warning(f"HTTP security analyzer could not fetch '{start_url}': {e.message}")
        status = "TIMEOUT" if e.reason == "TIMEOUT" else "FAILED"
        return {
            "module": MODULE_NAME,
            "status": status,
            "http_status": None,
            "https_enabled": https_enabled,
            "security_headers": {},
            "cookie_analysis": {},
            "server_information": {},
            "findings": [],
        }, findings

    headers = response["headers"]
    final_url = response["final_url"]
    http_status = response["status"]
    final_parsed = urlsplit(final_url)
    https_enabled = final_parsed.scheme == "https"
    content_type = headers.get("content-type")
    content_length = headers.get("content-length")

    # --- Security headers presence ---
    lowered_headers = {k.lower(): v for k, v in headers.items()}
    csp_present = "content-security-policy" in lowered_headers
    for header_name, meta in SECURITY_HEADERS.items():
        key = header_name.lower()
        value = lowered_headers.get(key)
        if value:
            security_headers[header_name] = value[:200]
        else:
            # X-Frame-Options is satisfied by CSP frame-ancestors
            if (
                header_name == "X-Frame-Options"
                and csp_present
                and "frame-ancestors" in lowered_headers.get("content-security-policy", "").lower()
            ):
                security_headers[header_name] = "(satisfied by CSP frame-ancestors)"
                continue
            security_headers[header_name] = None
            findings.append(
                Finding(
                    id=meta["id"],
                    module=MODULE_NAME,
                    severity=meta["severity"],
                    title=meta["title"],
                    description=meta["description"],
                    evidence={"header": header_name},
                )
            )

    # --- HTTPS enforcement check ---
    if not https_enabled:
        findings.append(
            Finding(
                id="HTTP_NO_HTTPS",
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="Site Served Over Plain HTTP",
                description=(
                    "Traffic is unencrypted, exposing content and cookies to network "
                    "observers. Security configuration weakness, not phishing evidence."
                ),
                evidence={"final_url": final_url},
            )
        )

    # --- Server information disclosure ---
    server_value = headers.get("server")
    server_information = {
        "server": server_value,
        "powered_by": headers.get("x-powered-by"),
        "discloses_version": bool(server_value and any(c.isdigit() for c in server_value)),
    }
    if server_information["discloses_version"]:
        findings.append(
            Finding(
                id="HTTP_SERVER_DISCLOSURE",
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="Server Version Disclosure",
                description=(
                    "The Server header reveals software and version details, aiding "
                    "targeted attacks. Security configuration weakness."
                ),
                evidence={"server": server_value},
            )
        )
    if server_value and any(p in server_value.lower() for p in SUSPICIOUS_SERVER_PATTERNS):
        findings.append(
            Finding(
                id="HTTP_OUTDATED_SERVER",
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="Outdated Server Software Signature",
                description="Response advertises a very old server software version.",
                evidence={"server": server_value},
            )
        )

    # --- Cookie security ---
    cookie_analysis = _analyze_cookies(headers)
    if cookie_analysis["any_missing_secure"]:
        findings.append(
            Finding(
                id="HTTP_COOKIE_MISSING_SECURE",
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="Cookie Without Secure Flag",
                description=(
                    "One or more cookies lack the Secure attribute and may transit "
                    "unencrypted channels. Security configuration weakness."
                ),
                evidence={"cookie_count": cookie_analysis["count"]},
            )
        )
    if cookie_analysis["any_missing_httponly"]:
        findings.append(
            Finding(
                id="HTTP_COOKIE_MISSING_HTTPONLY",
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="Cookie Without HttpOnly Flag",
                description=(
                    "One or more cookies are readable by client-side scripts, "
                    "increasing session-theft impact. Security configuration weakness."
                ),
                evidence={"cookie_count": cookie_analysis["count"]},
            )
        )
    if cookie_analysis["any_missing_samesite"]:
        findings.append(
            Finding(
                id="HTTP_COOKIE_MISSING_SAMESITE",
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="Cookie Without SameSite Attribute",
                description=(
                    "SameSite is not declared for at least one cookie, widening CSRF "
                    "exposure. Security configuration weakness."
                ),
                evidence={"cookie_count": cookie_analysis["count"]},
            )
        )

    # --- Unexpected content types ---
    if content_type and any(
        ext in content_type.lower()
        for ext in ("octet-stream", "application/x-", "application/msdownload")
    ):
        findings.append(
            Finding(
                id="HTTP_UNEXPECTED_CONTENT_TYPE",
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="Executable or Unusual Content Type",
                description=(
                    "The root URL returns binary/executable content instead of HTML, "
                    "a pattern seen in malware delivery pages."
                ),
                evidence={"content_type": content_type},
            )
        )
    elif content_type and "text/html" not in content_type.lower():
        findings.append(
            Finding(
                id="HTTP_NON_HTML_ROOT",
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="Non-HTML Root Response",
                description=f"The root URL responds with '{content_type}' rather than HTML.",
                evidence={"content_type": content_type},
            )
        )

    if http_status and http_status >= 400:
        findings.append(
            Finding(
                id="HTTP_ERROR_STATUS",
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="HTTP Error Status at Root",
                description=f"The target responded with HTTP {http_status}.",
                evidence={"http_status": http_status},
            )
        )

    result: dict[str, Any] = {
        "module": MODULE_NAME,
        "status": status,
        "http_status": http_status,
        "https_enabled": https_enabled,
        "final_url": final_url,
        "content_type": content_type,
        "content_length": content_length,
        "security_headers": security_headers,
        "cookie_analysis": cookie_analysis,
        "server_information": server_information,
        "findings": [f.model_dump() for f in findings],
    }
    return result, findings
