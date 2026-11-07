"""Asynchronous scan pipeline execution engine (Phase 2).

Coordinates URL, DNS, TLS, HTTP security, redirect, content, domain (RDAP),
and threat-intelligence analyzers with timeout boundaries and thread pooling.

Concurrency model:
- DNS / RDAP / threat-intelligence run concurrently (independent services).
- TLS uses DNS-validated IPs; HTTP/redirect/content share a single safe fetch.
"""

import asyncio
from typing import Any

from backend.app.analyzers.content_analyzer.analyzer import analyze_content
from backend.app.analyzers.dns_analyzer.analyzer import analyze_dns
from backend.app.analyzers.domain_intelligence.analyzer import analyze_domain_registration
from backend.app.analyzers.tls_analyzer.validator import validate_tls
from backend.app.analyzers.url_analyzer.features import extract_url_features
from backend.app.analyzers.url_analyzer.normalizer import NormalizedURL
from backend.app.analyzers.website.safe_client import SafeFetchError, fetch_page
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.detection.aggregator import AggregatedScanResult, aggregate_evidence
from backend.app.intelligence import check_threat_intelligence
from backend.app.schemas.evidence import Finding, Severity

MODULE_TIMEOUT = settings.SCAN_PIPELINE_TIMEOUT + 10.0  # generous per-module bound


def _failed_module(module: str, reason: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "module": module,
        "status": "FAILED",
        "error": reason,
        "findings": [],
        **(extra or {}),
    }


def _run_with_findings(fn, *args) -> tuple[dict[str, Any], list[Finding]]:
    """Run a Phase 2 analyzer, normalizing exceptions into module status."""
    try:
        return fn(*args)
    except SafeFetchError as e:
        return _failed_module(module=getattr(fn, "module_name", "unknown"), reason=e.message), []
    except Exception as e:
        logger.error(
            f"Phase 2 module error in {getattr(fn, '__module__', '?')}: {e}", exc_info=True
        )
        return _failed_module(module=getattr(fn, "module_name", "unknown"), reason=str(e)), []


async def execute_scan_pipeline(
    normalized: NormalizedURL,
    raw_url: str,
) -> AggregatedScanResult:
    """Execute all security analysis modules asynchronously.

    Ensures that failures or timeouts in one module do not interrupt the broader scan.
    """
    # 1. URL Structural and Feature Analysis
    url_findings: list[Finding] = []
    try:
        url_features, url_findings = extract_url_features(normalized, raw_url)
        url_result: dict[str, Any] = {
            "module": "url_analysis",
            "features": url_features,
            "findings": [f.model_dump() for f in url_findings],
            "status": "COMPLETED",
        }
    except Exception as e:
        logger.error(f"URL analysis module error: {e}", exc_info=True)
        url_result = {
            "module": "url_analysis",
            "features": {},
            "findings": [],
            "status": "FAILED",
        }

    # 2. DNS Infrastructure Analysis (worker thread)
    dns_findings: list[Finding] = []
    validated_ips: list[str] = []
    try:
        dns_result, dns_findings, validated_ips = await asyncio.wait_for(
            asyncio.to_thread(analyze_dns, normalized.hostname),
            timeout=settings.DNS_TIMEOUT + 2.0,
        )
    except TimeoutError:
        logger.warning(f"DNS analysis timed out for {normalized.hostname}")
        dns_findings.append(
            Finding(
                id="DNS_TIMEOUT",
                module="dns_analysis",
                severity=Severity.INFO,
                title="DNS Resolution Timeout",
                description="DNS queries timed out during pipeline execution.",
                evidence={"hostname": normalized.hostname},
            )
        )
        dns_result = {
            "module": "dns_analysis",
            "domain": normalized.hostname,
            "records": {},
            "dns_status": "TIMEOUT",
            "findings": [f.model_dump() for f in dns_findings],
        }
    except Exception as e:
        logger.error(f"DNS analysis module failure for {normalized.hostname}: {e}", exc_info=True)
        dns_result = {
            "module": "dns_analysis",
            "domain": normalized.hostname,
            "records": {},
            "dns_status": "ERROR",
            "findings": [],
        }

    # 3. TLS Certificate and Transport Inspection (worker thread)
    tls_findings: list[Finding] = []
    try:
        if normalized.scheme == "http":
            tls_result, tls_findings = validate_tls(
                scheme="http",
                hostname=normalized.hostname,
                port=normalized.port,
            )
        else:
            destination_ip = validated_ips[0] if validated_ips else None
            tls_result, tls_findings = await asyncio.wait_for(
                asyncio.to_thread(
                    validate_tls,
                    scheme="https",
                    hostname=normalized.hostname,
                    destination_ip=destination_ip,
                    port=normalized.port,
                    timeout=settings.TLS_TIMEOUT,
                ),
                timeout=settings.TLS_TIMEOUT + 2.0,
            )
    except TimeoutError:
        logger.warning(f"TLS analysis timed out for {normalized.hostname}")
        tls_findings.append(
            Finding(
                id="TLS_HANDSHAKE_ERROR",
                module="tls_analysis",
                severity=Severity.LOW,
                title="TLS Inspection Timeout",
                description="TLS handshake timed out before completion.",
                evidence={"hostname": normalized.hostname},
            )
        )
        tls_result = {
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
            "findings": [f.model_dump() for f in tls_findings],
        }
    except Exception as e:
        logger.error(f"TLS analysis module failure for {normalized.hostname}: {e}", exc_info=True)
        tls_result = {
            "module": "tls_analysis",
            "status": "FAILED",
            "https_enabled": True,
            "hostname_match": None,
            "chain_validation": "UNKNOWN",
            "certificate_expired": None,
            "issuer": None,
            "tls_version": None,
            "cipher": None,
            "certificate": None,
            "findings": [],
        }

    # ---- Phase 2 modules (run concurrently where independent) ----

    # A. Independent network intelligence: RDAP + threat intelligence run
    #    concurrently with each other (both are external service lookups).
    async def _rdap_task() -> tuple[dict[str, Any], list[Finding]]:
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(analyze_domain_registration, normalized.hostname),
                timeout=MODULE_TIMEOUT,
            )
        except TimeoutError:
            return {
                "module": "domain_intelligence",
                "status": "TIMEOUT",
                "findings": [],
            }, []
        except Exception as e:
            logger.error(f"RDAP module failure: {e}", exc_info=True)
            return _failed_module("domain_intelligence", str(e)), []

    async def _ti_task() -> tuple[dict[str, Any], list[Finding]]:
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(check_threat_intelligence, normalized),
                timeout=MODULE_TIMEOUT,
            )
        except TimeoutError:
            return {
                "module": "threat_intelligence",
                "status": "TIMEOUT",
                "findings": [],
            }, []
        except Exception as e:
            logger.error(f"Threat intelligence module failure: {e}", exc_info=True)
            return _failed_module("threat_intelligence", str(e)), []

    rdap_task = asyncio.create_task(_rdap_task())
    ti_task = asyncio.create_task(_ti_task())

    # B. HTTP fetch chain: HTTP security → redirects share one validated fetch.
    async def _web_task() -> tuple[
        dict[str, Any], dict[str, Any], list[Finding], dict[str, Any], list[Finding]
    ]:
        """Fetch once, then run HTTP-security, redirect, and content analyses."""
        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(fetch_page, normalized.normalized_url),
                timeout=MODULE_TIMEOUT,
            )
        except SafeFetchError as e:
            status = "TIMEOUT" if e.reason == "TIMEOUT" else "FAILED"
            empty = {
                "module": "http_security",
                "status": status,
                "error": e.message,
                "findings": [],
            }
            redirect_result = {
                "module": "redirect_analysis",
                "status": status,
                "error": e.message,
                "redirect_count": 0,
                "redirect_chain": [],
                "cross_domain_redirects": False,
                "redirect_loop_detected": e.reason == "REDIRECT_LOOP",
                "findings": [],
            }
            content_result = {
                "module": "content_analysis",
                "status": status,
                "error": e.message,
                "findings": [],
            }
            return empty, redirect_result, [], content_result, []
        except Exception as e:
            logger.error(f"Website fetch chain failure: {e}", exc_info=True)
            failed = _failed_module("http_security", str(e))
            return (
                failed,
                _failed_module("redirect_analysis", str(e)),
                [],
                _failed_module("content_analysis", str(e)),
                [],
            )

        # HTTP security + redirect analysis consume the fetch result directly.
        http_result, _http_findings = await asyncio.to_thread(
            _http_analysis_from_response, normalized.normalized_url, response
        )
        redirect_result, redirect_findings = await asyncio.to_thread(
            _redirect_analysis_from_response, normalized.normalized_url, response
        )

        # Content analysis needs the response body (HTML only).
        content_type = (response["headers"].get("content-type") or "").lower()
        if "html" in content_type or "text/plain" in content_type or response["status"] < 400:
            content_result, content_findings = await asyncio.to_thread(
                analyze_content,
                response["final_url"],
                response["body"],
                response["final_url"].split("://", 1)[-1].split("/", 1)[0],
            )
        else:
            content_result = {
                "module": "content_analysis",
                "status": "NOT_APPLICABLE",
                "reason": f"Content type '{content_type}' is not HTML.",
                "findings": [],
            }
            content_findings = []
        return http_result, redirect_result, redirect_findings, content_result, content_findings

    web_task = asyncio.create_task(_web_task())

    (rdap_result, rdap_findings) = await rdap_task
    (ti_result, ti_findings) = await ti_task
    (
        http_result,
        redirect_result,
        redirect_findings,
        content_result,
        content_findings,
    ) = await web_task
    # HTTP-security findings are reconstructed from the persisted result dict.
    http_findings = [Finding(**f) for f in http_result.get("findings", [])]

    phase2_results = {
        "http_security": http_result,
        "redirect_analysis": redirect_result,
        "content_analysis": content_result,
        "domain_intelligence": rdap_result,
        "threat_intelligence": ti_result,
    }
    phase2_findings = (
        http_findings + redirect_findings + content_findings + rdap_findings + ti_findings
    )

    # 4. Evidence Aggregation & Advanced Risk Correlation
    aggregated = aggregate_evidence(
        url_result=url_result,
        url_findings=url_findings,
        dns_result=dns_result,
        dns_findings=dns_findings,
        tls_result=tls_result,
        tls_findings=tls_findings,
        phase2_results=phase2_results,
        phase2_findings=phase2_findings,
    )

    return aggregated


def _http_analysis_from_response(
    url: str, response: dict[str, Any]
) -> tuple[dict[str, Any], list[Finding]]:
    """Adapt an already-fetched response into the HTTP security analyzer's flow."""
    from urllib.parse import urlsplit

    from backend.app.analyzers.website.http_analyzer import SECURITY_HEADERS, _analyze_cookies

    findings: list[Finding] = []
    headers = response["headers"]
    final_url = response["final_url"]
    final_parsed = urlsplit(final_url)

    security_headers: dict[str, Any] = {}
    lowered = {k.lower(): v for k, v in headers.items()}
    csp_present = "content-security-policy" in lowered
    for header_name, meta in SECURITY_HEADERS.items():
        key = header_name.lower()
        value = lowered.get(key)
        if value:
            security_headers[header_name] = value[:200]
        else:
            if (
                header_name == "X-Frame-Options"
                and csp_present
                and "frame-ancestors" in lowered.get("content-security-policy", "").lower()
            ):
                security_headers[header_name] = "(satisfied by CSP frame-ancestors)"
                continue
            security_headers[header_name] = None
            findings.append(
                Finding(
                    id=meta["id"],
                    module="http_security",
                    severity=meta["severity"],
                    title=meta["title"],
                    description=meta["description"],
                    evidence={"header": header_name},
                )
            )

    https_enabled = final_parsed.scheme == "https"
    if not https_enabled:
        findings.append(
            Finding(
                id="HTTP_NO_HTTPS",
                module="http_security",
                severity=Severity.LOW,
                title="Site Served Over Plain HTTP",
                description=(
                    "Traffic is unencrypted. Security configuration weakness, "
                    "not phishing evidence."
                ),
                evidence={"final_url": final_url},
            )
        )

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
                module="http_security",
                severity=Severity.INFO,
                title="Server Version Disclosure",
                description="The Server header reveals software versions. Security weakness.",
                evidence={"server": server_value},
            )
        )

    cookie_analysis = _analyze_cookies(headers)
    if cookie_analysis["any_missing_secure"]:
        findings.append(
            Finding(
                id="HTTP_COOKIE_MISSING_SECURE",
                module="http_security",
                severity=Severity.LOW,
                title="Cookie Without Secure Flag",
                description="A cookie lacks the Secure attribute. Security weakness.",
                evidence={"cookie_count": cookie_analysis["count"]},
            )
        )
    if cookie_analysis["any_missing_httponly"]:
        findings.append(
            Finding(
                id="HTTP_COOKIE_MISSING_HTTPONLY",
                module="http_security",
                severity=Severity.LOW,
                title="Cookie Without HttpOnly Flag",
                description="A cookie lacks the HttpOnly attribute. Security weakness.",
                evidence={"cookie_count": cookie_analysis["count"]},
            )
        )
    if cookie_analysis["any_missing_samesite"]:
        findings.append(
            Finding(
                id="HTTP_COOKIE_MISSING_SAMESITE",
                module="http_security",
                severity=Severity.INFO,
                title="Cookie Without SameSite Attribute",
                description="A cookie lacks the SameSite attribute. Security weakness.",
                evidence={"cookie_count": cookie_analysis["count"]},
            )
        )

    content_type = headers.get("content-type")
    if content_type and "text/html" not in content_type.lower():
        findings.append(
            Finding(
                id="HTTP_NON_HTML_ROOT",
                module="http_security",
                severity=Severity.INFO,
                title="Non-HTML Root Response",
                description=f"The root URL responds with '{content_type}'.",
                evidence={"content_type": content_type},
            )
        )

    if response["status"] >= 400:
        findings.append(
            Finding(
                id="HTTP_ERROR_STATUS",
                module="http_security",
                severity=Severity.INFO,
                title="HTTP Error Status at Root",
                description=f"The target responded with HTTP {response['status']}.",
                evidence={"http_status": response["status"]},
            )
        )

    result = {
        "module": "http_security",
        "status": "COMPLETED",
        "http_status": response["status"],
        "https_enabled": https_enabled,
        "final_url": final_url,
        "content_type": content_type,
        "content_length": headers.get("content-length"),
        "security_headers": security_headers,
        "cookie_analysis": cookie_analysis,
        "server_information": server_information,
        "findings": [f.model_dump() for f in findings],
    }
    return result, findings


def _redirect_analysis_from_response(
    url: str, response: dict[str, Any]
) -> tuple[dict[str, Any], list[Finding]]:
    """Adapt an already-fetched response into the redirect analyzer's flow."""
    from urllib.parse import urlsplit

    from backend.app.analyzers.redirect_analyzer.analyzer import (
        _is_benign_service,
        _is_known_shortener,
        _registrable_domain,
    )

    findings: list[Finding] = []
    chain = response["redirect_chain"]
    start_parsed = urlsplit(url)
    final_parsed = urlsplit(response["final_url"])
    original_domain = _registrable_domain(start_parsed.hostname)
    final_domain = _registrable_domain(final_parsed.hostname)
    cross_domain = bool(original_domain and final_domain and original_domain != final_domain)

    https_downgrade = False
    hop_domains: list[str] = []
    for hop in chain:
        hop_parsed = urlsplit(hop["to_url"])
        hop_domains.append(_registrable_domain(hop_parsed.hostname))
        if hop_parsed.scheme == "http":
            https_downgrade = True

    if https_downgrade:
        findings.append(
            Finding(
                id="REDIRECT_HTTPS_DOWNGRADE",
                module="redirect_analysis",
                severity=Severity.MEDIUM,
                title="HTTPS Downgrade in Redirect Chain",
                description=(
                    "A redirect moved traffic from HTTPS to plain HTTP. Reason: "
                    "HTTPS-to-HTTP transitions are anomalous for well-configured sites."
                ),
                evidence={"chain": chain},
            )
        )

    if cross_domain:
        benign = _is_benign_service(final_parsed.hostname)
        shortener_used = any(_is_known_shortener(h) for h in hop_domains) or _is_known_shortener(
            start_parsed.hostname
        )
        findings.append(
            Finding(
                id="REDIRECT_CROSS_DOMAIN",
                module="redirect_analysis",
                severity=Severity.INFO if benign else Severity.LOW,
                title="Cross-Domain Redirect",
                description=(
                    f"The redirect chain leaves '{original_domain}' and ends at "
                    f"'{final_domain}'. Reason: destination domain differs from the "
                    f"submitted domain — common for legitimate CDNs and payment services, "
                    f"not proof of maliciousness."
                ),
                evidence={
                    "original_domain": original_domain,
                    "final_domain": final_domain,
                    "known_benign_service": benign,
                },
            )
        )
        if shortener_used and not benign:
            findings.append(
                Finding(
                    id="REDIRECT_SHORTENER",
                    module="redirect_analysis",
                    severity=Severity.LOW,
                    title="URL Shortener in Redirect Chain",
                    description=(
                        "The chain passes through a public URL shortener. Reason: "
                        "shorteners hide the true destination from users."
                    ),
                    evidence={"chain_domains": hop_domains},
                )
            )

    if response["blocked"]:
        findings.append(
            Finding(
                id="REDIRECT_TOO_MANY",
                module="redirect_analysis",
                severity=Severity.LOW,
                title="Excessive Redirect Chain",
                description=(
                    "More than 5 redirects were requested; following was halted. Reason: "
                    "long chains evade static analysis."
                ),
                evidence={"redirect_count": response["redirect_count"]},
            )
        )

    if len(chain) >= 3:
        findings.append(
            Finding(
                id="REDIRECT_LONG_CHAIN",
                module="redirect_analysis",
                severity=Severity.INFO,
                title="Multi-Hop Redirect Chain",
                description=f"The redirect chain contains {len(chain)} hops.",
                evidence={"hops": len(chain)},
            )
        )

    result = {
        "module": "redirect_analysis",
        "status": "COMPLETED",
        "redirect_count": response["redirect_count"],
        "redirect_chain": chain,
        "final_url": response["final_url"],
        "final_domain": final_parsed.hostname or final_domain,
        "original_domain": original_domain,
        "cross_domain_redirects": cross_domain,
        "redirect_loop_detected": False,
        "unsafe_redirect_blocked": False,
        "findings": [f.model_dump() for f in findings],
    }
    return result, findings
