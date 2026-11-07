"""Module 2 — Redirect chain analyzer.

Tracks the full redirect chain of a fetch, classifying cross-domain transitions,
HTTPS downgrades, loops, shortener hops, and unsafe (blocked) destinations.
Cross-domain redirects are noted as suspicious-characteristic findings only —
CDN/auth/payment hops are legitimate and common — with an explicit reason in
every finding.
"""

from typing import Any
from urllib.parse import urlsplit

from backend.app.analyzers.website.safe_client import SafeFetchError, fetch_page
from backend.app.core.logging import logger
from backend.app.core.security import SSRFSecurityException
from backend.app.schemas.evidence import Finding, Severity

MODULE_NAME = "redirect_analysis"

MAX_REDIRECTS = 5

# Public URL shorteners whose final destination commonly differs from the submitted one.
KNOWN_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
    "s.id",
}

# Common legitimate cross-domain service bases whose redirects are routine.
BENIGN_SERVICE_SUFFIXES = (
    "google.com",
    "accounts.google.com",
    "cloudflare.com",
    "cloudflareinsights.com",
    "cloudfront.net",
    "akamaihd.net",
    "akamaized.net",
    "amazonaws.com",
    "azurewebsites.net",
    "edgekey.net",
    "edgesuite.net",
    "doubleclick.net",
    "facebook.com",
    "apple.com",
    "microsoft.com",
    "msecnd.net",
    "recaptcha.net",
    "gstatic.com",
    "github.io",
)


def _registrable_domain(hostname: str | None) -> str:
    """Very small suffix heuristic: last two labels (good enough for comparison)."""
    if not hostname:
        return ""
    parts = hostname.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    return ".".join(parts[-2:])


def _is_known_shortener(hostname: str | None) -> bool:
    if not hostname:
        return False
    host = hostname.lower()
    bare = host[4:] if host.startswith("www.") else host
    return bare in KNOWN_SHORTENERS or host in KNOWN_SHORTENERS


def _is_benign_service(hostname: str | None) -> bool:
    if not hostname:
        return False
    host = hostname.lower()
    return any(host == s or host.endswith("." + s) for s in BENIGN_SERVICE_SUFFIXES)


def analyze_redirects(start_url: str) -> tuple[dict[str, Any], list[Finding]]:
    """Follow redirects safely and classify the transition chain.

    Args:
        start_url: Submitted target URL.

    Returns:
        Tuple of (module_result_dict, findings_list).
    """
    findings: list[Finding] = []
    start_parsed = urlsplit(start_url)
    original_domain = _registrable_domain(start_parsed.hostname)

    try:
        response = fetch_page(start_url)
    except SSRFSecurityException as e:
        # A redirect attempted to leave for a private/loopback/metadata target.
        findings.append(
            Finding(
                id="REDIRECT_SSRF_BLOCKED",
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="Unsafe Redirect Destination Blocked",
                description=(
                    f"A redirect attempted to reach a prohibited internal/private destination "
                    f"and was blocked by SSRF policy. Reason: {e.message}"
                ),
                evidence={"start_url": start_url},
            )
        )
        return {
            "module": MODULE_NAME,
            "status": "COMPLETED",
            "redirect_count": 0,
            "redirect_chain": [],
            "final_domain": original_domain,
            "cross_domain_redirects": False,
            "redirect_loop_detected": False,
            "unsafe_redirect_blocked": True,
            "findings": [f.model_dump() for f in findings],
        }, findings
    except SafeFetchError as e:
        logger.warning(f"Redirect analysis could not fetch '{start_url}': {e.message}")
        status = "TIMEOUT" if e.reason == "TIMEOUT" else "FAILED"
        loop_detected = e.reason == "REDIRECT_LOOP"
        if loop_detected:
            findings.append(
                Finding(
                    id="REDIRECT_LOOP",
                    module=MODULE_NAME,
                    severity=Severity.MEDIUM,
                    title="Redirect Loop Detected",
                    description=(
                        "The server redirected back to a previously visited URL, creating an "
                        "infinite loop. Reason: repeated destinations indicate misconfiguration "
                        "or intentional redirect abuse."
                    ),
                    evidence={"start_url": start_url},
                )
            )
        return {
            "module": MODULE_NAME,
            "status": status,
            "redirect_count": 0,
            "redirect_chain": [],
            "final_domain": original_domain,
            "cross_domain_redirects": False,
            "redirect_loop_detected": loop_detected,
            "findings": [f.model_dump() for f in findings],
        }, findings

    chain = response["redirect_chain"]
    final_parsed = urlsplit(response["final_url"])
    final_domain = _registrable_domain(final_parsed.hostname)
    cross_domain = bool(original_domain and final_domain and original_domain != final_domain)

    # Per-hop classification
    hop_domains: list[str] = []
    https_downgrade = False
    for hop in chain:
        hop_parsed = urlsplit(hop["to_url"])
        hop_domain = _registrable_domain(hop_parsed.hostname)
        hop_domains.append(hop_domain)

        # HTTPS downgrade: https hop landing on http
        if hop_parsed.scheme == "http" and hop.get("status") in (301, 302, 307, 308):
            https_downgrade = True

    if https_downgrade:
        findings.append(
            Finding(
                id="REDIRECT_HTTPS_DOWNGRADE",
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="HTTPS Downgrade in Redirect Chain",
                description=(
                    "A redirect moved traffic from HTTPS to plain HTTP, exposing it to "
                    "network tampering. Reason: HTTPS-to-HTTP transitions are anomalous for "
                    "well-configured sites."
                ),
                evidence={"chain": chain},
            )
        )

    if cross_domain:
        benign = _is_benign_service(final_parsed.hostname)
        shortener_used = any(_is_known_shortener(h) for h in hop_domains) or _is_known_shortener(
            start_parsed.hostname
        )
        severity = Severity.INFO if benign else Severity.LOW
        findings.append(
            Finding(
                id="REDIRECT_CROSS_DOMAIN",
                module=MODULE_NAME,
                severity=severity,
                title="Cross-Domain Redirect",
                description=(
                    f"The redirect chain leaves the submitted domain '{original_domain}' and "
                    f"ends at '{final_domain}'. Reason: destination domain differs from the "
                    f"submitted domain. This is common for legitimate CDNs, authentication "
                    f"providers and payment services; treated as a characteristic, not proof "
                    f"of maliciousness."
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
                    module=MODULE_NAME,
                    severity=Severity.LOW,
                    title="URL Shortener in Redirect Chain",
                    description=(
                        "The chain passes through a public URL shortener, concealing the "
                        "true destination. Reason: shorteners are frequently abused to hide "
                        "phishing endpoints behind benign-looking links."
                    ),
                    evidence={"chain_domains": hop_domains},
                )
            )
    elif _is_known_shortener(start_parsed.hostname) and not cross_domain:
        findings.append(
            Finding(
                id="REDIRECT_SHORTENER",
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="Submitted URL Shortener",
                description=(
                    "The submitted URL is a shortener that resolves to a same-domain "
                    "destination. Reason: shortened links obscure the final target."
                ),
                evidence={"final_url": response["final_url"]},
            )
        )

    if response["blocked"]:
        findings.append(
            Finding(
                id="REDIRECT_TOO_MANY",
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="Excessive Redirect Chain",
                description=(
                    f"More than {MAX_REDIRECTS} redirects were requested; following was "
                    f"halted for safety. Reason: long chains are used to evade static "
                    f"analysis and frustrate users."
                ),
                evidence={"redirect_count": response["redirect_count"]},
            )
        )

    if len(chain) >= 3:
        findings.append(
            Finding(
                id="REDIRECT_LONG_CHAIN",
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="Multi-Hop Redirect Chain",
                description=(
                    f"The redirect chain contains {len(chain)} hops. Reason: multi-hop "
                    f"chaining is a mild obfuscation characteristic."
                ),
                evidence={"hops": len(chain)},
            )
        )

    result: dict[str, Any] = {
        "module": MODULE_NAME,
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
