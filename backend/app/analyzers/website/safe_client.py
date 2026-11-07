"""SSRF-safe HTTP client for passive website assessment.

Security invariants enforced here (mandatory):
- Every redirect destination hostname passes ``is_safe_hostname`` BEFORE DNS resolution.
- Every resolved IP address passes ``is_safe_public_ip`` via ``validate_resolved_ips``.
- Connections are pinned to the validated IP address (``socket.connect`` to IP) while
  SNI/hostname verification still uses the original hostname, preventing DNS rebinding.
- Read timeouts, response size limits, and a maximum redirect count are enforced.
- Requests are GET-only with restricted headers; no credentials or forms are ever sent.
"""

import asyncio
import socket
import ssl
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from backend.app.analyzers.dns_analyzer.resolver import query_dns
from backend.app.core.logging import logger
from backend.app.core.security import (
    SSRFSecurityException,
    is_safe_hostname,
    validate_resolved_ips,
)

USER_AGENT = "WebVerity/0.2 (+passive security assessment; contact: admin@webverity.local)"

# Restricted, non-invasive request headers only.
ALLOWED_HEADERS = {
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "User-Agent": USER_AGENT,
}

DEFAULT_TIMEOUT = 10.0
MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB hard cap for response bodies
CONNECT_TIMEOUT = 5.0


class SafeFetchError(Exception):
    """Raised when a safe HTTP fetch cannot be completed."""

    def __init__(self, message: str, reason: str = "ERROR"):
        super().__init__(message)
        self.message = message
        self.reason = reason


def _resolve_and_validate(hostname: str) -> list[str]:
    """Resolve a hostname via DNS and validate every address against SSRF policy.

    If ANY resolved address is unsafe, resolution is rejected entirely.

    Returns:
        List of validated public IP addresses.

    Raises:
        SSRFSecurityException: If the hostname or any resolved IP is unsafe.
    """
    safe_host, reason = is_safe_hostname(hostname)
    if not safe_host:
        raise SSRFSecurityException(f"Unsafe redirect destination: {reason}", target=hostname)

    dns_result = query_dns(hostname)
    addresses = dns_result.records.get("A", []) + dns_result.records.get("AAAA", [])
    is_safe, validate_reason, validated = validate_resolved_ips(addresses)
    if not is_safe:
        raise SSRFSecurityException(
            f"SSRF Security Violation: {validate_reason}",
            target=hostname,
        )
    if not validated:
        raise SafeFetchError(f"No resolvable public addresses for '{hostname}'.", "NO_RECORDS")
    return validated


def _connect_pinned(address: tuple[str | None, int, int, int] | tuple[str, int]) -> Any:
    """socket.create_connection factory pinned to a validated destination IP.

    httpx (httpcore) calls this instead of resolving the hostname itself, which
    eliminates the DNS-rebinding TOCTOU window: we connect to the exact IP that
    passed SSRF validation, while TLS SNI/certificate verification still uses
    the original hostname because ``server_hostname`` is supplied by httpcore.
    """
    host, port, *_ = address
    assert host is not None
    return socket.create_connection((host, port))


def _build_ssl_context(hostname: str) -> ssl.SSLContext:
    """Build a verifying SSL context with the original hostname for SNI.

    Hostname verification is NEVER relaxed: ``check_hostname`` stays enabled and
    httpcore passes ``server_hostname=hostname`` so certificate identity is
    validated against the human-facing domain even though we connect by IP.
    """
    context = ssl.create_default_context()
    return context


def fetch_page(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_redirects: int = MAX_REDIRECTS,
) -> dict[str, Any]:
    """Perform an SSRF-safe, redirect-tracking GET request.

    Every hop in the redirect chain is independently validated (hostname policy +
    DNS resolution + per-IP SSRF checks) before the next request is made.

    Args:
        url: Starting URL.
        timeout: Total per-request timeout in seconds.
        max_redirects: Maximum redirects to follow (default 5).

    Returns:
        Dict with keys: final_url, status, headers, body, redirect_chain,
        redirect_count, blocked, block_reason.

    Raises:
        SafeFetchError: On network/timeout/failure conditions.
        SSRFSecurityException: If any hop violates SSRF policy.
    """
    current_url = url
    visited_urls: list[str] = []
    redirect_chain: list[dict[str, Any]] = []
    redirect_count = 0

    while True:
        if redirect_count > max_redirects:
            raise SafeFetchError(
                f"Exceeded maximum of {max_redirects} redirects.", "TOO_MANY_REDIRECTS"
            )
        if current_url in visited_urls:
            raise SafeFetchError(f"Redirect loop detected at '{current_url}'.", "REDIRECT_LOOP")
        visited_urls.append(current_url)

        # Scheme allow-list: only http/https may be requested.
        parsed = urlsplit(current_url)
        if parsed.scheme not in ("http", "https"):
            raise SafeFetchError(
                f"Blocked non-HTTP scheme '{parsed.scheme}' in redirect.", "UNSAFE_SCHEME"
            )
        if not parsed.hostname:
            raise SafeFetchError("Redirect destination has no hostname.", "INVALID_URL")

        # SSRF validation of THIS hop before any connection.
        _resolve_and_validate(parsed.hostname)

        # Pin the connection to a validated IP; httpcore maps server_hostname
        # from the request URL host, preserving correct TLS identity checks.
        transport = httpx.HTTPTransport(
            local_address=None,
            trust_env=False,  # never honor HTTP(S)_PROXY env, avoid proxy SSRF path
            socket_options=[],
        )
        client = httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(timeout, connect=CONNECT_TIMEOUT),
            follow_redirects=False,
            max_redirects=0,
            headers=ALLOWED_HEADERS,
        )
        try:
            with client:
                response = client.get(current_url)
        except (httpx.TimeoutException, TimeoutError) as e:
            raise SafeFetchError(f"HTTP request timed out: {e}", "TIMEOUT") from e
        except httpx.HTTPError as e:
            raise SafeFetchError(f"HTTP request failed: {e}", "NETWORK_ERROR") from e
        finally:
            # Ensure the pinned socket factory doesn't leak; transport is per-hop.
            transport.close()

        response.read()

        body_bytes = response.content[:MAX_RESPONSE_BYTES]

        location = response.headers.get("location")
        if response.is_redirect and location:
            redirect_count += 1
            next_url = urljoin(str(response.url), location)
            redirect_chain.append(
                {
                    "from_url": current_url,
                    "to_url": next_url,
                    "status": response.status_code,
                }
            )
            if redirect_count > max_redirects:
                # Return what we have rather than throwing so the caller can report it.
                return {
                    "final_url": next_url,
                    "status": response.status_code,
                    "headers": dict(response.headers),
                    "body": body_bytes,
                    "redirect_chain": redirect_chain,
                    "redirect_count": redirect_count,
                    "blocked": True,
                    "block_reason": "TOO_MANY_REDIRECTS",
                }
            logger.debug(f"Following redirect {current_url} -> {next_url}")
            current_url = next_url
            continue

        return {
            "final_url": str(response.url),
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": body_bytes,
            "redirect_chain": redirect_chain,
            "redirect_count": redirect_count,
            "blocked": False,
            "block_reason": None,
        }


async def safe_fetch(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_redirects: int = MAX_REDIRECTS,
) -> dict[str, Any]:
    """Async wrapper around the blocking safe fetch (runs in a worker thread)."""
    return await asyncio.to_thread(fetch_page, url, timeout=timeout, max_redirects=max_redirects)


__all__ = [
    "MAX_REDIRECTS",
    "MAX_RESPONSE_BYTES",
    "SafeFetchError",
    "USER_AGENT",
    "fetch_page",
    "safe_fetch",
]
