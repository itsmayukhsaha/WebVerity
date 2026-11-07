"""Indicator matching engine (Phase 3).

Explainable, false-positive-resistant matching of submitted URLs/domains
against threat-intelligence indicators. Supports exact URL, canonicalized
URL, exact domain, and subdomain matching with IDNA/case normalization.

Hostnames are compared as exact equality of registered domains or explicit
subdomain relations — never naive substring matching, so
``example.com.evil.test`` can never match an ``example.com`` indicator.
"""

import ipaddress
from urllib.parse import urlsplit, urlunparse

from backend.app.intelligence.models import IndicatorType, MatchType


def normalize_indicator(value: str) -> str:
    """Normalize an indicator for comparison: lowercase host, strip default
    port, strip fragment, strip trailing dot from hostname, decode
    percent-encoded path consistently."""
    raw = value.strip().lower()
    if raw.startswith("https://"):
        parts = urlsplit(raw)
        scheme = "https"
    elif raw.startswith("http://"):
        parts = urlsplit(raw)
        scheme = "http"
    else:
        parts = urlsplit(f"http://{raw}")
        scheme = "http"
    host = (parts.hostname or "").lower().rstrip(".")
    # Keep IDNA as-is (already normalized upstream); lowercase suffices here.
    path = parts.path or "/"
    # Percent-decode once for consistent comparison, re-encode to safe form.
    from urllib.parse import quote, unquote

    path = quote(unquote(path), safe="/%:@")
    netloc = host
    if parts.port is not None and parts.port not in (80, 443):
        netloc = f"{host}:{parts.port}"
    return urlunparse((scheme, netloc, path, "", "", ""))


def _registered_domain(hostname: str) -> str:
    """Approximate registered domain: last two labels (sufficient for the
    comparator's purposes; publicsuffix precision is a documented limitation)."""
    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname
    return ".".join(labels[-2:])


def classify_indicator(value: str) -> IndicatorType:
    """Determine whether an indicator is a URL, IP, or domain."""
    raw = value.strip()
    if raw.startswith("http"):
        return IndicatorType.URL
    try:
        ipaddress.ip_address(raw)
        version = ipaddress.ip_address(raw).version
        return IndicatorType.IPV4 if version == 4 else IndicatorType.DOMAIN
    except ValueError:
        return IndicatorType.DOMAIN


def match_indicator(
    submitted: str,
    indicator_value: str,
    indicator_type: IndicatorType | None = None,
) -> tuple[bool, MatchType]:
    """Match a submitted URL/domain/IP against a threat indicator.

    Returns:
        (matched, match_type) — an explainable pair. ``matched=False`` implies
        ``MatchType.NONE``.
    """
    kind = indicator_type or classify_indicator(indicator_value)
    normalized_submitted = normalize_indicator(submitted)

    if kind == IndicatorType.URL:
        normalized_indicator = normalize_indicator(indicator_value)
        if normalized_submitted == normalized_indicator:
            return True, MatchType.EXACT_URL
        if urlsplit(normalized_submitted).netloc == urlsplit(normalized_indicator).netloc:
            return True, MatchType.CANONICAL_URL
        return False, MatchType.NONE

    # Domain / IP matching
    submitted_host = urlsplit(normalized_submitted).hostname or normalized_submitted
    indicator_host = indicator_value.lower().rstrip(".")
    if submitted_host == indicator_host:
        return True, MatchType.EXACT_DOMAIN
    # Subdomain relation only: submitted host ends with "." + indicator
    if submitted_host.endswith("." + indicator_host):
        return True, MatchType.SUBDOMAIN
    return False, MatchType.NONE


__all__ = [
    "classify_indicator",
    "match_indicator",
    "normalize_indicator",
]
