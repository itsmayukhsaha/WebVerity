"""URL normalization module.

Handles IDNA encoding, punycode identification, default port removal,
fragment stripping, path normalization, and query parameter redaction.
"""

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import idna


@dataclass
class NormalizedURL:
    """Structured container for normalized URL components."""

    normalized_url: str
    redacted_url: str
    scheme: str
    hostname: str
    unicode_hostname: str
    has_punycode: bool
    port: int
    path: str
    query: str


def redact_query_parameters(query_string: str) -> str:
    """Mask parameter values in a query string to avoid storing credentials or PII.

    Args:
        query_string: Raw query string (without leading '?').

    Returns:
        Redacted query string, e.g. 'token=[REDACTED]&user=[REDACTED]'.
    """
    if not query_string:
        return ""

    try:
        pairs = parse_qsl(query_string, keep_blank_values=True)
        if not pairs:
            return ""
        redacted_pairs = [(k, "[REDACTED]") for k, _ in pairs]
        return urlencode(redacted_pairs)
    except Exception:
        return "[REDACTED]"


def normalize_url(raw_url: str) -> NormalizedURL:
    """Normalize a raw URL into standard form.

    Actions:
    - Lowercase scheme and host.
    - IDNA ASCII encode host (punycode conversion where applicable).
    - Strip default ports (80 for http, 443 for https).
    - Remove URL fragments.
    - Default empty path to '/'.
    - Generate query-redacted URL for safe persistence.

    Args:
        raw_url: Input URL string.

    Returns:
        NormalizedURL dataclass.
    """
    clean_url = raw_url.strip()
    parsed = urlparse(clean_url)

    scheme = parsed.scheme.lower()
    raw_host = (parsed.hostname or "").strip().rstrip(".")

    # IDNA / Punycode handling
    has_punycode = False
    unicode_host = raw_host
    try:
        # Check if already punycode or contains non-ascii
        if "xn--" in raw_host.lower():
            has_punycode = True
            try:
                unicode_host = idna.decode(raw_host.lower())
            except Exception:
                unicode_host = raw_host
            ascii_host = raw_host.lower()
        else:
            # Convert any non-ASCII to IDNA ASCII
            ascii_host = idna.encode(raw_host).decode("ascii").lower()
            if "xn--" in ascii_host:
                has_punycode = True
    except Exception:
        # Fallback to lowercased raw hostname if IDNA encode fails
        ascii_host = raw_host.lower()

    # Port normalization
    default_port = 443 if scheme == "https" else 80
    explicit_port = parsed.port
    effective_port = explicit_port if explicit_port is not None else default_port

    # Strip default port from netloc
    if explicit_port is not None and explicit_port == default_port:
        netloc = ascii_host
    elif explicit_port is not None and explicit_port != default_port:
        netloc = f"{ascii_host}:{explicit_port}"
    else:
        netloc = ascii_host

    # Path normalization: standard single slash if empty
    path = parsed.path if parsed.path else "/"

    # Reconstruct normalized URL (fragment omitted)
    normalized = urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))

    # Construct redacted URL
    redacted_query = redact_query_parameters(parsed.query)
    redacted_url = urlunparse((scheme, netloc, path, parsed.params, redacted_query, ""))

    return NormalizedURL(
        normalized_url=normalized,
        redacted_url=redacted_url,
        scheme=scheme,
        hostname=ascii_host,
        unicode_hostname=unicode_host,
        has_punycode=has_punycode,
        port=effective_port,
        path=path,
        query=parsed.query,
    )
