"""URL validation module.

Enforces strict protocol, port, format, and credential boundaries.
"""

import re
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}


class URLValidationError(ValueError):
    """Raised when an invalid or forbidden URL is submitted."""

    pass


def validate_url(raw_url: str) -> None:
    """Validate a submitted URL against strict security criteria.

    Raises:
        URLValidationError: If URL violates any validation constraint.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise URLValidationError("URL cannot be empty or non-string.")

    clean_url = raw_url.strip()
    if len(clean_url) > 2048:
        raise URLValidationError("URL exceeds maximum permissible length of 2048 characters.")

    # Reject dangerous control characters or embedded newlines
    if re.search(r"[\r\n\t]", clean_url):
        raise URLValidationError("URL contains forbidden whitespace or control characters.")

    try:
        parsed = urlparse(clean_url)
    except Exception as e:
        raise URLValidationError(f"Malformed URL structure: {e}") from e

    # Protocol validation
    if not parsed.scheme:
        raise URLValidationError(
            "URL must include an explicit protocol scheme (http:// or https://)."
        )

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise URLValidationError(
            f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS protocols are permitted."
        )

    # Reject credentials in URL (e.g. http://user:pass@host)
    if parsed.username or parsed.password:
        raise URLValidationError(
            "URLs containing embedded authentication credentials are forbidden."
        )

    # Validate hostname existence
    if not parsed.hostname:
        raise URLValidationError("URL must specify a valid destination hostname.")

    # Port restriction: Only ports 80 and 443 permitted in initial version
    if parsed.port is not None and parsed.port not in ALLOWED_PORTS:
        raise URLValidationError(
            f"Port {parsed.port} is not permitted. Only standard HTTP (80) and HTTPS (443) ports are allowed."
        )

    # Check for empty path delimiters or malformed components
    hostname = parsed.hostname.strip()
    if not hostname:
        raise URLValidationError("URL contains an empty or malformed hostname.")
