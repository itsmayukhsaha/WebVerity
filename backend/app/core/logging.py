"""Structured logging configuration for WebVerity.

Ensures sensitive values such as query strings containing tokens/passwords
are redacted before writing to log streams.
"""

import logging
import sys
from urllib.parse import urlparse, urlunparse

from backend.app.core.config import settings


def sanitize_url_for_logging(url: str) -> str:
    """Strip or redact sensitive query parameters from URLs before logging.

    Args:
        url: Raw or normalized URL.

    Returns:
        URL with query parameters redacted or omitted.
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        # Redact query string to prevent credential or token leakage in logs
        sanitized_query = "[REDACTED]" if parsed.query else ""
        # Also ensure userinfo is never present
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        return urlunparse(
            (
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.params,
                sanitized_query,
                "",  # remove fragments
            )
        )
    except Exception:
        return "[UNPARSEABLE_URL]"


def setup_logging() -> logging.Logger:
    """Configure root and application loggers."""
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )

    logger = logging.getLogger("webverity")
    logger.setLevel(log_level)
    return logger


logger = setup_logging()
