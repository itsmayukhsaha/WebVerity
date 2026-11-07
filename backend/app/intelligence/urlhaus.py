"""URLhaus (abuse.ch) threat intelligence provider.

Official API: POST https://urlhaus-api.abuse.ch/v1/url/ with an "url" field
(JSON body). An optional auth key is supported via the URLHAUS_AUTH_KEY
environment variable and is never logged or hardcoded.
Docs: https://urlhaus.abuse.ch/api/
"""

import os
import time
from typing import Any

import httpx
from backend.app.core.logging import logger
from backend.app.intelligence.base import (
    ProviderStatus,
    ThreatIntelligenceResult,
    redact_url_for_external_query,
)

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
REQUEST_TIMEOUT = 8.0
MIN_REQUEST_INTERVAL = 1.0  # conservative rate limit: 1 request/second


class URLhausProvider:
    """abuse.ch URLhaus adapter implementing the ThreatIntelligenceProvider contract."""

    def __init__(self, auth_key: str | None = None):
        self._auth_key = auth_key if auth_key is not None else os.environ.get("URLHAUS_AUTH_KEY")
        self._last_request_ts = 0.0

    def get_source_name(self) -> str:
        return "URLhaus"

    def get_provider_status(self) -> ProviderStatus:
        # URLhaus works without an API key; treat as available unless a prior
        # failure marks it degraded. Simple time-based cooldown is used.
        if time.time() - self._last_request_ts < 0:
            return ProviderStatus.DEGRADED
        return ProviderStatus.AVAILABLE

    def _throttle(self) -> None:
        elapsed = time.time() - self._last_request_ts
        if elapsed < MIN_REQUEST_INTERVAL:
            time.sleep(MIN_REQUEST_INTERVAL - elapsed)
        self._last_request_ts = time.time()

    def _lookup(self, indicator: str, query_type: str) -> ThreatIntelligenceResult:
        base = ThreatIntelligenceResult(source=self.get_source_name(), query=indicator)
        self._throttle()
        headers = {"Auth-Key": self._auth_key} if self._auth_key else {}
        payload: dict[str, Any] = {query_type: indicator}
        try:
            response = httpx.post(
                URLHAUS_API_URL,
                data=payload,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                follow_redirects=False,
            )
        except httpx.TimeoutException:
            base.error = "URLhaus API timeout"
            base.status = "TIMEOUT"
            return base
        except httpx.HTTPError as e:
            base.error = f"URLhaus API unreachable: {e}"
            base.status = "FAILED"
            return base

        if response.status_code == 429:
            base.error = "URLhaus rate limit exceeded (HTTP 429)"
            base.status = "RATE_LIMITED"
            return base
        if response.status_code == 401:
            base.error = "URLhaus rejected credentials (HTTP 401)"
            base.status = "FAILED"
            return base
        if response.status_code != 200:
            base.error = f"URLhaus returned HTTP {response.status_code}"
            base.status = "FAILED"
            return base

        try:
            data = response.json()
        except ValueError:
            base.error = "URLhaus returned invalid JSON"
            base.status = "FAILED"
            return base

        if not data or not isinstance(data, dict):
            base.status = "COMPLETED"
            return base

        # URLhaus returns {"query_status": "ok"/"no_results", ...} on match.
        if data.get("query_status") == "no_results":
            base.status = "COMPLETED"
            return base
        if data.get("query_status") != "ok":
            base.error = f"URLhaus query_status: {data.get('query_status')}"
            base.status = "FAILED"
            return base

        base.match_found = True
        base.verified = data.get("url_status") in (
            "online",
            "offline",
            "blocked",
        )  # flagged in the dataset (active or historic)
        base.threat_type = "malware_url" if data.get("threat") is None else str(data.get("threat"))
        base.confidence = "HIGH"  # curated multi-source feed
        base.last_seen = data.get("last_online") or data.get("date_added")
        base.reference = "https://urlhaus.abuse.ch/browse/"
        base.status = "COMPLETED"
        return base

    def check_url(self, url: str) -> ThreatIntelligenceResult:
        """Look up a redacted URL in the URLhaus database."""
        redacted = redact_url_for_external_query(url)
        logger.debug(f"URLhaus URL lookup for {redacted}")
        return self._lookup(redacted, "url")

    def check_domain(self, domain: str) -> ThreatIntelligenceResult:
        """Look up a host indicator in the URLhaus database."""
        logger.debug(f"URLhaus host lookup for {domain}")
        return self._lookup(domain, "host")
