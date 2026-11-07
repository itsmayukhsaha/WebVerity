"""PhishTank (phishtank.org) threat intelligence provider.

PhishTank's free API requires an application key (PHISHTANK_API_KEY) and has
strict rate limits (historically ~1 request per 15 seconds). Without a key the
provider reports UNAVAILABLE and is skipped — no fabricated results.
Docs: https://phishtank.org/api_documentation.php
"""

import os

import httpx
from backend.app.core.logging import logger
from backend.app.intelligence.base import (
    ProviderStatus,
    ThreatIntelligenceResult,
    redact_url_for_external_query,
)

PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/index.php"
REQUEST_TIMEOUT = 8.0


class PhishTankProvider:
    """PhishTank adapter implementing the ThreatIntelligenceProvider contract."""

    def __init__(self, api_key: str | None = None):
        self._api_key = api_key if api_key is not None else os.environ.get("PHISHTANK_API_KEY")

    def get_source_name(self) -> str:
        return "PhishTank"

    def get_provider_status(self) -> ProviderStatus:
        return ProviderStatus.AVAILABLE if self._api_key else ProviderStatus.UNAVAILABLE

    def _lookup(self, indicator: str) -> ThreatIntelligenceResult:
        base = ThreatIntelligenceResult(source=self.get_source_name(), query=indicator)
        if not self._api_key:
            base.error = "PHISHTANK_API_KEY not configured; provider disabled."
            base.status = "SKIPPED"
            return base

        payload = {
            "url": indicator,
            "format": "json",
            "app_key": self._api_key,
        }
        try:
            response = httpx.post(PHISHTANK_API_URL, data=payload, timeout=REQUEST_TIMEOUT)
        except httpx.TimeoutException:
            base.error = "PhishTank API timeout"
            base.status = "TIMEOUT"
            return base
        except httpx.HTTPError as e:
            base.error = f"PhishTank API unreachable: {e}"
            base.status = "FAILED"
            return base

        if response.status_code == 429:
            base.error = "PhishTank rate limit exceeded"
            base.status = "RATE_LIMITED"
            return base
        if response.status_code != 200:
            base.error = f"PhishTank returned HTTP {response.status_code}"
            base.status = "FAILED"
            return base

        try:
            data = response.json()
        except ValueError:
            base.error = "PhishTank returned invalid JSON"
            base.status = "FAILED"
            return base

        results = data.get("results", {}) if isinstance(data, dict) else {}
        if not isinstance(results, dict) or not results:
            base.status = "COMPLETED"
            return base

        in_db = bool(results.get("in_database"))
        verified = bool(results.get("verified")) and bool(results.get("valid"))
        base.match_found = in_db
        base.verified = verified
        if in_db:
            base.threat_type = "phishing"
            base.confidence = "HIGH" if verified else "LOW"
            base.last_seen = results.get("verified_at")
            base.reference = "https://phishtank.org"
        base.status = "COMPLETED"
        return base

    def check_url(self, url: str) -> ThreatIntelligenceResult:
        """Look up a redacted URL in the PhishTank database."""
        redacted = redact_url_for_external_query(url)
        logger.debug(f"PhishTank URL lookup for {redacted}")
        return self._lookup(redacted)

    def check_domain(self, domain: str) -> ThreatIntelligenceResult:
        """PhishTank supports URL lookups only; domain queries are no-ops."""
        base = ThreatIntelligenceResult(source=self.get_source_name(), query=domain)
        base.status = "NOT_APPLICABLE"
        base.error = "PhishTank supports URL lookups only."
        return base
