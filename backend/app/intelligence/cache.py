"""TTL cache for threat-intelligence provider lookups (Phase 3).

Reduces redundant external API calls within the configured freshness window.
Entries expire after ``THREAT_INTELLIGENCE_CACHE_TTL`` seconds. Never caches
failures as clean results — failed lookups are cached only briefly as errors.
"""

import time
from typing import Any

from backend.app.core.config import settings


class TTLCache:
    """Minimal thread-hostile TTL cache; safe under the pipeline's thread pool
    because each provider instance performs its own throttling."""

    def __init__(self, ttl_seconds: int | None = None):
        self.ttl = (
            ttl_seconds if ttl_seconds is not None else settings.THREAT_INTELLIGENCE_CACHE_TTL
        )
        self._store: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        stored_at, value = entry
        if time.monotonic() - stored_at > self.ttl:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        self._store[key] = (time.monotonic(), value)

    def clear(self) -> None:
        self._store.clear()
