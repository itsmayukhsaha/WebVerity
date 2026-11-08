"""Application configuration management using Pydantic Settings."""

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Core settings and environment configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    APP_NAME: str = "WebVerity"
    APP_ENV: str = "development"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    DATABASE_URL: str = "sqlite:///./webverity.db"

    CORS_ORIGINS: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://localhost:8000",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:8000",
        ]
    )

    DNS_TIMEOUT: float = 3.0
    TLS_TIMEOUT: float = 4.0
    SCAN_PIPELINE_TIMEOUT: float = 10.0

    # Phase 2 — threat intelligence credentials (never hardcoded)
    URLHAUS_AUTH_KEY: str | None = None
    PHISHTANK_API_KEY: str | None = None

    # Phase 3 — threat intelligence subsystem configuration
    THREAT_INTELLIGENCE_TIMEOUT: float = 8.0
    THREAT_INTELLIGENCE_CACHE_TTL: int = 900
    ENABLE_URLHAUS: bool = True
    ENABLE_PHISHTANK: bool = True

    # Phase 2 — safe HTTP fetch limits
    HTTP_FETCH_TIMEOUT: float = 10.0
    MAX_REDIRECTS: int = 5
    MAX_RESPONSE_BYTES: int = 2097152

    LOG_LEVEL: str = "INFO"

    # Phase 5 — collaborative threat intelligence
    WEBVERITY_ADMIN_TOKEN: str = ""
    SUBMISSION_RATE_LIMIT: int = 5  # submissions per identity per hour
    COMMUNITY_INTEL_TTL_DAYS: int = 90

    @field_validator("DEBUG", mode="before")
    @classmethod
    def _coerce_debug(cls, value: object) -> object:
        """Tolerate ambient machine env vars (e.g. DEBUG=release from CI tooling)
        that would otherwise crash Pydantic's bool parsing at import time."""
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return value


settings = Settings()
