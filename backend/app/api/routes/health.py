"""Health check endpoint."""

from backend.app.core.config import settings
from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=dict[str, str])
async def health_check() -> dict[str, str]:
    """Return application operational status and version."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
    }
