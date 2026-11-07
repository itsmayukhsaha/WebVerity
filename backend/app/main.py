"""WebVerity FastAPI Application Entry Point.

Intelligent Phishing Detection & Website Trust Assessment Platform.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from backend.app.api.routes import health, scans
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.database.connection import init_db
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context: manage startup and shutdown procedures."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} ({settings.APP_ENV})...")
    # Initialize database tables
    init_db()
    logger.info("Application startup completed successfully.")
    yield
    logger.info(f"Shutting down {settings.APP_NAME}...")


def create_application() -> FastAPI:
    """Build and configure the FastAPI application instance."""
    app = FastAPI(
        title=settings.APP_NAME,
        description=(
            "WebVerity provides multi-layered threat assessment combining URL structure analysis, "
            "DNS infrastructure evaluation, cryptographic TLS inspection, and explainable risk scoring."
        ),
        version=settings.APP_VERSION,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Restrict CORS to configured origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # Register API v1 routes
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(scans.router, prefix="/api/v1")

    @app.get("/", include_in_schema=False)
    async def root_redirect() -> RedirectResponse:
        """Redirect root requests to interactive API documentation."""
        return RedirectResponse(url="/docs")

    return app


app = create_application()
