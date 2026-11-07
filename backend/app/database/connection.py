"""Database connection, session lifecycle, and lightweight schema migration.

Preserves existing SQLite records: tables are created if absent and new
columns are added in place with ALTER TABLE (no destructive recreation).
"""

from collections.abc import Generator

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.models.scan import Base
from backend.app.models.threat import (  # noqa: F401  (registers tables with Base.metadata)
    DetectionResult,
    IntelligenceMatch,
    ScanEvidence,
    ThreatIndicator,
    ThreatSource,
)
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

# Normalize legacy Postgres URLs (Render/Railway sometimes emit postgres://).
_DATABASE_URL = settings.DATABASE_URL
if _DATABASE_URL.startswith("postgres://"):
    _DATABASE_URL = _DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Configure engine with thread safety for SQLite and pooled connections for Postgres
connect_args = {}
engine_kwargs: dict = {"echo": False, "future": True}
if _DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    engine_kwargs["pool_pre_ping"] = True
    engine_kwargs["pool_recycle"] = 280  # stay under Render/Railway connection idle limits

engine = create_engine(
    _DATABASE_URL,
    connect_args=connect_args,
    **engine_kwargs,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)

# Columns added after the initial Phase 1 schema (table, column, DDL fragment).
_PHASE2_COLUMNS: list[tuple[str, str, str]] = [
    ("scans", "security_posture_score", "INTEGER NOT NULL DEFAULT 100"),
]


def _apply_phase2_migrations() -> None:
    """Add Phase 2 columns to existing tables without touching existing rows."""
    with engine.connect() as conn:
        for table, column, ddl in _PHASE2_COLUMNS:
            try:
                existing = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
                column_names = {row[1] for row in existing}
                if column not in column_names:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
                    logger.info(f"Migration: added column '{column}' to table '{table}'.")
            except Exception as e:
                # Table may not exist yet on a fresh database — create_all handles it.
                logger.debug(f"Migration check skipped for {table}.{column}: {e}")
        conn.commit()


def init_db() -> None:
    """Initialize database tables and apply incremental schema migrations."""
    logger.info("Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    _apply_phase2_migrations()
    logger.info("Database schema initialized successfully.")


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for obtaining a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
