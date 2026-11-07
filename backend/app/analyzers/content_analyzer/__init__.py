"""Module 3 — Passive HTML content analysis."""

from backend.app.analyzers.content_analyzer.analyzer import (
    BRAND_REFERENCE,
    analyze_brand_impersonation,
    analyze_content,
)

__all__ = ["BRAND_REFERENCE", "analyze_brand_impersonation", "analyze_content"]
