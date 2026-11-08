-- ============================================================
-- WebVerity — Supabase / PostgreSQL RLS + schema policies
-- Phase 5 collaborative threat intelligence
-- ============================================================
-- Apply in the Supabase SQL editor AFTER the backend has created
-- tables (via SQLAlchemy create_all on first startup against the
-- Supabase DATABASE_URL), or run the CREATE TABLE IF NOT EXISTS
-- blocks below first for a fresh project.
--
-- Model:
--   * Anonymous/authenticated users (anon, authenticated) may READ
--     only PENDING / APPROVED / INFO_REQUESTED community submissions.
--   * All INSERT/UPDATE/DELETE goes through the FastAPI backend
--     using the SERVICE_ROLE key, which bypasses RLS. Client-facing
--     roles get no write access at all — review/moderation decisions
--     are exclusively backend-enforced.
--   * audit_logs and api_tokens are never readable by client roles.
-- ============================================================

-- ------------------------------------------------------------
-- 0. Tables (skip if the backend already created them)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS community_submissions (
    id                VARCHAR(36) PRIMARY KEY,
    indicator_type    VARCHAR(16)  NOT NULL,
    indicator_value   VARCHAR(2048) NOT NULL,
    indicator_key     VARCHAR(2048) NOT NULL,
    threat_category   VARCHAR(64)  NOT NULL,
    description       TEXT         NOT NULL,
    evidence          TEXT,
    source_name       VARCHAR(128) NOT NULL,
    submitter_id      VARCHAR(128),
    submitter_role    VARCHAR(16)  NOT NULL DEFAULT 'CONTRIBUTOR',
    status            VARCHAR(24)  NOT NULL DEFAULT 'PENDING',
    confidence        DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    review_notes      TEXT,
    reviewed_by       VARCHAR(128),
    reviewed_at       TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_community_submissions_indicator_type ON community_submissions (indicator_type);
CREATE INDEX IF NOT EXISTS ix_community_submissions_indicator_value ON community_submissions (indicator_value);
CREATE INDEX IF NOT EXISTS ix_community_submissions_indicator_key ON community_submissions (indicator_key);
CREATE INDEX IF NOT EXISTS ix_community_submissions_threat_category ON community_submissions (threat_category);
CREATE INDEX IF NOT EXISTS ix_community_submissions_status ON community_submissions (status);
CREATE INDEX IF NOT EXISTS ix_community_submissions_submitter_id ON community_submissions (submitter_id);
CREATE INDEX IF NOT EXISTS ix_community_submissions_created_at ON community_submissions (created_at);
-- duplicate prevention at the database level
CREATE UNIQUE INDEX IF NOT EXISTS uq_community_active_indicator
    ON community_submissions (indicator_key)
    WHERE status IN ('PENDING', 'APPROVED', 'INFO_REQUESTED');

CREATE TABLE IF NOT EXISTS submission_reviews (
    id             VARCHAR(36) PRIMARY KEY,
    submission_id  VARCHAR(36) NOT NULL REFERENCES community_submissions (id),
    reviewer_id    VARCHAR(128) NOT NULL,
    reviewer_role  VARCHAR(16)  NOT NULL,
    decision       VARCHAR(24)  NOT NULL,
    notes          TEXT,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_submission_reviews_submission_id ON submission_reviews (submission_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id             VARCHAR(36) PRIMARY KEY,
    actor_id       VARCHAR(128) NOT NULL,
    actor_role     VARCHAR(16)  NOT NULL,
    action         VARCHAR(64)  NOT NULL,
    resource_type  VARCHAR(32)  NOT NULL,
    resource_id    VARCHAR(64),
    details        TEXT,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_audit_logs_actor_id ON audit_logs (actor_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS ix_audit_logs_created_at ON audit_logs (created_at);

CREATE TABLE IF NOT EXISTS api_tokens (
    id          VARCHAR(36) PRIMARY KEY,
    token_hash  VARCHAR(64) NOT NULL UNIQUE,
    role        VARCHAR(16) NOT NULL,
    label       VARCHAR(64),
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_api_tokens_token_hash ON api_tokens (token_hash);

CREATE TABLE IF NOT EXISTS submission_rate_limits (
    id            VARCHAR(36) PRIMARY KEY,
    identity      VARCHAR(128) NOT NULL,
    window_start  TIMESTAMPTZ NOT NULL,
    count         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_submission_rate_limits_identity ON submission_rate_limits (identity);

-- ------------------------------------------------------------
-- 1. Enable RLS on every Phase 5 table
-- ------------------------------------------------------------
ALTER TABLE community_submissions  ENABLE ROW LEVEL SECURITY;
ALTER TABLE submission_reviews     ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs             ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_tokens             ENABLE ROW LEVEL SECURITY;
ALTER TABLE submission_rate_limits ENABLE ROW LEVEL SECURITY;

-- Also harden the Phase 1–3 tables the backend writes with the
-- service role (no client-facing writes; reads are backend-mediated).
ALTER TABLE scans                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_sources        ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_indicators     ENABLE ROW LEVEL SECURITY;
ALTER TABLE intelligence_matches  ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_evidence         ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_results     ENABLE ROW LEVEL SECURITY;

-- ------------------------------------------------------------
-- 2. Policies — community_submissions
--    Public read of non-rejected submissions only.
--    No client writes: submissions/reviews go through the backend
--    service role (service_role bypasses RLS).
-- ------------------------------------------------------------
CREATE POLICY community_read_active ON community_submissions
    FOR SELECT TO anon, authenticated
    USING (status IN ('PENDING', 'APPROVED', 'INFO_REQUESTED'));

-- Submitters may read their own submissions even if rejected.
CREATE POLICY community_read_own ON community_submissions
    FOR SELECT TO authenticated
    USING (submitter_id = auth.uid()::text);

-- ------------------------------------------------------------
-- 3. Policies — submission_reviews (read-only mirror for transparency)
-- ------------------------------------------------------------
CREATE POLICY reviews_read ON submission_reviews
    FOR SELECT TO anon, authenticated
    USING (true);

-- ------------------------------------------------------------
-- 4. Policies — sensitive tables: NO client access at all
--    (no policy = default deny under RLS)
--    Explicitly commented for clarity:
--      audit_logs, api_tokens, submission_rate_limits,
--      threat_sources, threat_indicators, intelligence_matches,
--      scan_evidence, detection_results, scans
--    The FastAPI backend connects with the service_role key, which
--    bypasses RLS and retains full read/write.
-- ------------------------------------------------------------

-- ------------------------------------------------------------
-- 5. Optional hardening: revoke direct table grants from anon
--    on sensitive tables (belt-and-braces alongside RLS)
-- ------------------------------------------------------------
REVOKE ALL ON audit_logs, api_tokens, submission_rate_limits FROM anon;
REVOKE ALL ON threat_indicators, threat_sources, intelligence_matches FROM anon;

-- ------------------------------------------------------------
-- 6. Verification queries (run after applying)
-- ------------------------------------------------------------
-- Expect: policy rows for community_read_active / community_read_own / reviews_read
-- SELECT schemaname, tablename, policyname, roles FROM pg_policies
--  WHERE schemaname = 'public' AND tablename LIKE '%submission%';
--
-- Expect: rls_enabled = true for all 11 tables
-- SELECT tablename, rowsecurity AS rls_enabled FROM pg_tables
--  WHERE schemaname = 'public' ORDER BY tablename;
