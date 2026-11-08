# WebVerity — Phase 4 & Phase 5

## Phase 4 — React Dashboard, Visual Reports & User Experience

The `frontend/` directory is a Next.js 16 + React 19 + TypeScript + Tailwind CSS 4 App Router
application with a self-contained dark cybersecurity design system (no external font loading).

| Route            | Feature                                                                                    |
| ---------------- | ------------------------------------------------------------------------------------------ |
| `/`              | Landing page — hero, feature cards, explainable-detection section, pipeline overview, CTAs |
| `/dashboard`     | Security dashboard — real persisted counts, intel provider health, recent scans            |
| `/scan`          | URL scanner with validation, loading state, SSRF-aware error handling, result summary      |
| `/scan/[scanId]` | Detailed report: overview, evidence, findings, intelligence, recommendations               |
| `/history`       | Scan history with search, risk/status filters, pagination (GET `/api/v1/scans`)            |
| `/intelligence`  | Threat-intel center: provider status + passive URL lookup                                  |
| `/analytics`     | Recharts visual reports computed from real scan records                                    |
| `/settings`      | Backend connection diagnostics and data/privacy notes                                      |
| `/about`         | Architecture, scoring model, disclosures                                                   |

### Quality gates

```bash
cd frontend
npx tsc --noEmit   # zero errors
npm run lint       # zero errors
npm run build      # production build succeeds
```

All statistics come from persisted backend records — nothing is fabricated. Scores are labeled
heuristic (`is_probability: false`); LOW ratings carry the required safety disclaimer.

### Added backend endpoint (Phase 4)

| Method | Path            | Description                                                                       |
| ------ | --------------- | --------------------------------------------------------------------------------- |
| GET    | `/api/v1/scans` | Scan history list with `search`, `risk_level`, `status_filter`, `limit`, `offset` |

---

## Phase 5 — Collaborative Threat Intelligence

### Architecture

Community-submitted indicators are stored in dedicated tables, strictly quarantined from the
verified Phase 3 `threat_indicators` until an authorized reviewer approves them:

```
Submission (POST /api/v1/community/submissions)
   │  validation (type/category/format/length)
   │  SSRF-style rejection of private/loopback/metadata targets
   │  fixed-window rate limit per identity (SUBMISSION_RATE_LIMIT/hour)
   │  duplicate detection on normalized indicator key
   ▼
community_submissions (status = PENDING)      ← quarantine
   │  review (POST .../review, ANALYST|ADMIN bearer token)
   ▼
APPROVED → copied into verified threat_indicators with
           source=community:<name>, verification_status=community_approved,
           expires_at = now + COMMUNITY_INTEL_TTL_DAYS
REJECTED / INFO_REQUESTED → never promoted
```

Every submission and moderation action writes to the append-only `audit_logs` table.

### Roles

| Role        | Capability                  | Enforcement                             |
| ----------- | --------------------------- | --------------------------------------- |
| VIEWER      | Browse submissions, scans   | default (no token)                      |
| CONTRIBUTOR | Submit indicators           | open (rate limited)                     |
| ANALYST     | Approve/reject/request-info | `Authorization: Bearer <analyst-token>` |
| ADMIN       | Everything + audit logs     | `WEBVERITY_ADMIN_TOKEN` bearer token    |

Authorization is enforced **server-side**; the frontend admin page only holds the token in
`sessionStorage` and never bypasses backend checks. Token hashes (SHA-256) can be provisioned
in the `api_tokens` table; the trusted admin token comes from the environment.

### API endpoints (Phase 5)

| Method | Path                                         | Auth          | Description                                    |
| ------ | -------------------------------------------- | ------------- | ---------------------------------------------- |
| GET    | `/api/v1/community/meta`                     | public        | Allowed indicator types/categories, rate limit |
| POST   | `/api/v1/community/submissions`              | contributor   | Submit indicator for review                    |
| GET    | `/api/v1/community/submissions`              | public        | List pending/approved submissions (filters)    |
| GET    | `/api/v1/community/submissions/{id}/reviews` | public        | Review history                                 |
| POST   | `/api/v1/community/submissions/{id}/review`  | ANALYST/ADMIN | Approve/reject/request-info                    |
| GET    | `/api/v1/community/audit-logs`               | ADMIN         | Append-only audit trail                        |

### New database tables

`community_submissions`, `submission_reviews`, `audit_logs`, `api_tokens`,
`submission_rate_limits` — created non-destructively by the existing `init_db()`
(`create_all`; existing tables and data are untouched). On Supabase/PostgreSQL deployments,
apply equivalent Row Level Security policies: public read on approved submissions, write
restricted to the backend service role.

### Frontend pages (Phase 5)

| Route        | Feature                                                                    |
| ------------ | -------------------------------------------------------------------------- |
| `/community` | Submit indicator, browse/filter submissions with status badges             |
| `/admin`     | Review queue (approve/reject/request evidence) + audit trail (ADMIN token) |

### Production configuration

Environment templates (`backend/.env.example`, `backend/.env.local.example`,
`frontend/.env.local.example`) document every variable including the Phase 5 secrets.
Deployment uses the existing Render blueprint (`render.yaml`) with Docker images for both
services; set `WEBVERITY_ADMIN_TOKEN`, `CORS_ORIGINS` and `NEXT_PUBLIC_API_URL` in the hosting
dashboard — never in the repository.
