# WebVerity
> **Intelligent Phishing Detection & Website Trust Assessment.**
> **Now with a full Next.js frontend (`frontend/`).**

WebVerity is an accessible, multi-layered cybersecurity platform that detects phishing infrastructure and evaluates website trustworthiness through deterministic feature extraction, DNS configuration analysis, cryptographic TLS certificate validation, HTTP security-header assessment, redirect-chain inspection, passive HTML content analysis, RDAP domain registration intelligence, external threat-intelligence feeds, and explainable rule-based risk scoring.

---

## Problem
Phishing remains the primary initial access vector in modern cyberattacks, accounting for catastrophic financial loss, credential theft, and ransomware deployment. Modern threat actors leverage ephemeral cloud infrastructure, typosquatting domains, punycode homographs, and disposable TLS certificates to impersonate trusted institutions. Traditional blacklists suffer from critical latency gaps, leaving users unprotected during the initial hours of a zero-day phishing campaign.

## Solution
WebVerity tackles this challenge through active, multi-layer verification performed immediately upon URL submission:
1. **URL Structural & Lexical Analysis:** Evaluates hostname entropy, subdomain depth, suspicious keywords, punycode encoding, embedded credentials, and obfuscated character encodings.
2. **DNS & Infrastructure Inspection:** Resolves IPv4/IPv6 address records, CNAME chains, mail exchanger (MX) presence, and nameservers.
3. **Cryptographic TLS Analysis:** Conducts an active TLS handshake against a validated public IP with Server Name Indication (SNI), verifying system trust-store chains, certificate validity dates, subject alternative names (SANs), cipher suites, and key strengths.
4. **Hardened SSRF Defenses:** Enforces strict IP address validation preventing internal network pivoting, DNS rebinding attacks, and cloud metadata access — for every request and every redirect hop.
5. **HTTP Security & Redirect Analysis:** Passive assessment of security headers, cookie attributes, and redirect chains with per-hop SSRF re-validation.
6. **Content & Brand-Impersonation Heuristics:** BeautifulSoup HTML parsing (no JS execution) detecting password forms, external form actions, deceptive metadata, and lookalike brand domains.
7. **Threat Intelligence:** abuse.ch URLhaus lookups (optional PhishTank adapter) with redacted indicators, timeouts, and honest UNAVAILABLE states.
8. **RDAP Domain Intelligence:** Registration age, expiration, and registrar via standards-based RDAP.
9. **Explainable Dual Scoring:** Separate THREAT RISK (phishing likelihood) and SECURITY POSTURE (configuration quality) scores plus an independent evidence confidence rating — missing headers can never masquerade as phishing proof.

---

## Tech Stack
- **Language:** Python 3.11+
- **API Framework:** FastAPI, Uvicorn (ASGI)
- **Data Validation:** Pydantic v2, Pydantic-Settings
- **DNS Resolution:** dnspython
- **Cryptography & Security:** Python `cryptography`, `ssl`, `ipaddress`, `socket`
- **Database & ORM:** SQLAlchemy 2.x (SQLite for local development; PostgreSQL/Supabase compatible)
- **HTTP Client:** HTTPX
- **Quality & Testing:** Pytest, Pytest-Asyncio, Ruff

---

## Architecture

The Day 1 synchronous API orchestrates an asynchronous security pipeline:

```
URL Submission (POST /api/v1/scans)
       │
       ▼
Input Validation & Normalization ──► Rejects non-HTTP(S), invalid ports, embedded credentials
       │
       ▼
SSRF Guard ──► Rejects private/loopback/link-local/metadata IPs & hostnames
       │
       ▼
Parallel Module Execution (Async Worker Threads)
  ├─► URL Feature Extraction (Entropy, keywords, subdomains, punycode)
  ├─► DNS Infrastructure Analysis (A, AAAA, CNAME, NS, MX, TXT records)
  ├─► RDAP Domain Intelligence (age, expiry, registrar — concurrent with DNS)
  ├─► Threat Intelligence (URLhaus / PhishTank adapters — concurrent)
  └─► TLS Certificate Handshake (Pinned destination IP, SNI, X.509 validation)
       │
       ▼
Safe HTTP Fetch (SSRF-validated, IP-pinned, ≤5 redirects, ≤2 MiB)
  ├─► HTTP Security Analyzer (headers, cookies, server disclosure)
  ├─► Redirect Analyzer (cross-domain hops, downgrades, shorteners)
  └─► Content Analyzer (BeautifulSoup: forms, links, brand impersonation)
       │
       ▼
Evidence Aggregator ──► Consolidates findings, deduplicates, normalizes statuses
       │
       ▼
Advanced Risk Correlation ──► Threat Risk (0-100) + Security Posture (0-100) + Confidence
       │
       ▼
Recommendations ──► Actionable, finding-driven guidance
       │
       ▼
Database Persistence ──► SQLAlchemy 2.x / SQLite scan record
       │
       ▼
API Response (ScanResponse)
```

---

## Setup and Run

### 1. Prerequisites
- Python 3.11 or newer
- Git

### 2. Clone and Setup Environment
```bash
git clone <repository-url>
cd WebVerity

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt
```

### 3. Environment Configuration
Copy the template configuration:
```bash
cp backend/.env.example backend/.env
```

Default settings in `.env.example`:
```env
APP_NAME=WebVerity
APP_ENV=development
APP_VERSION=0.1.0
DEBUG=true
DATABASE_URL=sqlite:///./webverity.db
CORS_ORIGINS=["http://localhost:3000","http://localhost:8000","http://127.0.0.1:3000","http://127.0.0.1:8000"]
DNS_TIMEOUT=3.0
TLS_TIMEOUT=4.0
SCAN_PIPELINE_TIMEOUT=10.0
# Phase 2 (optional)
URLHAUS_AUTH_KEY=           # optional abuse.ch URLhaus auth key
PHISHTANK_API_KEY=          # optional PhishTank application key
```

### 4. Running the Application
From the repository root:
```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 5. Access Interactive Documentation
Open your browser to:
- **Swagger UI:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **Health Check:** [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)

### 6. Running Tests & Linting
```bash
# Run pytest test suite (107 automated tests: Phase 1 + Phase 2)
pytest -v

# Run only mocked unit tests (no external network):
pytest -m "not integration"

# Run ruff code linter
ruff check .

# Run ruff code formatter
ruff format --check .
```

### 7. Phase 2 API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/scans` | Submit URL for full 8-module assessment |
| GET | `/api/v1/scans/{id}` | Complete scan report (all modules, findings, recommendations) |
| GET | `/api/v1/scans/{id}/intelligence` | Threat-intelligence + RDAP module outputs |
| GET | `/api/v1/scans/{id}/findings` | Deduplicated findings list |
| GET | `/api/v1/scans/{id}/recommendations` | Actionable recommendations |

### 8. Scoring Model (Phase 2)
- **Threat Risk (0–100):** phishing/malicious likelihood. Bands: 0–24 LOW, 25–49 MODERATE, 50–74 HIGH, 75–100 CRITICAL. Verified threat-feed matches dominate weak heuristics; configuration weaknesses are excluded from threat evidence.
- **Security Posture (0–100):** configuration quality (headers, cookies, TLS hygiene). A legit site with missing CSP stays LOW-threat with a reduced posture.
- **Confidence (LOW/MEDIUM/HIGH):** evidence completeness × intelligence verification — independent of risk level.
- All scores are heuristic (`is_probability: false`); LOW risk always carries the safety disclaimer.

---

## Phase 3 — Threat Intelligence Integration, Evidence Correlation & Intelligent Risk Detection

Phase 3 layers an explainable detection engine on top of the Phase 2 pipeline:

- **Threat-intelligence subsystem** (`backend/app/intelligence/`): URLhaus and PhishTank adapters behind a common contract, normalized indicator/match models (`models.py`), explainable matching (`indicator_matcher.py`), a TTL result cache (`cache.py`), and a fan-out manager with per-provider failure isolation (`intelligence_manager.py`). Providers are configured via `URLHAUS_AUTH_KEY`, `PHISHTANK_API_KEY`, `ENABLE_URLHAUS`, `ENABLE_PHISHTANK`, `THREAT_INTELLIGENCE_TIMEOUT`, `THREAT_INTELLIGENCE_CACHE_TTL`. Missing keys mean honest UNAVAILABLE states — never fabricated clean results.
- **Indicator matching:** exact/canonical URL, exact domain and explicit subdomain matching with case/IDNA/port/percent-encoding normalization; substring spoofing (`example.com.evil.test`) cannot match.
- **Evidence correlation** (`detection/evidence_correlator.py`): deduplicated evidence in five buckets (malicious / suspicious / security weakness / neutral / unavailable). Missing headers are weaknesses, not phishing proof; failed modules are UNAVAILABLE, never negative evidence.
- **Risk engine** (`detection/risk_engine.py`): deterministic, configurable, weighted 0–100 score with breakdown and reasons. Provider-confirmed matches force CRITICAL precedence; insufficient evidence caps escalation.
- **Confidence engine** (`detection/confidence_engine.py`): independent of risk; failed essential checks cap confidence even with verified intelligence.
- **Detection orchestrator** (`detection/detection_orchestrator.py`): single unified detection result, persisted per scan.

### Phase 3 API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/intelligence/check` | Passive TI lookup of a URL/domain across enabled providers |
| GET | `/api/v1/intelligence/status` | Provider configuration/availability (no credentials returned) |
| GET | `/api/v1/scans/{id}/detection` | Unified detection result (risk, confidence, breakdown, evidence) |
| GET | `/api/v1/scans/{id}/evidence` | Deduplicated correlated evidence |
| GET | `/api/v1/scans/{id}/intelligence` | Normalized intelligence matches for the scan |

### Phase 3 Database entities
`threat_sources`, `threat_indicators`, `intelligence_matches`, `scan_evidence`, `detection_results` — see `docs/PHASE_3_ARCHITECTURE.md`.

### Phase 3 tests
`pytest tests/test_phase3_detection.py` — mocked, offline tests covering matching, provider responses, timeouts, rate limits, dedup, scoring precedence, confidence and API behaviour. Full suite: **139 tests**.

---

## Phase 4 — Frontend (Next.js)

The `frontend/` directory contains a complete Next.js 16 + React 19 + TypeScript + Tailwind CSS 4 App Router interface:

| Route | Feature |
|-------|---------|
| `/` | Professional landing page (design system, pipeline overview) |
| `/dashboard` | Security dashboard — real persisted counts, intel provider health, recent scans |
| `/scan` | Website URL scanner with live pipeline progress |
| `/scan/[scanId]` | Detailed report: overview, evidence, modules, findings, intelligence, recommendations |
| `/history` | Scan history with search, risk/status filters, pagination (GET `/api/v1/scans`) |
| `/intelligence` | Threat-intelligence center: provider status + passive URL lookup (POST `/api/v1/intelligence/check`) |
| `/analytics` | Recharts visual reports computed from real scan records |
| `/settings` | Backend connection diagnostics (health check) and data/privacy notes |
| `/about` | Architecture, scoring model, disclosures |

### Frontend setup

```bash
cd frontend
npm install
copy .env.local.example .env.local   # defaults to NEXT_PUBLIC_API_URL=http://127.0.0.1:8001
npm run dev                          # http://localhost:3000
```

> **Windows port note:** if port 8000 fails with `WinError 10013` (port reserved by
> Windows), start the backend on 8001 instead:
> `uvicorn backend.app.main:app --host 127.0.0.1 --port 8001 --reload`
> The frontend default `NEXT_PUBLIC_API_URL` already points at 8001.

Fonts are intentionally **not** loaded from Google Fonts (this breaks offline/proxied
builds with `Can't resolve '@vercel/turbopack-next/internal/font/google/font'`);
the design uses a self-contained system-font stack in `globals.css`.

### Frontend quality gates

```bash
npm run build   # Next.js production build (TypeScript checked)
npm run lint    # ESLint (zero errors)
```

All statistics shown in the UI come from persisted backend records — nothing is fabricated. Threat-intelligence states (configured/unavailable) are surfaced honestly; credentials are never exposed.

### Deployment (Render Blueprint)

`render.yaml` defines two services:
- `webverity-backend` — Docker image with a persistent disk at `/data` for the SQLite database.
- `webverity-frontend` — Dockerized Next.js; set `NEXT_PUBLIC_API_URL` to the backend's public URL in the Render dashboard (also update backend `CORS_ORIGINS` with the frontend origin).

### Added backend endpoint (Phase 4)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/scans` | Scan history list with `search`, `risk_level`, `status`, `limit`, `offset` |

---

## Disclosures
- **Third-Party Dependencies:** All external libraries (`fastapi`, `uvicorn`, `pydantic`, `cryptography`, `dnspython`, `sqlalchemy`, `httpx`, `beautifulsoup4`, `lxml`, `pytest`, `ruff`) are free and open-source software under permissive licenses (MIT, Apache-2.0, BSD).
- **Threat Intelligence:** URLhaus (abuse.ch) data is used per its public API terms; queries are redacted (no query strings sent). PhishTank requires an application key and is disabled without one. No fabricated intelligence is ever produced — unavailable sources return honest UNAVAILABLE/SKIPPED states.
- **AI-Assisted Development:** Built with pair-programming assistance from Antigravity (Google DeepMind). All architecture decisions, security boundaries, and code implementations were systematically reviewed, hardened, and verified with automated test suites.

---

## Track
`[TRACK / PROBLEM STATEMENT IDENTIFIER TO BE ENTERED BY TEAM]`
