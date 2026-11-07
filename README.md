# WebVerity
> **Intelligent Phishing Detection & Website Trust Assessment.**

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

## Disclosures
- **Third-Party Dependencies:** All external libraries (`fastapi`, `uvicorn`, `pydantic`, `cryptography`, `dnspython`, `sqlalchemy`, `httpx`, `beautifulsoup4`, `lxml`, `pytest`, `ruff`) are free and open-source software under permissive licenses (MIT, Apache-2.0, BSD).
- **Threat Intelligence:** URLhaus (abuse.ch) data is used per its public API terms; queries are redacted (no query strings sent). PhishTank requires an application key and is disabled without one. No fabricated intelligence is ever produced — unavailable sources return honest UNAVAILABLE/SKIPPED states.
- **AI-Assisted Development:** Built with pair-programming assistance from Antigravity (Google DeepMind). All architecture decisions, security boundaries, and code implementations were systematically reviewed, hardened, and verified with automated test suites.

---

## Track
`[TRACK / PROBLEM STATEMENT IDENTIFIER TO BE ENTERED BY TEAM]`
