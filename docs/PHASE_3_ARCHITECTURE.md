# WebVerity — Phase 3 Architecture: Threat Intelligence, Evidence Correlation & Intelligent Risk Detection

## Overview

Phase 3 extends the Phase 2 pipeline with:

1. A modular threat-intelligence subsystem (`backend/app/intelligence/`).
2. An explainable indicator-matching engine.
3. An evidence correlation engine (`detection/evidence_correlator.py`).
4. A configurable risk scoring engine (`detection/risk_engine.py`).
5. An independent confidence engine (`detection/confidence_engine.py`).
6. A unified detection orchestrator (`detection/detection_orchestrator.py`).
7. Persistence for indicators, matches, evidence and detection results.
8. New intelligence/detection API endpoints.

## Data flow

```
Phase 2 pipeline (URL/DNS/TLS/HTTP/Redirect/Content/RDAP)
        │  AggregatedScanResult
        ▼
Detection Orchestrator (detection_orchestrator.run_detection)
        │
        ├─► Intelligence Manager ──► URLhaus / PhishTank (passive, redacted)
        │         │
        │         └─► NormalizedIndicatorMatch[] (deduplicated)
        │
        ├─► Evidence Correlator ──► categorized, deduplicated evidence
        │     buckets: malicious | suspicious | weakness | neutral | unavailable
        │
        ├─► Risk Engine ──► 0-100 score + breakdown + reasons
        │     (confirmed TI match ⇒ CRITICAL precedence)
        │
        └─► Confidence Engine ──► independent confidence verdict
              (failed checks cap confidence; count ≠ reliability)
        │
        ▼
ScanManager persists: ThreatIndicator, IntelligenceMatch,
ScanEvidence, DetectionResult + results_json["detection"]
        │
        ▼
API: /scans/{id}/detection | /evidence | /intelligence
     /intelligence/check | /intelligence/status
```

## Intelligence providers

### URLhaus (abuse.ch)

- API: `POST https://urlhaus-api.abuse.ch/v1/url/` with `url` / `host` fields.
- Optional `URLHAUS_AUTH_KEY` header; never logged or returned by the API.
- Timeouts (`THREAT_INTELLIGENCE_TIMEOUT`), 1 req/s throttling, 429 → `RATE_LIMITED`.
- Match ⇒ `verified=True` when `url_status` ∈ {online, offline, blocked}.

### PhishTank

- API: `POST https://checkurl.phishtank.com/checkurl/index.php` (`url`, `format=json`, `app_key`).
- Requires `PHISHTANK_API_KEY`; without it the provider reports `UNAVAILABLE`/`SKIPPED` — never a fabricated result.
- `in_database + verified + valid` ⇒ CONFIRMED; unverified reports stay UNVERIFIED.
- Domain-only queries are `NOT_APPLICABLE` (URL lookups only).

### Normalized result schema (`intelligence/models.py`)

`provider, indicator_type, indicator_value, original_value, matched, match_type,
threat_category, verification_status, source_url, first_observed, last_observed,
retrieved_at, expires_at, response_status, error, is_probability=false`.

Missing information is NEVER interpreted as a clean result: failures map to
`RATE_LIMITED / TIMEOUT / ERROR / UNAVAILABLE` response statuses and become
UNAVAILABLE evidence.

## Indicator matching

- Normalizes scheme case, hostname case, default ports, fragments, trailing dots and percent-encoding before comparison.
- Match types: `exact_url`, `canonical_url`, `exact_domain`, `subdomain`.
- Hostname comparison is exact or explicit subdot relation — never substring:
  `example.com.evil.test` cannot match an `example.com` indicator.

## Evidence correlation

- Deduplicates by finding id + host/url fingerprint (cross-module duplicates collapse).
- Missing security headers ⇒ SECURITY_WEAKNESS (never phishing evidence).
- Valid TLS ⇒ at most NEUTRAL; never proof of legitimacy.
- Failed/timed-out/skipped modules ⇒ UNAVAILABLE evidence with confidence 0.

## Risk scoring (heuristic, NOT a probability)

Initial weights (configurable via `DEFAULT_WEIGHTS`):

| Evidence                       | Weight |
| ------------------------------ | -----: |
| Confirmed phishing match       |    +90 |
| Confirmed malware match        |    +90 |
| Strong brand impersonation     |    +35 |
| Suspicious URL characteristics |    +15 |
| Suspicious redirect behaviour  |    +20 |
| High-risk page/form behaviour  |    +25 |
| Suspicious DNS/domain evidence |    +10 |
| Weak TLS configuration         |     +5 |
| Expired certificate            |     +5 |
| Missing security headers       |     +2 |

- Per-source caps prevent single-module domination; final score capped at 100.
- **Precedence rule:** a provider-confirmed match forces `risk_score ≥ 90` and
  a CRITICAL classification.
- Insufficient completed checks caps escalation at MODERATE.
- Bands: 0–19 LOW, 20–49 MODERATE, 50–79 HIGH, 80–100 CRITICAL.
- Output includes `score_breakdown`, `reasons`, and `is_probability: false`.

## Confidence (independent of risk)

Weighted combination of module completeness (60%), evidence source
reliability (25%), corroboration bonus, and verified-intelligence floor.
HIGH requires ≥6 successful checks. Any failed essential check caps
confidence at 75 even with verified intelligence.

## Database additions (`backend/app/models/threat.py`)

`threat_sources`, `threat_indicators`, `intelligence_matches`,
`scan_evidence`, `detection_results` — created by the existing
`init_db()` `create_all` (SQLite dev / PostgreSQL compatible). Only redacted
indicators and normalized match summaries are stored, never full third-party
payloads or unredacted URLs.

## Security invariants maintained

- Passive intelligence only — no connection to the target by TI modules.
- Query strings stripped before any external submission.
- SSRF guard, DNS validation, redirect revalidation, timeouts and response
  size limits from Phase 2 are untouched.
- No API keys in responses, logs or the database.
- Provider failures are recorded as unavailable/error, never as "safe".
