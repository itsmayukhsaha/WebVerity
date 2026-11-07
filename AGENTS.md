# WebVerity Agent Development Instructions & Architecture Guide

This document serves as the operational manual for future Antigravity AI coding agents and human developers maintaining **WebVerity**.

---

## 1. Core Architecture & Mental Model

WebVerity evaluates website trust through deterministic, multi-layered evidence gathering:
- **`backend/app/analyzers/url_analyzer`:** Lexical features, Shannon entropy, subdomains, Punycode, keywords, query redaction.
- **`backend/app/analyzers/dns_analyzer`:** `dnspython` querying A/AAAA/CNAME/NS/MX/TXT with address validation.
- **`backend/app/analyzers/tls_analyzer`:** Standard library `ssl` and `cryptography.x509` handshake against pinned public IP with SNI.
- **`backend/app/detection`:** Rule weights table (`rules_engine.py`) and scoring algorithm (`risk_scoring.py`) combining evidence into 0–100 score (URL 50%, DNS 25%, TLS 25%).
- **`backend/app/orchestration`:** Asynchronous pipeline (`pipeline.py`) isolating analyzer failures and thread pooling blocking I/O.
- **`backend/app/database`:** SQLAlchemy 2.x persistence layer targeting SQLite for local development and PostgreSQL for Supabase.

---

## 2. Critical Security Invariants (DO NOT VIOLATE)

1. **SSRF Guard Invariance:**
   - Under NO circumstances may the scanner connect directly to private, loopback, link-local, multicast, or cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
   - Every resolved DNS address must be evaluated using `is_safe_public_ip` before initiating any outbound connection.
   - If any resolved address in a record is private, the target MUST be marked `SSRF_BLOCKED` and connection attempts aborted.
2. **DNS Rebinding Protection (Pinned Connections):**
   - When connecting for TLS analysis, always pass the validated IP address to `socket.create_connection((ip, port))` while supplying the original hostname to `server_hostname=hostname` for SNI and certificate validation. Never reconnect by hostname directly.
3. **No Fabricated Evidence or Hallucinated ML Scores:**
   - Heuristic risk scores must clearly state `is_probability: false`.
   - Never claim an ML model or brand impersonation dictionary ran if none was invoked.
   - A certificate must only be marked `REVOKED` if an actual OCSP/CRL check proves revocation. If unreachable, mark `UNKNOWN`.
   - A `LOW` risk score must always include the required disclaimer:
     *"No strong threat indicators observed in the completed checks. This does not guarantee that the website is safe."*
4. **Data Minimization & Redaction:**
   - Always sanitize URLs before logging using `sanitize_url_for_logging()`.
   - Never persist unredacted query parameters containing sensitive tokens or credentials in `scans.submitted_url_redacted`.

---

## 3. Coding Conventions & Quality Standards

- **Python Version:** Python 3.11+
- **Type Annotations:** Full type hinting across all function parameters and return types.
- **Data Models:** Pydantic v2 schemas for request and response validation; SQLAlchemy 2.x for database entities.
- **Error Handling:** Use structured custom exceptions (`URLValidationError`, `SSRFSecurityException`).
- **Linter & Formatter:** Ruff. All code must pass `ruff check .` and `ruff format --check .` with zero warnings.
- **Testing:** Pytest. Use mocked network fixtures for DNS and TLS. Tests must run completely offline without relying on third-party live servers.

---

## 4. Key Developer Commands

```bash
# Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Run full automated test suite
pytest -v

# Run linting check
ruff check .

# Auto-fix linting issues
ruff check --fix .

# Code formatting check
ruff format --check .

# Start FastAPI development server
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
