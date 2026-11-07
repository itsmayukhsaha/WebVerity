# WebVerity Technical Architecture — Day 1

## 1. System Overview

WebVerity provides an automated, multi-tiered analysis pipeline designed to assess website trust and detect phishing infrastructure. The architecture follows clean separation of concerns across input validation, security gating, modular analyzer execution, evidence aggregation, explainable risk scoring, and persistent audit logging.

```mermaid
flowchart TD
    Client["Client / API Consumer"] -->|POST /api/v1/scans| Gateway["FastAPI Gateway"]
    Gateway --> Normalizer["URL Normalizer & Validator"]
    Normalizer --> SSRFGuard["SSRF Guard (ipaddress check)"]
    SSRFGuard --> Orchestrator["Scan Orchestrator"]
    
    subgraph Analyzers["Modular Analyzer Pipeline"]
        direction LR
        URLA["URL Analyzer<br/>(Entropy, Lexical, Punycode)"]
        DNSA["DNS Analyzer<br/>(dnspython A/AAAA/MX/NS/TXT)"]
        TLSA["TLS Analyzer<br/>(Pinned IP + SNI Handshake)"]
    end
    
    Orchestrator --> URLA
    Orchestrator --> DNSA
    DNSA -.->|Validated Public IP| TLSA
    
    URLA --> Aggregator["Evidence Aggregator"]
    DNSA --> Aggregator
    TLSA --> Aggregator
    
    Aggregator --> RulesEngine["Rule-Based Risk Engine"]
    RulesEngine --> DB[("SQLAlchemy 2.x Store<br/>(SQLite / PostgreSQL)")]
    RulesEngine --> Response["Unified ScanResponse JSON"]
```

---

## 2. Security Subsystem & SSRF Defenses

The scanner is engineered so that it cannot be turned into an attack proxy or pivot against local networks, internal services, or cloud infrastructure.

### Core Mitigations
1. **Loopback & Private Address Blocking:** Every target host is evaluated using Python's standard `ipaddress` library against RFC 1918, RFC 4193, RFC 3927, and RFC 6598 ranges.
2. **Cloud Metadata Defense:** Explicitly blocks AWS/GCP/Azure link-local metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
3. **IPv4-Mapped IPv6 Unpacking:** Automatically unpacks `::ffff:x.x.x.x` addresses to prevent dual-stack firewall bypass.
4. **Pre-Resolution Verification:** Authoritative DNS resolution is performed first. If *any* resolved address falls within a restricted range, the domain is flagged `DNS_SSRF_UNSAFE_IP` and rejected.
5. **DNS Rebinding Prevention (Pinned Connection):** The TLS analyzer connects directly to the IP address pre-validated by the DNS module, while passing the original domain name in the TLS Server Name Indication (SNI) extension. This eliminates time-of-check to time-of-use (TOCTOU) DNS rebinding vulnerabilities.

---

## 3. Analyzer Modules

### URL Analyzer (`app.analyzers.url_analyzer`)
- **Normalizer:** Strips fragments, normalizes default ports (80/443), performs IDNA Punycode conversion (`xn--...`), and generates a query-redacted representation for persistent logs.
- **Validator:** Strict protocol enforcement (HTTP/HTTPS only), port restrictions (80 and 443 permitted on Day 1), and rejection of embedded credentials (`user:pass@host`).
- **Feature Extractor:** Calculates Shannon entropy of hostnames, counts subdomain levels, detects suspicious keyword presence (`login`, `verify`, `account`, etc.), identifies percent-encoding anomalies, and evaluates structural metrics.

### DNS Analyzer (`app.analyzers.dns_analyzer`)
- Leverages `dnspython` with non-blocking thread execution via `asyncio.to_thread`.
- Queries `A`, `AAAA`, `CNAME`, `NS`, `MX`, and `TXT` records.
- Gracefully handles `NXDOMAIN`, `NoAnswer`, and `Timeout` exceptions without interrupting the overarching scan pipeline.
- Validates public reachability on all returned IP addresses.

### TLS Analyzer (`app.analyzers.tls_analyzer`)
- Executes TLS negotiation using a system-trusted SSL context against the pinned public IP.
- Extracts leaf certificate DER bytes and parses attributes via Python `cryptography`:
  - Subject and Issuer Distinguished Names (RFC 4514)
  - Serial Number (Hex)
  - Subject Alternative Names (SANs)
  - Validity Start and Expiry Timestamps
  - Public Key Algorithm, Key Size, and Elliptic Curves
  - Signature Algorithm (flagging SHA-1 / MD5)
  - SHA-256 Certificate Fingerprint
  - Negotiated TLS Protocol Version and Cipher Suite
- Evaluates certificate status: `VALID`, `INVALID`, `EXPIRED`, `UNKNOWN`, or `NOT_APPLICABLE` (for plaintext HTTP).

---

## 4. Risk Scoring Engine

WebVerity uses an explainable, deterministic rule-based engine. It does not output fake probabilities or hallucinated classifications.

### Weighting Matrix
| Analysis Category | Maximum Weight | Share | Description |
| :--- | :---: | :---: | :--- |
| **URL Anomalies** | 50 points | 50% | IP hosts, @ symbols, punycode, entropy, keywords, depth |
| **DNS Indicators** | 25 points | 25% | NXDOMAIN, missing address records, SSRF attempts |
| **TLS Posture** | 25 points | 25% | Hostname mismatch, expired certs, untrusted chains, weak keys |
| **Total** | **100 points** | **100%** | Bounded composite score |

### Classification Tiers
- **0–24 (LOW):** No strong indicators observed. Accompanied by standard disclaimer: *"No strong threat indicators observed in the completed checks. This does not guarantee that the website is safe."*
- **25–49 (MODERATE):** Suspicious signals or configuration weaknesses detected.
- **50–74 (HIGH):** Substantial threat signals present (e.g. direct IP hosting, missing DNS records, hostname mismatch).
- **75–100 (CRITICAL):** Multiple confirmed deceptive or malicious patterns.

### Evidence Confidence Rating
- **HIGH:** All three modules completed successfully.
- **MEDIUM:** One module timed out or degraded.
- **LOW:** Two or more modules failed or provided insufficient data.

---

## 5. Database Schema & Persistence

Database operations are handled using SQLAlchemy 2.x with the following table model:

```sql
CREATE TABLE scans (
    id VARCHAR(36) PRIMARY KEY,
    submitted_url_redacted VARCHAR(2048) NOT NULL,
    normalized_url VARCHAR(2048) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level VARCHAR(32) NOT NULL,
    confidence VARCHAR(32) NOT NULL,
    results_json JSON NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX ix_scans_domain ON scans (domain);
CREATE INDEX ix_scans_status ON scans (status);
```

### PostgreSQL / Supabase Migration
The database layer reads `DATABASE_URL` dynamically from the environment. Swapping from local SQLite to hosted Supabase PostgreSQL requires only setting:
```bash
DATABASE_URL=postgresql+psycopg2://user:password@db.supabase.co:5432/postgres
```
No query changes or ORM refactoring are required.
