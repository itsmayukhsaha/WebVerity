# WebVerity REST API Documentation

Base URL: `http://localhost:8000/api/v1`

---

## 1. Health Check

Checks service availability and returns version metadata.

- **Method:** `GET`
- **Path:** `/api/v1/health`
- **Auth Required:** No

### Response (200 OK)
```json
{
  "status": "healthy",
  "service": "WebVerity",
  "version": "0.1.0",
  "environment": "development"
}
```

---

## 2. Submit URL for Scan

Submits a target URL to the WebVerity scanner. Initiates immediate multi-layer analysis across URL structure, DNS configuration, and TLS certificate validation.

- **Method:** `POST`
- **Path:** `/api/v1/scans`
- **Content-Type:** `application/json`

### Request Body
```json
{
  "url": "https://example.com/login"
}
```

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `url` | string | Yes | Full target URL (length: 3 to 2048 characters). Must start with `http://` or `https://`. |

### Response (201 Created)
```json
{
  "scan_id": "8489cf30-6b6f-4424-9b22-544ef4aebecf",
  "status": "COMPLETED",
  "target": "example.com",
  "threat_assessment": {
    "risk_score": 10,
    "classification": "LOW",
    "confidence": "HIGH",
    "is_probability": false,
    "explanation": "No strong threat indicators observed in the completed checks. This does not guarantee that the website is safe."
  },
  "modules": {
    "url_analysis": {
      "module": "url_analysis",
      "features": {
        "url_length": 25,
        "hostname_length": 11,
        "dot_count": 1,
        "hostname_dot_count": 1,
        "subdomain_count": 0,
        "hyphen_count": 0,
        "hostname_hyphen_count": 0,
        "digit_count": 0,
        "special_char_count": 0,
        "has_ip_hostname": false,
        "has_punycode": false,
        "has_at_symbol": false,
        "has_suspicious_encoding": false,
        "contains_suspicious_keywords": true,
        "matched_keywords": ["login"],
        "hostname_entropy": 2.855
      },
      "findings": [
        {
          "id": "URL_SUSPICIOUS_KEYWORDS",
          "module": "url_analysis",
          "severity": "LOW",
          "title": "Suspicious Security/Authentication Keywords",
          "description": "URL path or query contains sensitive authentication terms (login).",
          "evidence": { "matched_keywords": ["login"] },
          "timestamp": "2026-11-07T06:00:00Z"
        }
      ],
      "status": "COMPLETED"
    },
    "dns_analysis": {
      "module": "dns_analysis",
      "domain": "example.com",
      "records": {
        "A": ["93.184.216.34"],
        "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
        "CNAME": [],
        "NS": ["a.iana-servers.net", "b.iana-servers.net"],
        "MX": [],
        "TXT": ["v=spf1 -all"]
      },
      "dns_status": "RESOLVED",
      "findings": []
    },
    "tls_analysis": {
      "module": "tls_analysis",
      "status": "COMPLETED",
      "https_enabled": true,
      "hostname_match": true,
      "chain_validation": "VALID",
      "certificate_expired": false,
      "issuer": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
      "tls_version": "TLSv1.3",
      "cipher": "TLS_AES_256_GCM_SHA384",
      "certificate": {
        "subject": { "common_name": "www.example.org" },
        "issuer": { "common_name": "DigiCert Global G2 TLS RSA SHA256 2020 CA1" },
        "serial_number": "0C7F...",
        "subject_alternative_names": ["example.com", "*.example.com"],
        "validity_start": "2024-01-15T00:00:00Z",
        "validity_expiry": "2025-01-15T23:59:59Z",
        "is_expired": false,
        "is_not_yet_valid": false,
        "days_until_expiry": 68,
        "public_key": {
          "algorithm": "RSA",
          "key_size": 2048,
          "curve": null
        },
        "signature_algorithm": "sha256WithRSAEncryption",
        "sha256_fingerprint": "B8:94:..."
      },
      "findings": []
    }
  },
  "findings": [
    {
      "id": "URL_SUSPICIOUS_KEYWORDS",
      "module": "url_analysis",
      "severity": "LOW",
      "title": "Suspicious Security/Authentication Keywords",
      "description": "URL path or query contains sensitive authentication terms (login).",
      "evidence": { "matched_keywords": ["login"] },
      "timestamp": "2026-11-07T06:00:00Z"
    }
  ],
  "created_at": "2026-11-07T06:00:00Z",
  "completed_at": "2026-11-07T06:00:01Z"
}
```

### Error Responses

#### 400 Bad Request — Invalid URL Structure
```json
{
  "detail": "Port 8080 is not permitted. Only standard HTTP (80) and HTTPS (443) ports are allowed."
}
```

#### 400 Bad Request — SSRF Violation
```json
{
  "detail": "Security rejection: Host '192.168.1.1' is an internal or reserved name."
}
```

---

## 3. Retrieve Scan by ID

Fetches persistent audit record and analysis results for a previous scan.

- **Method:** `GET`
- **Path:** `/api/v1/scans/{scan_id}`

### Path Parameters
| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `scan_id` | string (UUID) | Yes | Unique scan identifier returned at creation. |

### Response (200 OK)
Returns the identical `ScanResponse` contract as `POST /api/v1/scans`.

### Error Responses

#### 404 Not Found
```json
{
  "detail": "Scan record with ID '8489cf30-6b6f-4424-9b22-544ef4aebecf' not found."
}
```
