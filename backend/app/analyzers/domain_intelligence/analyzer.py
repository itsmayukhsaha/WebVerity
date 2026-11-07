"""Module 5 — RDAP-based domain registration intelligence.

Queries the IANA RDAP bootstrap service to locate the authoritative RDAP
server for a TLD, then requests registration data. Never scrapes WHOIS pages;
returns UNKNOWN whenever data cannot be verified.
"""

import json
from datetime import UTC, datetime
from typing import Any

import httpx
from backend.app.core.logging import logger
from backend.app.schemas.evidence import Finding, Severity

MODULE_NAME = "domain_intelligence"

IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
REQUEST_TIMEOUT = 8.0
MAX_RESPONSE_BYTES = 512 * 1024

NEW_DOMAIN_THRESHOLD_DAYS = 30
EXPIRING_SOON_THRESHOLD_DAYS = 30


def _parse_rdap_date(value: Any) -> datetime | None:
    """Parse RDAP event dates like '1997-09-15T04:00:00Z'."""
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _extract_events(events: Any) -> dict[str, str]:
    """Flatten RDAP events list into {event_type: date_string}."""
    out: dict[str, str] = {}
    if not isinstance(events, list):
        return out
    for event in events:
        if isinstance(event, dict) and "eventAction" in event and "eventDate" in event:
            out[str(event["eventAction"])] = str(event["eventDate"])
    return out


def _get_registrar(entities: Any) -> str | None:
    if not isinstance(entities, list):
        return None
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles") or []
        if "registrar" in roles:
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and item and item[0] == "fn" and len(item) > 3:
                        return str(item[3])
            return entity.get("handle")
    return None


def _bootstrap_rdap_server(tld: str) -> str | None:
    """Resolve the authoritative RDAP endpoint for a TLD via IANA bootstrap."""
    try:
        response = httpx.get(IANA_BOOTSTRAP_URL, timeout=REQUEST_TIMEOUT, follow_redirects=True)
        response.raise_for_status()
        data = json.loads(response.content[:MAX_RESPONSE_BYTES])
    except Exception as e:
        logger.debug(f"RDAP bootstrap fetch failed: {e}")
        return None
    for service in data.get("services", []):
        tlds, urls = service
        if tld.lower() in (t.lower() for t in tlds):
            return urls[0] if urls else None
    return None


def analyze_domain_registration(domain: str) -> tuple[dict[str, Any], list[Finding]]:
    """Query RDAP for registration data and derive domain-age indicators.

    Args:
        domain: Fully qualified domain name.

    Returns:
        Tuple of (module_result_dict, findings_list).
    """
    findings: list[Finding] = []
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""

    base = {
        "module": MODULE_NAME,
        "status": "COMPLETED",
        "domain": domain,
        "domain_age_days": None,
        "registration_date": None,
        "expiration_date": None,
        "last_update_date": None,
        "registrar": None,
        "domain_status": [],
        "nameservers": [],
        "findings": [],
    }

    if not tld:
        base["status"] = "NOT_APPLICABLE"
        return base, findings

    rdap_server = _bootstrap_rdap_server(tld)
    if not rdap_server:
        base["status"] = "UNAVAILABLE"
        base["error"] = f"No RDAP server found for TLD '{tld}'."
        return base, findings

    url = f"{rdap_server.rstrip('/')}/domain/{domain}"
    try:
        response = httpx.get(url, timeout=REQUEST_TIMEOUT, follow_redirects=True)
    except httpx.TimeoutException:
        base["status"] = "TIMEOUT"
        base["error"] = "RDAP query timed out."
        return base, findings
    except httpx.HTTPError as e:
        base["status"] = "FAILED"
        base["error"] = f"RDAP query failed: {e}"
        return base, findings

    if response.status_code == 404:
        base["status"] = "COMPLETED"
        base["error"] = "Domain not registered (RDAP 404)."
        findings.append(
            Finding(
                id="RDAP_DOMAIN_NOT_FOUND",
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="Domain Not Found in RDAP",
                description=(
                    "The RDAP registry reports the domain as not registered. "
                    "Reason: a live site on an unregistered domain is anomalous."
                ),
                evidence={"domain": domain},
            )
        )
        base["findings"] = [f.model_dump() for f in findings]
        return base, findings

    if response.status_code == 429:
        base["status"] = "RATE_LIMITED"
        base["error"] = "RDAP rate limit reached."
        return base, findings

    if response.status_code != 200:
        base["status"] = "FAILED"
        base["error"] = f"RDAP returned HTTP {response.status_code}."
        return base, findings

    try:
        data = json.loads(response.content[:MAX_RESPONSE_BYTES])
    except ValueError:
        base["status"] = "FAILED"
        base["error"] = "RDAP returned invalid JSON."
        return base, findings

    events = _extract_events(data.get("events"))
    registration_date = events.get("registration")
    expiration_date = events.get("expiration")
    last_update_date = events.get("last changed") or events.get("last update of RDAP database")

    reg_dt = _parse_rdap_date(registration_date)
    exp_dt = _parse_rdap_date(expiration_date)

    now = datetime.now(UTC)
    domain_age_days: int | None = None
    days_to_expiration: int | None = None
    if reg_dt:
        domain_age_days = max(0, (now - reg_dt).days)
    if exp_dt:
        days_to_expiration = max(0, (exp_dt - now).days)

    registrar = _get_registrar(data.get("entities"))
    nameservers = [
        str(ns.get("ldhName", "")).lower().rstrip(".")
        for ns in (data.get("nameservers") or [])
        if isinstance(ns, dict) and ns.get("ldhName")
    ]
    domain_status = [str(s) for s in (data.get("status") or [])]

    base.update(
        {
            "registration_date": registration_date,
            "expiration_date": expiration_date,
            "last_update_date": last_update_date,
            "registrar": registrar,
            "nameservers": nameservers,
            "domain_status": domain_status,
            "domain_age_days": domain_age_days,
            "days_to_expiration": days_to_expiration,
            "rdap_server": url.rsplit("/domain/", 1)[0],
        }
    )

    # --- Derived indicators ---
    if domain_age_days is not None and domain_age_days <= NEW_DOMAIN_THRESHOLD_DAYS:
        findings.append(
            Finding(
                id="RDAP_NEW_DOMAIN",
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="Recently Registered Domain",
                description=(
                    f"The domain was registered {domain_age_days} day(s) ago. Reason: phishing "
                    f"campaigns disproportionately use fresh domains, though many legitimate "
                    f"projects launch on new registrations — this is not malicious by itself."
                ),
                evidence={"domain_age_days": domain_age_days},
            )
        )

    if days_to_expiration is not None and 0 < days_to_expiration <= EXPIRING_SOON_THRESHOLD_DAYS:
        findings.append(
            Finding(
                id="RDAP_EXPIRING_SOON",
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="Domain Expiring Soon",
                description=(
                    f"The domain registration expires in {days_to_expiration} day(s). "
                    f"Reason: abandoned/expired domains are sometimes re-registered for abuse."
                ),
                evidence={"days_to_expiration": days_to_expiration},
            )
        )

    if any("pendingDelete" in s or "redemptionPeriod" in s for s in domain_status):
        findings.append(
            Finding(
                id="RDAP_PENDING_DELETE",
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="Domain in PendingDelete / Redemption State",
                description=(
                    "Registry status indicates the domain is being deleted. Reason: "
                    "content served from a de-registered domain is highly anomalous."
                ),
                evidence={"status": domain_status},
            )
        )

    if not registrar and not registration_date:
        findings.append(
            Finding(
                id="RDAP_DATA_WITHHELD",
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="Registration Data Unavailable",
                description=(
                    "RDAP returned data without registrar or registration events "
                    "(possibly privacy-protected). Marked UNKNOWN, not suspicious."
                ),
                evidence={"domain": domain},
            )
        )

    base["findings"] = [f.model_dump() for f in findings]
    return base, findings
