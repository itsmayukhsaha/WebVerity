"""Module 3 — Passive HTML content analyzer.

Parses fetched HTML with BeautifulSoup (no JavaScript execution, no downloads
beyond the initial document) and extracts page identity, forms, links, and
brand-impersonation indicators.
"""

import difflib
import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from backend.app.schemas.evidence import Finding, Severity
from bs4 import BeautifulSoup

MODULE_NAME = "content_analysis"

MAX_HTML_PARSE_BYTES = 1 * 1024 * 1024  # 1 MiB parse cap

# High-profile brand reference dictionary (configurable, intentionally small).
BRAND_REFERENCE: dict[str, dict[str, Any]] = {
    "google": {"domains": ["google.com", "googlemail.com", "gmail.com"]},
    "microsoft": {"domains": ["microsoft.com", "outlook.com", "office.com", "live.com"]},
    "amazon": {"domains": ["amazon.com", "amazon.co.uk", "amzn.to"]},
    "paypal": {"domains": ["paypal.com"]},
    "apple": {"domains": ["apple.com", "icloud.com"]},
    "meta": {"domains": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com"]},
}

# Homoglyph substitutions commonly used in typosquatting.
HOMOGLYPHS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "v": "u",
    "w": "vv",
    "rn": "m",
}

PHISHING_TITLE_PATTERNS = [
    r"\bverify\s+your\s+account\b",
    r"\baccount\s+(has\s+been\s+)?(suspended|locked|blocked)\b",
    r"\bsecurity\s+(alert|warning)\b",
    r"\bconfirm\s+your\s+(identity|password|details)\b",
    r"\burgent\s+action\s+required\b",
    r"\bunusual\s+(login|sign.?in)\b",
]

SUSPICIOUS_FORM_PATH_KEYWORDS = ("login", "verify", "secure", "account", "confirm", "password")


def _registrable(hostname: str | None) -> str:
    if not hostname:
        return ""
    parts = hostname.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) > 2 else ".".join(parts)


def _normalize_brand_token(name: str) -> str:
    """Apply homoglyph normalization for fuzzy brand matching."""
    lowered = name.lower().replace("-", "").replace("_", "")
    for needle, replacement in sorted(HOMOGLYPHS.items(), key=lambda kv: -len(kv[0])):
        lowered = lowered.replace(needle, replacement)
    return lowered


def analyze_brand_impersonation(
    hostname: str | None, page_title: str, html_text: str
) -> dict[str, Any]:
    """Detect potential brand impersonation from hostname and page metadata.

    Returns descriptive indicators only — never a confirmed impersonation.
    """
    analysis: dict[str, Any] = {
        "possible_impersonation": False,
        "matches": [],
        "note": "Heuristic hostname/metadata similarity only; not confirmed impersonation.",
    }
    host = hostname or ""
    host_registrable = _registrable(host)
    if not host_registrable:
        return analysis

    host_unicode = host.encode("idna").decode("ascii").lower()
    if "xn--" in host_unicode:
        analysis["punycode_hostname"] = True

    for brand, meta in BRAND_REFERENCE.items():
        match_evidence: dict[str, Any] = {"brand": brand}

        # 1. Exact official domain → legitimate use, not impersonation.
        if host_registrable == brand or host_registrable in meta["domains"]:
            match_evidence.update({"type": "OFFICIAL_DOMAIN", "suspicious": False})
            analysis["matches"].append(match_evidence)
            continue

        # 2. Brand token embedded in an unrelated hostname.
        brand_norm = _normalize_brand_token(brand)
        host_tokens = re.split(r"[.\-_]", _normalize_brand_token(host))
        if brand_norm in host_tokens:
            match_evidence.update(
                {
                    "type": "BRAND_IN_HOSTNAME",
                    "suspicious": host_registrable not in meta["domains"],
                    "detail": f"Brand token '{brand}' appears in hostname '{host}'.",
                }
            )
            analysis["matches"].append(match_evidence)

        # 3. Fuzzy similarity to official domain (typosquatting).
        # Requires BOTH a high ratio AND near-identical length to avoid
        # coincidental overlap between short unrelated domains
        # (e.g. 'example.com' vs 'apple.com').
        best_ratio = 0.0
        best_domain = None
        for domain in meta["domains"]:
            ratio = difflib.SequenceMatcher(
                None, _normalize_brand_token(host_registrable), _normalize_brand_token(domain)
            ).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_domain = domain
        length_delta = abs(len(host_registrable) - len(best_domain or ""))
        if (
            0.86 <= best_ratio < 1.0
            and length_delta <= 2
            and host_registrable not in meta["domains"]
        ):
            match_evidence.update(
                {
                    "type": "DOMAIN_SIMILARITY",
                    "suspicious": True,
                    "detail": f"Hostname '{host_registrable}' is {best_ratio:.0%} similar to an official '{brand}' domain.",
                }
            )
            analysis["matches"].append(match_evidence)

        # 4. Brand name in page title on a non-official domain.
        if brand in page_title.lower() and host_registrable not in meta["domains"]:
            match_evidence.update(
                {
                    "type": "BRAND_IN_TITLE_MISMATCH",
                    "suspicious": True,
                    "detail": f"Page title references '{brand}' but is hosted on '{host_registrable}'.",
                }
            )
            analysis["matches"].append(match_evidence)

    suspicious_matches = [m for m in analysis["matches"] if m.get("suspicious")]
    analysis["possible_impersonation"] = bool(suspicious_matches)
    return analysis


def analyze_content(
    url: str, body: bytes, final_hostname: str | None
) -> tuple[dict[str, Any], list[Finding]]:
    """Parse and assess HTML content.

    Args:
        url: Final URL of the fetched document.
        body: Raw response bytes (may be non-HTML; caller checks content type).
        final_hostname: Hostname the document was served from.

    Returns:
        Tuple of (module_result_dict, findings_list).
    """
    findings: list[Finding] = []

    if len(body) > MAX_HTML_PARSE_BYTES:
        body = body[:MAX_HTML_PARSE_BYTES]
        findings.append(
            Finding(
                id="CONTENT_TRUNCATED",
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="HTML Truncated for Parsing",
                description=(
                    "Response exceeded the 1 MiB parse limit and was truncated before "
                    "analysis. Reason: resource safety limit."
                ),
                evidence={"limit_bytes": MAX_HTML_PARSE_BYTES},
            )
        )

    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover - decode with replace rarely fails
        text = ""
    try:
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        soup = BeautifulSoup(text, "html.parser")

    title = (soup.title.string or "").strip()[:300] if soup.title and soup.title.string else ""
    meta_desc_tag = soup.find("meta", attrs={"name": "description"})
    meta_description = (meta_desc_tag.get("content") or "").strip()[:300] if meta_desc_tag else ""
    canonical_tag = soup.find("link", rel=lambda v: v and "canonical" in v)
    canonical_url = (canonical_tag.get("href") or "").strip() if canonical_tag else ""
    favicon_tag = soup.find("link", rel=lambda v: v and "icon" in v)
    favicon_url = (favicon_tag.get("href") or "").strip() if favicon_tag else ""
    html_lang = (soup.find("html").get("lang") or "").strip() if soup.find("html") else ""

    # Forms analysis
    forms = soup.find_all("form")
    password_fields = sum(
        1 for inp in soup.find_all("input") if (inp.get("type") or "").lower() == "password"
    )
    external_form_actions: list[str] = []
    suspicious_form_actions: list[str] = []
    if final_hostname:
        final_registrable = _registrable(final_hostname)
        for form in forms:
            action = (form.get("action") or "").strip()
            if not action or action.startswith("#"):
                continue
            resolved = urljoin(url, action)
            action_host = urlsplit(resolved).hostname
            if action_host and _registrable(action_host) != final_registrable:
                external_form_actions.append(resolved[:300])
            lowered_action = (action_host or "") + urlsplit(resolved).path
            if any(kw in lowered_action.lower() for kw in SUSPICIOUS_FORM_PATH_KEYWORDS):
                suspicious_form_actions.append(resolved[:300])

    # Link classification
    internal_links = 0
    external_links = 0
    if final_hostname:
        final_registrable = _registrable(final_hostname)
        for anchor in soup.find_all("a", href=True):
            href = (anchor.get("href") or "").strip()
            if href.startswith(("mailto:", "javascript:", "tel:")):
                continue
            resolved = urljoin(url, href)
            link_host = urlsplit(resolved).hostname
            if not link_host:
                internal_links += 1
            elif _registrable(link_host) == final_registrable:
                internal_links += 1
            else:
                external_links += 1

    external_resources = 0
    if final_hostname:
        final_registrable = _registrable(final_hostname)
        for tag_name in ("script", "img", "iframe", "link"):
            for tag in soup.find_all(tag_name, src=True) + soup.find_all(tag_name, href=True):
                resource_host = urlsplit(
                    urljoin(url, tag.get("src") or tag.get("href") or "")
                ).hostname
                if resource_host and _registrable(resource_host) != final_registrable:
                    external_resources += 1

    iframes = soup.find_all("iframe")
    meta_refresh = soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "refresh"})
    meta_refresh_content = (meta_refresh.get("content") or "") if meta_refresh else None

    # --- Findings ---

    if password_fields > 0:
        findings.append(
            Finding(
                id="CONTENT_PASSWORD_INPUT",
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="Password Input Present",
                description=(
                    f"The page contains {password_fields} password input field(s). A login "
                    f"form alone is not evidence of phishing; it requires correlation with "
                    f"other indicators."
                ),
                evidence={"password_fields": password_fields, "forms_total": len(forms)},
            )
        )

    if external_form_actions:
        findings.append(
            Finding(
                id="CONTENT_EXTERNAL_FORM_ACTION",
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="Form Submits to External Domain",
                description=(
                    "One or more forms post data to a domain different from the page host. "
                    "Reason: credential-harvesting kits commonly relay stolen input to "
                    "third-party servers, though some legitimate flows do this too."
                ),
                evidence={"actions": external_form_actions[:5]},
            )
        )

    for pattern in PHISHING_TITLE_PATTERNS:
        if re.search(pattern, title.lower()):
            findings.append(
                Finding(
                    id="CONTENT_DECEPTIVE_METADATA",
                    module=MODULE_NAME,
                    severity=Severity.MEDIUM,
                    title="Deceptive Page Metadata Pattern",
                    description=(
                        f"Page title matches pressure-tactic pattern '{pattern}'. Reason: "
                        f"urgency/credential-pressure phrasing is characteristic of phishing "
                        f"lures, though it also occurs in legitimate notifications."
                    ),
                    evidence={"title": title[:200]},
                )
            )
            break

    brand_analysis = analyze_brand_impersonation(final_hostname, title, text[:20000])
    for match in brand_analysis.get("matches", []):
        if not match.get("suspicious"):
            continue
        findings.append(
            Finding(
                id="CONTENT_BRAND_IMPERSONATION",
                module=MODULE_NAME,
                severity=Severity.HIGH,
                title="Potential Brand Impersonation Indicator",
                description=(
                    f"{match['detail']} Reason: brand tokens, lookalike domains, and "
                    f"identity mismatch are common phishing pretexts. This is a potential "
                    f"impersonation indicator, not a confirmed impersonation."
                ),
                evidence={"brand": match["brand"], "type": match["type"]},
            )
        )

    if "xn--" in (final_hostname or "").encode("idna").decode("ascii").lower():
        findings.append(
            Finding(
                id="CONTENT_PUNYCODE_HOST",
                module=MODULE_NAME,
                severity=Severity.MEDIUM,
                title="Punycode Hostname Serving Content",
                description=(
                    "The content is served from an internationalized (xn--) hostname, "
                    "which can visually imitate well-known domains (homograph attack)."
                ),
                evidence={"hostname": final_hostname},
            )
        )

    if external_links > 40 and (internal_links + external_links) > 0:
        findings.append(
            Finding(
                id="CONTENT_EXCESSIVE_EXTERNAL_LINKS",
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="Excessive External Link Density",
                description=(
                    f"The page contains {external_links} external links. Reason: link farms "
                    f"and spam pages exhibit unusually high external link counts."
                ),
                evidence={"external_links": external_links, "internal_links": internal_links},
            )
        )

    if meta_refresh_content:
        findings.append(
            Finding(
                id="CONTENT_META_REFRESH",
                module=MODULE_NAME,
                severity=Severity.LOW,
                title="Meta Refresh Redirect",
                description=(
                    "The page declares a meta-refresh redirect. Reason: client-side "
                    "refreshes can chain users to a second, different destination."
                ),
                evidence={"content": meta_refresh_content[:100]},
            )
        )

    if not title and not meta_description and len(forms) == 0:
        findings.append(
            Finding(
                id="CONTENT_EMPTY_PAGE",
                module=MODULE_NAME,
                severity=Severity.INFO,
                title="Sparse Page Identity",
                description=(
                    "No title, description, or forms were found. Reason: empty or "
                    "cloaked pages are used to evade content-based inspection."
                ),
                evidence={},
            )
        )

    result: dict[str, Any] = {
        "module": MODULE_NAME,
        "status": "COMPLETED",
        "page_title": title,
        "meta_description": meta_description,
        "canonical_url": canonical_url,
        "favicon_url": favicon_url,
        "declared_language": html_lang,
        "forms": {
            "total": len(forms),
            "password_fields": password_fields,
            "external_form_actions": external_form_actions,
        },
        "links": {"internal": internal_links, "external": external_links},
        "external_resource_count": external_resources,
        "iframes": len(iframes),
        "meta_refresh": meta_refresh_content,
        "brand_analysis": brand_analysis,
        "findings": [f.model_dump() for f in findings],
    }
    return result, findings
