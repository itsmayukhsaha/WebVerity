"""URL feature extraction and anomaly detection module."""

import math
from typing import Any
from urllib.parse import unquote

from backend.app.analyzers.url_analyzer.normalizer import NormalizedURL
from backend.app.core.security import is_ip_address
from backend.app.schemas.evidence import Finding, Severity

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "banking",
    "payment",
    "password",
    "authentication",
    "confirm",
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for a given string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def count_subdomains(hostname: str) -> int:
    """Count subdomains in a hostname.

    Example:
    'example.com' -> 0 subdomains
    'sub.example.com' -> 1 subdomain
    'a.b.example.com' -> 2 subdomains
    """
    if is_ip_address(hostname):
        return 0
    parts = [p for p in hostname.split(".") if p]
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


def extract_url_features(
    normalized: NormalizedURL, raw_url: str
) -> tuple[dict[str, Any], list[Finding]]:
    """Extract deterministic URL characteristics and generate rule-based findings.

    Args:
        normalized: NormalizedURL structure.
        raw_url: Original submitted URL.

    Returns:
        Tuple of (features_dict, findings_list).
    """
    url_str = normalized.normalized_url
    hostname = normalized.hostname
    path = normalized.path
    query = normalized.query

    # Structural metrics
    url_length = len(url_str)
    hostname_length = len(hostname)
    dot_count = url_str.count(".")
    hostname_dot_count = hostname.count(".")
    subdomain_count = count_subdomains(hostname)
    hyphen_count = url_str.count("-")
    hostname_hyphen_count = hostname.count("-")
    digit_count = sum(c.isdigit() for c in url_str)
    hostname_digit_count = sum(c.isdigit() for c in hostname)

    # Special character counting (!, @, #, $, %, ^, &, *, _, ~, +, =, ;)
    special_chars = set("!@#$%^&*()_+=[]{}|;:,<>?~")
    special_char_count = sum(c in special_chars for c in url_str)

    has_ip = is_ip_address(hostname)
    has_at_symbol = "@" in raw_url or "@" in url_str
    has_punycode = normalized.has_punycode

    # Suspicious encoding checks
    percent_count = url_str.count("%")
    has_suspicious_encoding = False
    if percent_count > 3:
        has_suspicious_encoding = True
    # Check for encoded dots, slashes (%2e, %2f)
    lower_raw = raw_url.lower()
    if "%2e" in lower_raw or "%2f" in lower_raw or "%5c" in lower_raw:
        has_suspicious_encoding = True

    # Path depth
    path_segments = [p for p in path.strip("/").split("/") if p]
    path_depth = len(path_segments)
    excessive_nested_paths = path_depth >= 5

    # Query length
    query_length = len(query)
    excessive_query_length = query_length > 100

    # Keyword search across hostname, path, and decoded query
    found_keywords: list[str] = []
    combined_lower = f"{hostname}/{path}/{unquote(query)}".lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in combined_lower:
            found_keywords.append(kw)

    contains_suspicious_keywords = len(found_keywords) > 0
    hostname_entropy = calculate_entropy(hostname)

    features: dict[str, Any] = {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "dot_count": dot_count,
        "hostname_dot_count": hostname_dot_count,
        "subdomain_count": subdomain_count,
        "hyphen_count": hyphen_count,
        "hostname_hyphen_count": hostname_hyphen_count,
        "digit_count": digit_count,
        "hostname_digit_count": hostname_digit_count,
        "special_char_count": special_char_count,
        "has_ip_hostname": has_ip,
        "has_punycode": has_punycode,
        "unicode_hostname": normalized.unicode_hostname if has_punycode else None,
        "has_at_symbol": has_at_symbol,
        "has_suspicious_encoding": has_suspicious_encoding,
        "percent_count": percent_count,
        "path_depth": path_depth,
        "excessive_nested_paths": excessive_nested_paths,
        "query_length": query_length,
        "excessive_query_length": excessive_query_length,
        "contains_suspicious_keywords": contains_suspicious_keywords,
        "matched_keywords": found_keywords,
        "hostname_entropy": hostname_entropy,
    }

    # Generate findings based on extracted features
    findings: list[Finding] = []

    if has_ip:
        findings.append(
            Finding(
                id="URL_IP_HOST",
                module="url_analysis",
                severity=Severity.HIGH,
                title="Direct IP Address Hostname",
                description="The URL uses a raw IP address instead of a registered domain name, common in phishing and ad-hoc malicious infrastructure.",
                evidence={"hostname": hostname},
            )
        )

    if has_punycode:
        findings.append(
            Finding(
                id="URL_PUNYCODE",
                module="url_analysis",
                severity=Severity.MEDIUM,
                title="Punycode Internationalized Domain",
                description=f"Domain contains punycode encoding (xn--) resolving to '{normalized.unicode_hostname}', which can be abused for homograph visual spoofing.",
                evidence={"hostname": hostname, "unicode_domain": normalized.unicode_hostname},
            )
        )

    if has_at_symbol:
        findings.append(
            Finding(
                id="URL_AT_SYMBOL",
                module="url_analysis",
                severity=Severity.HIGH,
                title="Embedded @ Character in URL",
                description="The URL contains an '@' character, which can deceive users about the destination host.",
                evidence={"url": normalized.redacted_url},
            )
        )

    if has_suspicious_encoding:
        findings.append(
            Finding(
                id="URL_SUSPICIOUS_ENCODING",
                module="url_analysis",
                severity=Severity.MEDIUM,
                title="Suspicious Percent Encoding",
                description="URL includes high percent-encoding frequency or obfuscated path separators.",
                evidence={"percent_count": percent_count},
            )
        )

    if subdomain_count >= 3:
        findings.append(
            Finding(
                id="URL_EXCESSIVE_SUBDOMAINS",
                module="url_analysis",
                severity=Severity.MEDIUM,
                title="Excessive Subdomain Depth",
                description=f"Hostname contains {subdomain_count} subdomain levels, often used to conceal malicious hosting beneath complex prefixes.",
                evidence={"subdomain_count": subdomain_count, "hostname": hostname},
            )
        )

    if url_length > 100:
        findings.append(
            Finding(
                id="URL_EXCESSIVE_LENGTH",
                module="url_analysis",
                severity=Severity.LOW,
                title="Abnormally Long URL",
                description=f"Total URL length ({url_length} characters) is unusually large, typical of obfuscated links or token redirection.",
                evidence={"url_length": url_length},
            )
        )

    if contains_suspicious_keywords:
        findings.append(
            Finding(
                id="URL_SUSPICIOUS_KEYWORDS",
                module="url_analysis",
                severity=Severity.LOW,
                title="Suspicious Security/Authentication Keywords",
                description=f"URL path or query contains sensitive authentication terms ({', '.join(found_keywords)}). Note: Legitimate sites also use these words; requires correlation.",
                evidence={"matched_keywords": found_keywords},
            )
        )

    if hostname_hyphen_count >= 3:
        findings.append(
            Finding(
                id="URL_EXCESSIVE_HYPHENS",
                module="url_analysis",
                severity=Severity.LOW,
                title="Multiple Hyphens in Hostname",
                description=f"Hostname contains {hostname_hyphen_count} hyphens, frequently utilized in typosquatting and deceptive brand-mimicking domains.",
                evidence={"hostname_hyphen_count": hostname_hyphen_count},
            )
        )

    if hostname_entropy > 4.2:
        findings.append(
            Finding(
                id="URL_HIGH_ENTROPY_HOST",
                module="url_analysis",
                severity=Severity.LOW,
                title="High Hostname Entropy",
                description=f"Hostname exhibits high Shannon randomness ({hostname_entropy}), suggestive of algorithmic domain generation (DGA).",
                evidence={"entropy": hostname_entropy},
            )
        )

    return features, findings
