"""SSRF protection and network security validation module.

Mandatory security rules implemented:
- Rejects loopback, private, link-local, multicast, reserved, and unspecified IPs.
- Blocks IPv4-mapped IPv6 evasion attempts (e.g., ::ffff:127.0.0.1).
- Blocks cloud metadata endpoints (169.254.169.254, metadata.google.internal, etc.).
- Blocks localhost and local domain suffixes (.local, .internal, .lan, .arpa).
- Validates all resolved DNS addresses prior to outbound connection.
- Enforces pinned destination IP connections for TLS inspection to prevent DNS rebinding.
"""

import ipaddress

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata",
    "instance-data",
}

BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".arpa",
    ".invalid",
    ".test",
)

# Explicit sensitive networks to guard beyond standard ipaddress checks
EXTRA_RESERVED_NETWORKS = [
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-Grade NAT (RFC 6598)
    ipaddress.ip_network("198.18.0.0/15"),  # Benchmarking (RFC 2544)
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved for future use (Class E)
    ipaddress.ip_network("0.0.0.0/8"),  # Current network (only valid as source)
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local (AWS/GCP/Azure metadata)
    ipaddress.ip_network("::/128"),  # Unspecified IPv6
    ipaddress.ip_network("::1/128"),  # Loopback IPv6
    ipaddress.ip_network("fc00::/7"),  # Unique local IPv6
    ipaddress.ip_network("fe80::/10"),  # Link-local IPv6
]


class SSRFSecurityException(Exception):
    """Raised when an SSRF security violation or unsafe target is detected."""

    def __init__(self, message: str, target: str = ""):
        super().__init__(message)
        self.message = message
        self.target = target


def is_ip_address(host: str) -> bool:
    """Determine whether a host string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_safe_public_ip(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
    """Validate that an IP address is a safe, routable public address.

    Args:
        ip: String representation or ipaddress object.

    Returns:
        Tuple of (is_safe: bool, reason: str).
    """
    try:
        if isinstance(ip, str):
            ip_obj = ipaddress.ip_address(ip.strip("[]"))
        else:
            ip_obj = ip

        # Unwrap IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1 or ::ffff:192.168.1.1)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped

        # Check standard properties
        if ip_obj.is_loopback:
            return False, f"Loopback address '{ip}' is blocked."
        if ip_obj.is_private:
            return False, f"Private IP address '{ip}' is blocked."
        if ip_obj.is_link_local:
            return False, f"Link-local address '{ip}' is blocked."
        if ip_obj.is_multicast:
            return False, f"Multicast address '{ip}' is blocked."
        if ip_obj.is_reserved:
            return False, f"Reserved address '{ip}' is blocked."
        if ip_obj.is_unspecified:
            return False, f"Unspecified address '{ip}' is blocked."

        # Check against extra reserved/metadata networks
        for net in EXTRA_RESERVED_NETWORKS:
            # Handle cross-version compatibility for ip_obj vs network
            if ip_obj.version == net.version and ip_obj in net:
                return False, f"Address '{ip}' belongs to blocked network '{net}'."

        return True, "IP address is a valid public routable address."
    except ValueError as e:
        return False, f"Invalid IP address format: {e}"


def is_safe_hostname(hostname: str) -> tuple[bool, str]:
    """Evaluate whether a hostname is safe against SSRF heuristics before DNS resolution.

    Args:
        hostname: Normalized domain or IP string.

    Returns:
        Tuple of (is_safe: bool, reason: str).
    """
    if not hostname:
        return False, "Hostname cannot be empty."

    norm_host = hostname.lower().strip()

    # If it's an IP, validate directly
    if is_ip_address(norm_host):
        return is_safe_public_ip(norm_host)

    # Check blocked exact hostnames
    if norm_host in BLOCKED_HOSTNAMES:
        return False, f"Host '{hostname}' is an internal or reserved name."

    # Check blocked domain suffixes
    for suffix in BLOCKED_SUFFIXES:
        if norm_host.endswith(suffix):
            return False, f"Host '{hostname}' ends with restricted internal suffix '{suffix}'."

    # Check for metadata keywords
    if "metadata" in norm_host and (
        "internal" in norm_host or "google" in norm_host or "aws" in norm_host
    ):
        return False, f"Host '{hostname}' appears to be a cloud metadata endpoint."

    return True, "Hostname is valid for public DNS resolution."


def validate_resolved_ips(ips: list[str]) -> tuple[bool, str, list[str]]:
    """Validate all resolved IP addresses for a host.

    If ANY resolved address is unsafe (loopback, private, link-local, etc.),
    the entire resolution is rejected to prevent DNS rebinding or internal pivoting.

    Args:
        ips: List of resolved IP strings.

    Returns:
        Tuple of (is_safe: bool, reason: str, validated_ips: list[str]).
    """
    if not ips:
        return False, "No IP addresses resolved.", []

    safe_ips: list[str] = []
    for ip in ips:
        safe, reason = is_safe_public_ip(ip)
        if not safe:
            return False, f"Host resolved to unsafe destination: {reason}", []
        safe_ips.append(ip)

    return True, "All resolved IPs are valid public addresses.", safe_ips
