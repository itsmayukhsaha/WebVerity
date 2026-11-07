"""Tests for SSRF security validation, IP filtering, and metadata blocking."""

from backend.app.core.security import (
    is_safe_hostname,
    is_safe_public_ip,
    validate_resolved_ips,
)


def test_loopback_rejection():
    """Verify loopback IPv4 and IPv6 addresses are blocked."""
    safe_v4, _ = is_safe_public_ip("127.0.0.1")
    assert safe_v4 is False

    safe_v4_sub, _ = is_safe_public_ip("127.0.0.53")
    assert safe_v4_sub is False

    safe_v6, _ = is_safe_public_ip("::1")
    assert safe_v6 is False


def test_private_ipv4_rejection():
    """Verify standard RFC 1918 private IPv4 ranges are blocked."""
    for ip in [
        "10.0.0.1",
        "10.254.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.1.254",
    ]:
        safe, reason = is_safe_public_ip(ip)
        assert safe is False, f"Expected {ip} to be blocked as private"
        assert "Private" in reason or "blocked" in reason


def test_private_ipv6_rejection():
    """Verify unique local IPv6 (ULA) addresses are blocked."""
    for ip in ["fc00::1", "fd12:3456:789a:1::1"]:
        safe, reason = is_safe_public_ip(ip)
        assert safe is False, f"Expected {ip} to be blocked"


def test_link_local_and_cloud_metadata_rejection():
    """Verify link-local addresses and cloud metadata IPs are blocked."""
    # AWS/GCP/Azure metadata endpoint
    safe_meta, reason = is_safe_public_ip("169.254.169.254")
    assert safe_meta is False

    # IPv6 link-local
    safe_v6_ll, reason = is_safe_public_ip("fe80::1")
    assert safe_v6_ll is False


def test_ipv4_mapped_ipv6_evasion_blocked():
    """Verify IPv4-mapped IPv6 evasion attempts are unpacked and blocked."""
    safe, _ = is_safe_public_ip("::ffff:127.0.0.1")
    assert safe is False

    safe_priv, _ = is_safe_public_ip("::ffff:192.168.1.1")
    assert safe_priv is False


def test_cgnat_and_reserved_rejection():
    """Verify Carrier Grade NAT and reserved blocks are rejected."""
    safe_cgnat, _ = is_safe_public_ip("100.64.0.1")
    assert safe_cgnat is False

    safe_zero, _ = is_safe_public_ip("0.0.0.0")
    assert safe_zero is False


def test_public_ip_acceptance():
    """Verify standard public routable IPs are accepted."""
    for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"]:
        safe, reason = is_safe_public_ip(ip)
        assert safe is True, f"Expected {ip} to be safe: {reason}"


def test_hostname_ssrf_checks():
    """Verify hostname heuristics catch localhost and metadata domains."""
    safe, reason = is_safe_hostname("localhost")
    assert safe is False

    safe, reason = is_safe_hostname("sub.localhost")
    assert safe is False

    safe, reason = is_safe_hostname("metadata.google.internal")
    assert safe is False

    safe, reason = is_safe_hostname("router.local")
    assert safe is False

    safe, reason = is_safe_hostname("example.com")
    assert safe is True


def test_validate_resolved_ips():
    """Verify resolution containing any unsafe IP results in full rejection."""
    # Mixture containing a private IP
    safe, reason, valid = validate_resolved_ips(["93.184.216.34", "192.168.1.5"])
    assert safe is False
    assert len(valid) == 0

    # All safe public IPs
    safe, reason, valid = validate_resolved_ips(["93.184.216.34", "93.184.216.35"])
    assert safe is True
    assert len(valid) == 2
