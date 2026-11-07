"""Tests for DNS analyzer with mocked network lookups."""

from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
from backend.app.analyzers.dns_analyzer.analyzer import analyze_dns


@patch("dns.resolver.Resolver.resolve")
def test_successful_dns_resolution(mock_resolve):
    """Verify standard DNS records are queried and formatted."""

    def side_effect(domain, rtype):
        mock_answer = MagicMock()
        if rtype == "A":
            record = MagicMock()
            record.address = "93.184.216.34"
            mock_answer.__iter__.return_value = [record]
            return mock_answer
        elif rtype == "MX":
            record = MagicMock()
            record.preference = 10
            record.exchange.to_text.return_value = "mail.example.com."
            mock_answer.__iter__.return_value = [record]
            return mock_answer
        raise dns.resolver.NoAnswer()

    mock_resolve.side_effect = side_effect

    res, findings, valid_ips = analyze_dns("example.com")
    assert res["dns_status"] == "RESOLVED"
    assert "93.184.216.34" in res["records"]["A"]
    assert len(valid_ips) == 1
    assert valid_ips[0] == "93.184.216.34"


@patch("dns.resolver.Resolver.resolve")
def test_nxdomain_handling(mock_resolve):
    """Verify NXDOMAIN produces proper status and finding."""
    mock_resolve.side_effect = dns.resolver.NXDOMAIN()

    res, findings, valid_ips = analyze_dns("nonexistent-domain-123456.com")
    assert res["dns_status"] == "NXDOMAIN"
    assert len(valid_ips) == 0
    finding_ids = [f.id for f in findings]
    assert "DNS_NXDOMAIN" in finding_ids


@patch("dns.resolver.Resolver.resolve")
def test_dns_timeout_handling(mock_resolve):
    """Verify timeout produces TIMEOUT status without crashing."""
    mock_resolve.side_effect = dns.exception.Timeout()

    res, findings, valid_ips = analyze_dns("slow-dns-server.com")
    assert res["dns_status"] == "TIMEOUT"
    finding_ids = [f.id for f in findings]
    assert "DNS_TIMEOUT" in finding_ids


@patch("dns.resolver.Resolver.resolve")
def test_dns_ssrf_unsafe_resolution(mock_resolve):
    """Verify a domain resolving to an internal IP is blocked and flagged."""

    def side_effect(domain, rtype):
        if rtype == "A":
            record = MagicMock()
            record.address = "127.0.0.1"  # Unsafe loopback
            mock_answer = MagicMock()
            mock_answer.__iter__.return_value = [record]
            return mock_answer
        raise dns.resolver.NoAnswer()

    mock_resolve.side_effect = side_effect

    res, findings, valid_ips = analyze_dns("rebinding.example.com")
    assert res["dns_status"] == "SSRF_BLOCKED"
    assert len(valid_ips) == 0
    finding_ids = [f.id for f in findings]
    assert "DNS_SSRF_UNSAFE_IP" in finding_ids


def test_direct_ip_dns_analysis():
    """Verify direct public IP target passes without DNS lookup."""
    res, findings, valid_ips = analyze_dns("93.184.216.34")
    assert res["dns_status"] == "RESOLVED"
    assert "93.184.216.34" in valid_ips

    # Direct private IP target is blocked
    res_priv, findings_priv, valid_ips_priv = analyze_dns("192.168.1.1")
    assert res_priv["dns_status"] == "SSRF_BLOCKED"
    assert len(valid_ips_priv) == 0
