"""
Tests for parsing helper functions in server.py.
"""

import pytest
from threat_intel_mcp.server import parse_ip_list, parse_url_list, parse_cidr_list


class TestParseIPList:
    """Test IP list parsing functionality."""

    def test_parse_valid_ips(self):
        """Should parse valid IP addresses from text content."""
        content = """# Comment
192.0.2.1
10.0.0.1
172.16.0.1
# Another comment
"""
        ips = parse_ip_list(content)
        assert len(ips) == 3
        assert "192.0.2.1" in ips
        assert "10.0.0.1" in ips
        assert "172.16.0.1" in ips

    def test_parse_ips_with_whitespace(self):
        """Should handle leading/trailing whitespace."""
        content = """  192.0.2.1
   10.0.0.1
172.16.0.1   """
        ips = parse_ip_list(content)
        assert len(ips) == 3

    def test_parse_ips_with_extra_columns(self):
        """Should extract IP from first column when additional data present."""
        content = """192.0.2.1 malware.example.com
10.0.0.1 # inline comment
172.16.0.1 botnet c2"""
        ips = parse_ip_list(content)
        assert len(ips) == 3
        assert "192.0.2.1" in ips

    def test_parse_skips_comments(self):
        """Should skip lines starting with #."""
        content = """# This is a comment
192.0.2.1
# Another comment
10.0.0.1"""
        ips = parse_ip_list(content)
        assert len(ips) == 2
        assert all(not ip.startswith("#") for ip in ips)

    def test_parse_invalid_ips_filtered(self):
        """Should filter out invalid IP addresses."""
        content = """192.0.2.1
999.999.999.999
10.0.0.1
not-an-ip
256.1.1.1"""
        ips = parse_ip_list(content)
        assert len(ips) == 2
        assert "192.0.2.1" in ips
        assert "10.0.0.1" in ips

    def test_parse_empty_content(self):
        """Should handle empty content."""
        assert parse_ip_list("") == []
        assert parse_ip_list("\n\n\n") == []

    def test_parse_ipv6_addresses(self):
        """Should handle IPv6 addresses."""
        content = """2001:0db8:85a3::8a2e:0370:7334
fe80::1
::1"""
        ips = parse_ip_list(content)
        assert len(ips) == 3
        assert "2001:0db8:85a3::8a2e:0370:7334" in ips or "2001:db8:85a3::8a2e:370:7334" in ips


class TestParseURLList:
    """Test URL list parsing functionality."""

    def test_parse_valid_urls(self):
        """Should parse valid URLs."""
        content = """http://malware.example.com/payload.exe
https://phishing.example.com/login.php
http://botnet.cc/c2"""
        urls = parse_url_list(content)
        assert len(urls) == 3
        assert "http://malware.example.com/payload.exe" in urls
        assert "https://phishing.example.com/login.php" in urls

    def test_parse_skips_comments(self):
        """Should skip comment lines."""
        content = """# Malware URLs
http://malware.example.com/payload.exe
# Phishing
https://phishing.example.com/login.php"""
        urls = parse_url_list(content)
        assert len(urls) == 2
        assert all(url.startswith("http") for url in urls)

    def test_parse_requires_http_prefix(self):
        """Should only accept URLs starting with http:// or https://."""
        content = """http://valid.com
ftp://invalid.com
www.invalid.com
https://valid2.com"""
        urls = parse_url_list(content)
        assert len(urls) == 2
        assert "http://valid.com" in urls
        assert "https://valid2.com" in urls

    def test_parse_empty_content(self):
        """Should handle empty content."""
        assert parse_url_list("") == []
        assert parse_url_list("\n\n") == []

    def test_parse_with_whitespace(self):
        """Should trim whitespace from URLs."""
        content = """  http://example.com
   https://example2.com
http://example3.com   """
        urls = parse_url_list(content)
        assert len(urls) == 3


class TestParseCIDRList:
    """Test CIDR notation parsing functionality."""

    def test_parse_valid_cidrs(self):
        """Should parse valid CIDR blocks."""
        content = """192.0.2.0/24
10.0.0.0/8
172.16.0.0/12"""
        cidrs = parse_cidr_list(content)
        assert len(cidrs) == 3
        assert "192.0.2.0/24" in cidrs
        assert "10.0.0.0/8" in cidrs

    def test_parse_skips_semicolon_comments(self):
        """Should skip lines starting with ; (Spamhaus format)."""
        content = """; Comment
192.0.2.0/24
; Another comment
10.0.0.0/8"""
        cidrs = parse_cidr_list(content)
        assert len(cidrs) == 2

    def test_parse_skips_hash_comments(self):
        """Should skip lines starting with #."""
        content = """# Comment
192.0.2.0/24
# Another comment
10.0.0.0/8"""
        cidrs = parse_cidr_list(content)
        assert len(cidrs) == 2

    def test_parse_cidr_with_extra_data(self):
        """Should extract CIDR from first column."""
        content = """192.0.2.0/24 ; SBL123456
10.0.0.0/8 extra data"""
        cidrs = parse_cidr_list(content)
        assert len(cidrs) == 2
        assert "192.0.2.0/24" in cidrs

    def test_parse_invalid_cidrs_filtered(self):
        """Should filter out invalid CIDR notation."""
        content = """192.0.2.0/24
999.999.999.999/32
10.0.0.0/8
not-a-cidr
256.1.1.1/16"""
        cidrs = parse_cidr_list(content)
        assert len(cidrs) == 2
        assert "192.0.2.0/24" in cidrs
        assert "10.0.0.0/8" in cidrs

    def test_parse_empty_content(self):
        """Should handle empty content."""
        assert parse_cidr_list("") == []
        assert parse_cidr_list("\n\n") == []

    def test_parse_ipv6_cidrs(self):
        """Should handle IPv6 CIDR blocks."""
        content = """2001:db8::/32
fe80::/10"""
        cidrs = parse_cidr_list(content)
        assert len(cidrs) >= 1  # At least one should parse

    def test_parse_host_notation(self):
        """Should accept single IP as /32 CIDR (strict=False)."""
        content = """192.0.2.1/32
10.0.0.1"""
        cidrs = parse_cidr_list(content)
        # strict=False allows host bits set, so 10.0.0.1 should parse as network
        assert len(cidrs) >= 1
