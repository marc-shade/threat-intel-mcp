"""
Tests for validation functions in config.py.
"""

import pytest
from threat_intel_mcp.config import (
    validate_ip,
    validate_hash,
    validate_domain,
    validate_ioc_type
)


class TestValidateIP:
    """Test IP address validation."""

    def test_valid_ipv4(self):
        """Should accept valid IPv4 addresses."""
        valid_ips = [
            "192.0.2.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "127.0.0.1",
            "255.255.255.255",
            "0.0.0.0"
        ]
        for ip in valid_ips:
            is_valid, error = validate_ip(ip)
            assert is_valid, f"{ip} should be valid"
            assert error is None

    def test_valid_ipv6(self):
        """Should accept valid IPv6 addresses."""
        valid_ips = [
            "2001:0db8:85a3::8a2e:0370:7334",
            "::1",
            "fe80::1",
            "2001:db8::1"
        ]
        for ip in valid_ips:
            is_valid, error = validate_ip(ip)
            assert is_valid, f"{ip} should be valid"
            assert error is None

    def test_invalid_ip(self):
        """Should reject invalid IP addresses."""
        invalid_ips = [
            "999.999.999.999",
            "256.1.1.1",
            "192.0.2",
            "not-an-ip",
            "192.0.2.1.1",
            "",
            "192.0.2.1/24"  # CIDR notation not allowed
        ]
        for ip in invalid_ips:
            is_valid, error = validate_ip(ip)
            assert not is_valid, f"{ip} should be invalid"
            assert error is not None
            assert "Invalid IP" in error


class TestValidateHash:
    """Test file hash validation."""

    def test_valid_md5(self):
        """Should recognize valid MD5 hashes."""
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        is_valid, hash_type, error = validate_hash(md5_hash)
        assert is_valid
        assert hash_type == "md5"
        assert error is None

    def test_valid_sha1(self):
        """Should recognize valid SHA1 hashes."""
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        is_valid, hash_type, error = validate_hash(sha1_hash)
        assert is_valid
        assert hash_type == "sha1"
        assert error is None

    def test_valid_sha256(self):
        """Should recognize valid SHA256 hashes."""
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        is_valid, hash_type, error = validate_hash(sha256_hash)
        assert is_valid
        assert hash_type == "sha256"
        assert error is None

    def test_uppercase_hash(self):
        """Should handle uppercase hashes."""
        md5_upper = "D41D8CD98F00B204E9800998ECF8427E"
        is_valid, hash_type, error = validate_hash(md5_upper)
        assert is_valid
        assert hash_type == "md5"

    def test_mixed_case_hash(self):
        """Should handle mixed case hashes."""
        md5_mixed = "D41d8Cd98F00B204e9800998eCf8427E"
        is_valid, hash_type, error = validate_hash(md5_mixed)
        assert is_valid
        assert hash_type == "md5"

    def test_invalid_hash_length(self):
        """Should reject hashes with wrong length."""
        invalid_hashes = [
            "d41d8cd98f00b204",  # Too short
            "d41d8cd98f00b204e9800998ecf8427e123",  # Too long
            "abcd"  # Way too short
        ]
        for hash_val in invalid_hashes:
            is_valid, hash_type, error = validate_hash(hash_val)
            assert not is_valid
            assert hash_type is None
            assert "Invalid hash format" in error

    def test_invalid_hash_characters(self):
        """Should reject hashes with invalid characters."""
        invalid_hashes = [
            "g41d8cd98f00b204e9800998ecf8427e",  # 'g' not hex
            "d41d8cd98f00b204e9800998ecf8427z",  # 'z' not hex
            "d41d8cd98f00b204e9800998ecf8427 "   # space
        ]
        for hash_val in invalid_hashes:
            is_valid, hash_type, error = validate_hash(hash_val)
            assert not is_valid

    def test_empty_hash(self):
        """Should reject empty hash."""
        is_valid, hash_type, error = validate_hash("")
        assert not is_valid
        assert error is not None

    def test_whitespace_trimmed(self):
        """Should trim whitespace from hash."""
        md5_with_space = "  d41d8cd98f00b204e9800998ecf8427e  "
        is_valid, hash_type, error = validate_hash(md5_with_space)
        assert is_valid
        assert hash_type == "md5"


class TestValidateDomain:
    """Test domain name validation."""

    def test_valid_domains(self):
        """Should accept valid domain names."""
        valid_domains = [
            "example.com",
            "sub.example.com",
            "deep.sub.example.com",
            "example.co.uk",
            "test-domain.com",
            "test123.com",
            "a.b.c.d.example.com"
        ]
        for domain in valid_domains:
            is_valid, error = validate_domain(domain)
            assert is_valid, f"{domain} should be valid"
            assert error is None

    def test_invalid_domains(self):
        """Should reject invalid domain names."""
        invalid_domains = [
            "example",  # No TLD
            ".example.com",  # Leading dot
            "example.com.",  # Trailing dot
            "ex ample.com",  # Space
            "-example.com",  # Leading hyphen
            "example-.com",  # Trailing hyphen
            "example..com",  # Double dot
            "",  # Empty
            "192.0.2.1"  # IP address
        ]
        for domain in invalid_domains:
            is_valid, error = validate_domain(domain)
            assert not is_valid, f"{domain} should be invalid"
            assert error is not None


class TestValidateIOCType:
    """Test IOC type validation."""

    def test_valid_ioc_types(self):
        """Should accept valid IOC types."""
        valid_types = [
            "ip",
            "ip:port",
            "domain",
            "url",
            "md5",
            "sha1",
            "sha256",
            "email"
        ]
        for ioc_type in valid_types:
            is_valid, error = validate_ioc_type(ioc_type)
            assert is_valid, f"{ioc_type} should be valid"
            assert error is None

    def test_invalid_ioc_type(self):
        """Should reject invalid IOC types."""
        invalid_types = [
            "ipv4",
            "hash",
            "malware",
            "",
            "IP",  # Wrong case
            "ip_address"
        ]
        for ioc_type in invalid_types:
            is_valid, error = validate_ioc_type(ioc_type)
            assert not is_valid, f"{ioc_type} should be invalid"
            assert error is not None
            assert "Invalid IOC type" in error
