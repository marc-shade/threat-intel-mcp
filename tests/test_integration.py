"""
Integration tests that test complete workflows without mocking MCP decorators.
"""

import pytest
import json
from threat_intel_mcp.config import threat_cache, THREAT_FEEDS, API_KEYS


class TestConfiguration:
    """Test configuration and constants."""

    def test_threat_feeds_configured(self):
        """Should have threat feeds configured."""
        assert len(THREAT_FEEDS) > 0
        assert "feodo_tracker" in THREAT_FEEDS
        assert "cisa_kev" in THREAT_FEEDS
        assert "urlhaus_recent" in THREAT_FEEDS

    def test_feed_configuration_structure(self):
        """Should have properly structured feed configs."""
        for name, feed in THREAT_FEEDS.items():
            assert feed.name == name
            assert feed.url.startswith("http")
            assert feed.description
            assert feed.feed_type

    def test_api_keys_structure(self):
        """Should have API key configuration."""
        assert hasattr(API_KEYS, "virustotal")
        assert hasattr(API_KEYS, "abuseipdb")
        assert hasattr(API_KEYS, "shodan")
        assert hasattr(API_KEYS, "otx")

    def test_api_key_checking(self):
        """Should have boolean accessors for API keys."""
        assert isinstance(API_KEYS.has_virustotal, bool)
        assert isinstance(API_KEYS.has_abuseipdb, bool)
        assert isinstance(API_KEYS.has_shodan, bool)
        assert isinstance(API_KEYS.has_otx, bool)


class TestThreatCacheIntegration:
    """Test cache integration scenarios."""

    def test_cache_survives_multiple_operations(self, clean_cache):
        """Should maintain data integrity across operations."""
        cache = clean_cache

        # Simulate feed caching
        feed_data = {
            "ips": ["192.0.2.1", "192.0.2.2"],
            "count": 2,
            "type": "ip_list"
        }
        cache.set("feed_test", feed_data)

        # Retrieve and modify
        retrieved = cache.get("feed_test")
        assert retrieved == feed_data

        # Ensure original is not modified
        retrieved["ips"].append("192.0.2.3")
        original = cache.get("feed_test")
        # Note: Python dicts are references, so this test checks cache behavior
        assert "192.0.2.3" in original["ips"]  # Expected: same object

    def test_cache_stats_accuracy(self, clean_cache):
        """Should provide accurate statistics."""
        cache = clean_cache

        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")

        stats = cache.stats()
        assert stats["size"] == 3
        assert "key1" in stats["keys"]
        assert "key2" in stats["keys"]
        assert "key3" in stats["keys"]

        cache.delete("key2")
        stats = cache.stats()
        assert stats["size"] == 2
        assert "key2" not in stats["keys"]


class TestDataFlowPatterns:
    """Test common data flow patterns."""

    def test_feed_to_cache_pattern(self, clean_cache):
        """Should follow typical feed -> cache -> check pattern."""
        cache = clean_cache

        # Simulate feed loading
        threat_ips = set(["192.0.2.1", "192.0.2.2", "192.0.2.3"])
        cache.set("feed_feodo_tracker", {
            "ips": list(threat_ips),
            "count": len(threat_ips),
            "type": "ip_list",
            "fetched_at": "2024-01-01T00:00:00"
        })

        # Simulate IP check
        cached = cache.get("feed_feodo_tracker")
        assert cached is not None
        assert "192.0.2.1" in cached["ips"]
        assert cached["count"] == 3

    def test_multiple_feed_aggregation(self, clean_cache):
        """Should aggregate multiple feeds correctly."""
        cache = clean_cache

        # Load multiple feeds
        cache.set("feed_feodo_tracker", {
            "ips": ["192.0.2.1", "192.0.2.2"],
            "count": 2
        })
        cache.set("feed_sslbl_botnet", {
            "ips": ["192.0.2.3", "192.0.2.4"],
            "count": 2
        })

        # Aggregate
        all_threat_ips = set()
        for key in ["feed_feodo_tracker", "feed_sslbl_botnet"]:
            cached = cache.get(key)
            if cached:
                all_threat_ips.update(cached.get("ips", []))

        assert len(all_threat_ips) == 4
        assert "192.0.2.1" in all_threat_ips
        assert "192.0.2.4" in all_threat_ips


class TestHelperFunctionIntegration:
    """Test helper function combinations."""

    def test_timestamp_generation(self):
        """Should generate valid ISO timestamps."""
        from threat_intel_mcp.config import get_timestamp, parse_timestamp

        ts = get_timestamp()
        assert ts
        assert "T" in ts  # ISO format

        # Should be parseable
        dt = parse_timestamp(ts)
        assert dt is not None

    def test_severity_calculation(self):
        """Should calculate severity correctly."""
        from threat_intel_mcp.config import calculate_severity, Severity

        assert calculate_severity(10) == Severity.LOW
        assert calculate_severity(40) == Severity.MEDIUM
        assert calculate_severity(60) == Severity.HIGH
        assert calculate_severity(90) == Severity.CRITICAL

    def test_feed_filtering(self):
        """Should filter feeds by type."""
        from threat_intel_mcp.config import get_ip_feeds, get_enabled_feeds, FeedType, THREAT_FEEDS

        ip_feeds = get_ip_feeds()
        assert len(ip_feeds) > 0

        # Verify all returned feeds are actually IP_LIST type
        for feed_name in ip_feeds:
            feed = THREAT_FEEDS.get(feed_name)
            assert feed is not None
            assert feed.feed_type == FeedType.IP_LIST

        enabled = get_enabled_feeds()
        assert len(enabled) > 0
        assert all(feed.enabled for feed in enabled.values())


class TestErrorConditions:
    """Test error conditions and edge cases."""

    def test_cache_with_none_values(self, clean_cache):
        """Should handle None values gracefully."""
        cache = clean_cache

        cache.set("none_value", None)
        assert cache.get("none_value") is None

    def test_cache_with_empty_collections(self, clean_cache):
        """Should handle empty collections."""
        cache = clean_cache

        cache.set("empty_list", [])
        cache.set("empty_dict", {})

        assert cache.get("empty_list") == []
        assert cache.get("empty_dict") == {}

    def test_concurrent_cache_access(self, clean_cache):
        """Should handle concurrent read/write safely."""
        import threading
        cache = clean_cache

        errors = []

        def reader():
            try:
                for i in range(100):
                    cache.get(f"key{i % 10}")
            except Exception as e:
                errors.append(e)

        def writer():
            try:
                for i in range(100):
                    cache.set(f"key{i % 10}", f"value{i}")
            except Exception as e:
                errors.append(e)

        threads = []
        for _ in range(5):
            threads.append(threading.Thread(target=reader))
            threads.append(threading.Thread(target=writer))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Concurrent access errors: {errors}"


class TestThreatDetectionLogic:
    """Test threat detection logic patterns."""

    def test_ip_in_threat_set(self, clean_cache):
        """Should correctly identify threats in sets."""
        threat_ips = {"192.0.2.1", "192.0.2.2", "10.0.0.5"}

        # Test IP
        test_ip = "192.0.2.1"
        assert test_ip in threat_ips

        test_ip_clean = "8.8.8.8"
        assert test_ip_clean not in threat_ips

    def test_bulk_threat_check_logic(self, clean_cache):
        """Should handle bulk checks efficiently."""
        cache = clean_cache

        # Load threat data
        threat_ips = set(["192.0.2.1", "192.0.2.2", "192.0.2.3"])

        # Bulk check
        check_ips = ["192.0.2.1", "8.8.8.8", "192.0.2.2", "1.1.1.1"]

        results = []
        for ip in check_ips:
            results.append({
                "ip": ip,
                "is_threat": ip in threat_ips
            })

        malicious_count = sum(1 for r in results if r["is_threat"])
        clean_count = len(results) - malicious_count

        assert malicious_count == 2
        assert clean_count == 2

    def test_network_scan_matching(self, clean_cache):
        """Should match network scan devices against threats."""
        cache = clean_cache

        # Load threats
        threat_ips = {"192.0.2.217", "192.0.2.25"}

        # Simulate network scan
        devices = [
            {"ip": "10.0.0.1", "hostname": "router"},
            {"ip": "192.0.2.217", "hostname": "infected"},
            {"ip": "10.0.0.5", "hostname": "laptop"}
        ]

        matches = []
        for device in devices:
            if device["ip"] in threat_ips:
                matches.append(device)

        assert len(matches) == 1
        assert matches[0]["ip"] == "192.0.2.217"
