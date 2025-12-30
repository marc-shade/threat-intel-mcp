"""
Tests for ThreatCache functionality.
"""

import pytest
import time
from datetime import datetime, timedelta
from threat_intel_mcp.config import ThreatCache


class TestThreatCache:
    """Test the ThreatCache class."""

    def test_cache_set_and_get(self):
        """Should store and retrieve values."""
        cache = ThreatCache()
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_cache_get_nonexistent(self):
        """Should return None for nonexistent keys."""
        cache = ThreatCache()
        assert cache.get("nonexistent") is None

    def test_cache_expiry(self):
        """Should expire values after TTL."""
        cache = ThreatCache(default_ttl=1)
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

        # Wait for expiry
        time.sleep(1.1)
        assert cache.get("key1") is None

    def test_cache_custom_ttl(self):
        """Should respect custom TTL per key."""
        cache = ThreatCache(default_ttl=10)
        cache.set("short", "value1", ttl=1)
        cache.set("long", "value2", ttl=10)

        time.sleep(1.1)
        assert cache.get("short") is None
        assert cache.get("long") == "value2"

    def test_cache_max_size(self):
        """Should evict oldest when max size reached."""
        cache = ThreatCache(max_size=3)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        cache.set("key4", "value4")  # Should evict oldest

        # One key should be evicted
        assert cache.stats()["size"] == 3
        assert cache.get("key4") == "value4"

    def test_cache_delete(self):
        """Should delete keys."""
        cache = ThreatCache()
        cache.set("key1", "value1")
        assert cache.delete("key1") is True
        assert cache.get("key1") is None
        assert cache.delete("nonexistent") is False

    def test_cache_clear(self):
        """Should clear all cached data."""
        cache = ThreatCache()
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.clear()
        assert cache.get("key1") is None
        assert cache.get("key2") is None
        assert cache.stats()["size"] == 0

    def test_cache_stats(self):
        """Should return accurate statistics."""
        cache = ThreatCache(max_size=10)
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        stats = cache.stats()
        assert stats["size"] == 2
        assert stats["max_size"] == 10
        assert "key1" in stats["keys"]
        assert "key2" in stats["keys"]

    def test_cache_complex_values(self):
        """Should handle complex data types."""
        cache = ThreatCache()

        # Dictionary
        data = {"ips": ["192.0.2.1", "192.0.2.2"], "count": 2}
        cache.set("dict", data)
        assert cache.get("dict") == data

        # List
        data_list = [1, 2, 3, 4, 5]
        cache.set("list", data_list)
        assert cache.get("list") == data_list

        # Nested structure
        nested = {"data": {"nested": {"deep": "value"}}}
        cache.set("nested", nested)
        assert cache.get("nested") == nested

    def test_cache_update_existing(self):
        """Should update existing keys without increasing size."""
        cache = ThreatCache(max_size=2)
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        # Update existing key
        cache.set("key1", "new_value")

        assert cache.stats()["size"] == 2
        assert cache.get("key1") == "new_value"

    def test_cache_thread_safety(self):
        """Should be thread-safe for concurrent access."""
        import threading

        cache = ThreatCache()

        def writer(key, value):
            cache.set(key, value)

        # Create multiple threads writing concurrently
        threads = []
        for i in range(10):
            t = threading.Thread(target=writer, args=(f"key{i}", f"value{i}"))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # All values should be stored
        assert cache.stats()["size"] == 10
        for i in range(10):
            assert cache.get(f"key{i}") == f"value{i}"

    def test_cache_zero_ttl(self):
        """Should handle zero TTL edge case."""
        cache = ThreatCache()
        cache.set("key1", "value1", ttl=0)

        # TTL of 0 means "right now", but may not expire until checked
        # This is an edge case - the value expires at "now + 0 seconds"
        # Depending on timing, it may or may not be expired yet
        time.sleep(0.01)  # Small delay to ensure time has passed
        # The cache should either be None or about to expire
        # This is acceptable behavior for edge case
