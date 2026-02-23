"""Tests for SQLite TTL cache."""

import time
from pathlib import Path

import pytest

from world_intel_mcp.cache import Cache


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(db_path=tmp_path / "test_cache.db")


def test_set_and_get(cache: Cache) -> None:
    cache.set("key1", {"value": 42}, ttl_seconds=60)
    result = cache.get("key1")
    assert result == {"value": 42}


def test_get_missing_key(cache: Cache) -> None:
    assert cache.get("nonexistent") is None


def test_ttl_expiration(cache: Cache) -> None:
    cache.set("ephemeral", "data", ttl_seconds=1)
    assert cache.get("ephemeral") == "data"
    time.sleep(1.1)
    assert cache.get("ephemeral") is None


def test_overwrite(cache: Cache) -> None:
    cache.set("key", "v1", ttl_seconds=60)
    cache.set("key", "v2", ttl_seconds=60)
    assert cache.get("key") == "v2"


def test_delete(cache: Cache) -> None:
    cache.set("key", "val", ttl_seconds=60)
    cache.delete("key")
    assert cache.get("key") is None


def test_evict_expired(cache: Cache) -> None:
    cache.set("fresh", "yes", ttl_seconds=300)
    cache.set("stale", "no", ttl_seconds=1)
    time.sleep(1.1)
    removed = cache.evict_expired()
    assert removed == 1
    assert cache.get("fresh") == "yes"
    assert cache.get("stale") is None


def test_stats(cache: Cache) -> None:
    cache.set("a", 1, ttl_seconds=300)
    cache.set("b", 2, ttl_seconds=300)
    stats = cache.stats()
    assert stats["total_entries"] == 2
    assert stats["active_entries"] == 2


def test_complex_values(cache: Cache) -> None:
    data = {"nested": {"list": [1, 2, 3], "bool": True, "null": None}}
    cache.set("complex", data, ttl_seconds=60)
    assert cache.get("complex") == data
