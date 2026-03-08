"""Test configuration — strips proxy env vars so httpx doesn't try SOCKS."""

import asyncio
from pathlib import Path

import pytest

from world_intel_mcp.cache import Cache
from world_intel_mcp.circuit_breaker import CircuitBreaker
from world_intel_mcp.fetcher import Fetcher

_PROXY_VARS = [
    "ALL_PROXY",
    "all_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "FTP_PROXY",
    "ftp_proxy",
    "GRPC_PROXY",
    "grpc_proxy",
]


@pytest.fixture(autouse=True)
def _strip_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove system proxy env vars so httpx creates clean connections."""
    for var in _PROXY_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _reset_fetcher_locks() -> None:
    """Reset global asyncio locks between tests to avoid cross-loop binding."""
    import world_intel_mcp.fetcher as fetcher_mod

    fetcher_mod._yahoo_lock = asyncio.Lock()
    fetcher_mod._yahoo_last_call = 0.0
    fetcher_mod._source_locks.clear()
    fetcher_mod._source_last_call.clear()


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(db_path=tmp_path / "test_cache.db")


@pytest.fixture
def fetcher(cache: Cache) -> Fetcher:
    breaker = CircuitBreaker()
    return Fetcher(cache=cache, breaker=breaker, default_timeout=5.0)
