"""Test configuration — strips proxy env vars so httpx doesn't try SOCKS."""

import os

import pytest

_PROXY_VARS = [
    "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy",
    "HTTPS_PROXY", "https_proxy", "FTP_PROXY", "ftp_proxy",
    "GRPC_PROXY", "grpc_proxy",
]


@pytest.fixture(autouse=True)
def _strip_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove system proxy env vars so httpx creates clean connections."""
    for var in _PROXY_VARS:
        monkeypatch.delenv(var, raising=False)
