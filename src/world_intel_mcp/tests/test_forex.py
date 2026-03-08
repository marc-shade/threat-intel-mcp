"""Tests for forex source module — uses respx to mock HTTP calls."""

from pathlib import Path

import httpx
import pytest
import respx

from world_intel_mcp.cache import Cache
from world_intel_mcp.circuit_breaker import CircuitBreaker
from world_intel_mcp.fetcher import Fetcher


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(db_path=tmp_path / "test_cache.db")


@pytest.fixture
def fetcher(cache: Cache) -> Fetcher:
    breaker = CircuitBreaker()
    return Fetcher(cache=cache, breaker=breaker, default_timeout=5.0)


# ---------------------------------------------------------------------------
# fetch_forex_rates
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_forex_rates(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.forex import fetch_forex_rates

    api_response = {
        "base": "USD",
        "date": "2026-03-08",
        "rates": {"EUR": 0.92, "GBP": 0.79, "JPY": 149.5},
    }

    respx.get("https://api.frankfurter.dev/v1/latest").mock(
        return_value=httpx.Response(200, json=api_response)
    )

    result = await fetch_forex_rates(fetcher, base="USD", symbols="EUR,GBP,JPY")
    assert result["base"] == "USD"
    assert result["date"] == "2026-03-08"
    assert result["rates"]["EUR"] == 0.92
    assert result["rates"]["GBP"] == 0.79
    assert result["rates"]["JPY"] == 149.5
    assert result["source"] == "ecb-forex"
    assert "fetched_at" in result


@respx.mock
@pytest.mark.asyncio
async def test_fetch_forex_rates_all_currencies(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.forex import fetch_forex_rates

    api_response = {
        "base": "EUR",
        "date": "2026-03-08",
        "rates": {"USD": 1.087, "GBP": 0.858, "JPY": 162.4, "CHF": 0.965},
    }

    respx.get("https://api.frankfurter.dev/v1/latest").mock(
        return_value=httpx.Response(200, json=api_response)
    )

    result = await fetch_forex_rates(fetcher, base="EUR")
    assert result["base"] == "EUR"
    assert len(result["rates"]) == 4
    assert result["source"] == "ecb-forex"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_forex_rates_api_failure(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.forex import fetch_forex_rates

    respx.get("https://api.frankfurter.dev/v1/latest").mock(
        return_value=httpx.Response(500)
    )

    result = await fetch_forex_rates(fetcher, base="USD")
    assert result["base"] == "USD"
    assert result["rates"] == {}
    assert result["source"] == "ecb-forex"


# ---------------------------------------------------------------------------
# fetch_forex_timeseries
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_forex_timeseries(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.forex import fetch_forex_timeseries

    api_response = {
        "base": "USD",
        "start_date": "2026-02-06",
        "end_date": "2026-03-08",
        "rates": {
            "2026-02-06": {"EUR": 0.93},
            "2026-02-07": {"EUR": 0.925},
            "2026-02-10": {"EUR": 0.92},
            "2026-03-07": {"EUR": 0.915},
            "2026-03-08": {"EUR": 0.92},
        },
    }

    respx.get(url__regex=r"https://api\.frankfurter\.dev/v1/.*\.\..*").mock(
        return_value=httpx.Response(200, json=api_response)
    )

    result = await fetch_forex_timeseries(fetcher, base="USD", symbol="EUR", days=30)
    assert result["base"] == "USD"
    assert result["symbol"] == "EUR"
    assert result["days"] == 30
    assert len(result["rates"]) == 5
    assert result["rates"][0]["date"] == "2026-02-06"
    assert result["rates"][0]["rate"] == 0.93
    assert result["rates"][-1]["rate"] == 0.92
    assert result["trend"] is not None
    assert result["trend"]["start"] == 0.93
    assert result["trend"]["end"] == 0.92
    assert result["trend"]["change_pct"] < 0  # EUR weakened
    assert result["source"] == "ecb-forex"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_forex_timeseries_api_failure(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.forex import fetch_forex_timeseries

    respx.get(url__regex=r"https://api\.frankfurter\.dev/v1/.*\.\..*").mock(
        return_value=httpx.Response(500)
    )

    result = await fetch_forex_timeseries(fetcher, base="USD", symbol="EUR", days=7)
    assert result["base"] == "USD"
    assert result["symbol"] == "EUR"
    assert result["rates"] == []
    assert result["trend"] is None
    assert result["source"] == "ecb-forex"


# ---------------------------------------------------------------------------
# fetch_major_crosses
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_major_crosses(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.forex import fetch_major_crosses

    api_response = {
        "base": "USD",
        "date": "2026-03-08",
        "rates": {
            "EUR": 0.92,
            "GBP": 0.79,
            "JPY": 149.5,
            "CHF": 0.88,
            "AUD": 1.55,
            "CAD": 1.36,
            "NZD": 1.72,
            "CNY": 7.24,
        },
    }

    respx.get("https://api.frankfurter.dev/v1/latest").mock(
        return_value=httpx.Response(200, json=api_response)
    )

    result = await fetch_major_crosses(fetcher)
    assert len(result["major_pairs"]) == 8
    assert result["major_pairs"][0]["pair"] == "USD/EUR"
    assert result["major_pairs"][0]["rate"] == 0.92

    # Cross rates
    assert "EUR/GBP" in result["cross_rates"]
    assert "EUR/JPY" in result["cross_rates"]
    assert "GBP/JPY" in result["cross_rates"]
    # EUR/GBP = GBP/EUR = 0.79 / 0.92
    expected_eur_gbp = round(0.79 / 0.92, 6)
    assert result["cross_rates"]["EUR/GBP"] == expected_eur_gbp
    # EUR/JPY = JPY/EUR = 149.5 / 0.92
    expected_eur_jpy = round(149.5 / 0.92, 4)
    assert result["cross_rates"]["EUR/JPY"] == expected_eur_jpy

    # DXY proxy should be a positive float
    assert result["dxy_proxy"] is not None
    assert isinstance(result["dxy_proxy"], float)
    assert result["dxy_proxy"] > 0

    assert result["source"] == "ecb-forex"
    assert result["date"] == "2026-03-08"
    assert "fetched_at" in result


@respx.mock
@pytest.mark.asyncio
async def test_fetch_major_crosses_api_failure(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.forex import fetch_major_crosses

    respx.get("https://api.frankfurter.dev/v1/latest").mock(
        return_value=httpx.Response(500)
    )

    result = await fetch_major_crosses(fetcher)
    assert result["major_pairs"] == []
    assert result["cross_rates"] == {}
    assert result["source"] == "ecb-forex"
