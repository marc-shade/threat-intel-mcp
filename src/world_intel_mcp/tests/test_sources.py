"""Tests for source modules — uses respx to mock HTTP calls."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

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
# Markets
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_market_quotes(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.markets import fetch_market_quotes

    # Mock Yahoo Finance v8 chart response for ^GSPC
    chart_response = {
        "chart": {
            "result": [{
                "meta": {
                    "symbol": "^GSPC",
                    "regularMarketPrice": 5123.45,
                    "regularMarketChangePercent": 0.42,
                    "currency": "USD",
                }
            }]
        }
    }

    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/%5EGSPC").mock(
        return_value=httpx.Response(200, json=chart_response)
    )

    result = await fetch_market_quotes(fetcher, symbols=["^GSPC"])
    assert "quotes" in result
    assert len(result["quotes"]) == 1
    assert result["quotes"][0]["symbol"] == "^GSPC"
    assert result["quotes"][0]["price"] == 5123.45
    assert result["source"] == "yahoo-finance"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_crypto_quotes(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.markets import fetch_crypto_quotes

    coins = [
        {
            "id": "bitcoin",
            "symbol": "btc",
            "name": "Bitcoin",
            "current_price": 98000,
            "market_cap": 1900000000000,
            "price_change_percentage_24h": 2.5,
            "sparkline_in_7d": {"price": [95000, 96000, 97000, 98000]},
        }
    ]

    respx.get("https://api.coingecko.com/api/v3/coins/markets").mock(
        return_value=httpx.Response(200, json=coins)
    )

    result = await fetch_crypto_quotes(fetcher, limit=5)
    assert "coins" in result
    assert len(result["coins"]) == 1
    assert result["coins"][0]["symbol"] == "btc"
    assert result["source"] == "coingecko"


# ---------------------------------------------------------------------------
# Seismology
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_earthquakes(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.seismology import fetch_earthquakes

    geojson = {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "id": "us7000abc1",
                "properties": {
                    "mag": 5.2,
                    "place": "100km SSW of Somewhere",
                    "time": 1708700000000,
                    "tsunami": 0,
                    "felt": 15,
                    "alert": "green",
                    "url": "https://earthquake.usgs.gov/earthquakes/eventpage/us7000abc1",
                },
                "geometry": {
                    "type": "Point",
                    "coordinates": [-120.5, 35.2, 10.0],
                },
            }
        ],
    }

    respx.get("https://earthquake.usgs.gov/fdsnws/event/1/query").mock(
        return_value=httpx.Response(200, json=geojson)
    )

    result = await fetch_earthquakes(fetcher, min_magnitude=4.0, hours=24)
    assert result["count"] == 1
    eq = result["earthquakes"][0]
    assert eq["magnitude"] == 5.2
    assert eq["id"] == "us7000abc1"
    assert eq["depth_km"] == 10.0
    assert eq["latitude"] == 35.2
    assert eq["longitude"] == -120.5
    assert result["source"] == "usgs"


# ---------------------------------------------------------------------------
# Wildfire
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_wildfires_no_api_key(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.wildfire import fetch_wildfires

    with patch.dict("os.environ", {}, clear=False):
        # Remove the key if present
        import os
        os.environ.pop("NASA_FIRMS_API_KEY", None)
        result = await fetch_wildfires(fetcher, api_key=None)

    assert "error" in result


@respx.mock
@pytest.mark.asyncio
async def test_fetch_wildfires_single_region(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.wildfire import fetch_wildfires

    csv_data = (
        "latitude,longitude,bright_ti4,scan,track,acq_date,acq_time,satellite,confidence,version,bright_ti5,frp,daynight\n"
        "34.5,-118.2,350.0,0.5,0.5,2024-02-23,1200,N,high,2.0,290.0,45.0,D\n"
        "34.6,-118.3,360.0,0.5,0.5,2024-02-23,1200,N,high,2.0,295.0,55.0,D\n"
        "34.5,-118.2,340.0,0.5,0.5,2024-02-23,1200,N,low,2.0,285.0,30.0,D\n"
    )

    respx.get(url__regex=r".*firms\.modaps\.eosdis\.nasa\.gov.*").mock(
        return_value=httpx.Response(200, text=csv_data)
    )

    result = await fetch_wildfires(fetcher, region="north_america", api_key="testkey")
    assert "fires_by_region" in result
    na = result["fires_by_region"]["north_america"]
    assert na["count"] == 2  # only 2 high-confidence
    assert result["total_fires"] == 2


# ---------------------------------------------------------------------------
# Economic
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_fred_series_no_key(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.economic import fetch_fred_series

    import os
    os.environ.pop("FRED_API_KEY", None)
    result = await fetch_fred_series(fetcher, series_id="UNRATE", api_key=None)
    assert "error" in result


@respx.mock
@pytest.mark.asyncio
async def test_fetch_world_bank_indicators(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.economic import fetch_world_bank_indicators

    wb_response = [
        {"page": 1, "pages": 1, "per_page": 5, "total": 2},
        [
            {"indicator": {"id": "NY.GDP.MKTP.CD", "value": "GDP"}, "date": "2023", "value": 25000000000000},
            {"indicator": {"id": "NY.GDP.MKTP.CD", "value": "GDP"}, "date": "2022", "value": 24000000000000},
        ],
    ]

    respx.get(url__regex=r".*api\.worldbank\.org.*").mock(
        return_value=httpx.Response(200, json=wb_response)
    )

    result = await fetch_world_bank_indicators(fetcher, country="USA", indicators=["NY.GDP.MKTP.CD"])
    assert "indicators" in result
    assert len(result["indicators"]) == 1
    assert result["indicators"][0]["id"] == "NY.GDP.MKTP.CD"
    assert result["source"] == "world-bank"
