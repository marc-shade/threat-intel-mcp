"""Tests for bonds source module — uses respx to mock HTTP calls."""

from pathlib import Path
from unittest.mock import patch

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
# Yield Curve — Yahoo Finance fallback (no FRED key)
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_yield_curve_yahoo_fallback(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.bonds import fetch_yield_curve

    # Mock Treasury Fiscal Data API
    treasury_response = {
        "data": [
            {
                "record_date": "2026-03-01",
                "security_desc": "Treasury Notes",
                "avg_interest_rate_amt": "4.125",
            }
        ]
    }
    respx.get(url__regex=r".*api\.fiscaldata\.treasury\.gov.*").mock(
        return_value=httpx.Response(200, json=treasury_response)
    )

    # Mock Yahoo Finance for yield symbols
    def _yahoo_chart(symbol: str, price: float) -> dict:
        return {
            "chart": {
                "result": [
                    {
                        "meta": {
                            "symbol": symbol,
                            "regularMarketPrice": price,
                            "previousClose": price - 0.02,
                            "currency": "USD",
                        }
                    }
                ]
            }
        }

    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/%5EIRX").mock(
        return_value=httpx.Response(200, json=_yahoo_chart("^IRX", 4.52))
    )
    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/%5EFVX").mock(
        return_value=httpx.Response(200, json=_yahoo_chart("^FVX", 4.15))
    )
    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/%5ETNX").mock(
        return_value=httpx.Response(200, json=_yahoo_chart("^TNX", 4.33))
    )
    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/%5ETYX").mock(
        return_value=httpx.Response(200, json=_yahoo_chart("^TYX", 4.61))
    )

    # Ensure no FRED key
    with patch.dict("os.environ", {}, clear=False):
        import os

        os.environ.pop("FRED_API_KEY", None)
        result = await fetch_yield_curve(fetcher)

    assert "yields" in result
    assert len(result["yields"]) == 4
    assert result["source"] == "treasury"
    assert result["fetched_at"] is not None

    # Check spread computation: 3M=4.52, 10Y=4.33 -> spread_3m10y = 4.33-4.52 = -0.19
    assert result["spread_3m10y"] is not None
    assert result["spread_3m10y"] < 0
    assert result["inverted"] is True

    # Verify yield maturities
    maturities = {y["maturity"] for y in result["yields"]}
    assert "3M" in maturities
    assert "10Y" in maturities


# ---------------------------------------------------------------------------
# Yield Curve — FRED path
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_yield_curve_fred(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.bonds import fetch_yield_curve

    # Mock Treasury Fiscal Data API
    respx.get(url__regex=r".*api\.fiscaldata\.treasury\.gov.*").mock(
        return_value=httpx.Response(200, json={"data": []})
    )

    # Mock FRED responses for each series
    def _fred_response(value: str) -> dict:
        return {"observations": [{"date": "2026-03-07", "value": value}]}

    fred_values = {
        "DGS1MO": "3.80",
        "DGS3MO": "3.95",
        "DGS6MO": "4.05",
        "DGS1": "4.10",
        "DGS2": "4.20",
        "DGS5": "4.30",
        "DGS10": "4.45",
        "DGS20": "4.55",
        "DGS30": "4.61",
    }

    # Route all FRED requests — respx matches on base URL, params distinguish
    respx.get("https://api.stlouisfed.org/fred/series/observations").mock(
        side_effect=lambda request: httpx.Response(
            200,
            json=_fred_response(
                fred_values.get(
                    dict(request.url.params).get("series_id", ""),
                    "0.0",
                )
            ),
        )
    )

    with patch.dict("os.environ", {"FRED_API_KEY": "test-fred-key"}):
        result = await fetch_yield_curve(fetcher)

    assert "yields" in result
    assert len(result["yields"]) == 9
    assert result["source"] == "treasury"

    # Check spread: 2Y=4.20, 10Y=4.45 -> spread_2s10s = 0.25 (positive)
    # 3M=3.95, 10Y=4.45 -> spread_3m10y = 0.50 (positive) -> not inverted
    assert result["spread_2s10s"] is not None
    assert result["spread_2s10s"] > 0
    assert result["spread_3m10y"] is not None
    assert result["spread_3m10y"] > 0
    assert result["inverted"] is False

    # Verify all maturities present
    maturities = {y["maturity"] for y in result["yields"]}
    assert maturities == {"1M", "3M", "6M", "1Y", "2Y", "5Y", "10Y", "20Y", "30Y"}


# ---------------------------------------------------------------------------
# Bond Indices
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_bond_indices(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.bonds import fetch_bond_indices

    def _yahoo_chart(symbol: str, price: float) -> dict:
        return {
            "chart": {
                "result": [
                    {
                        "meta": {
                            "symbol": symbol,
                            "regularMarketPrice": price,
                            "previousClose": price + 0.15,
                            "currency": "USD",
                        }
                    }
                ]
            }
        }

    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/AGG").mock(
        return_value=httpx.Response(200, json=_yahoo_chart("AGG", 98.50))
    )
    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/TLT").mock(
        return_value=httpx.Response(200, json=_yahoo_chart("TLT", 92.30))
    )
    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/HYG").mock(
        return_value=httpx.Response(200, json=_yahoo_chart("HYG", 77.80))
    )
    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/LQD").mock(
        return_value=httpx.Response(200, json=_yahoo_chart("LQD", 108.20))
    )
    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/TIP").mock(
        return_value=httpx.Response(200, json=_yahoo_chart("TIP", 106.40))
    )

    result = await fetch_bond_indices(fetcher)

    assert "indices" in result
    assert len(result["indices"]) == 5
    assert result["source"] == "yahoo-finance"
    assert result["fetched_at"] is not None

    # Verify individual entries
    by_symbol = {idx["symbol"]: idx for idx in result["indices"]}
    assert by_symbol["AGG"]["name"] == "US Aggregate Bond"
    assert by_symbol["AGG"]["price"] == 98.50
    assert by_symbol["TLT"]["name"] == "20+ Year Treasury"
    assert by_symbol["HYG"]["name"] == "High Yield Corporate"

    # Change percent should be negative (price dropped from previousClose)
    for idx in result["indices"]:
        assert idx["change_pct"] is not None
        assert idx["change_pct"] < 0


# ---------------------------------------------------------------------------
# Bond Indices — partial failure
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_bond_indices_partial_failure(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.bonds import fetch_bond_indices

    chart_ok = {
        "chart": {
            "result": [
                {
                    "meta": {
                        "symbol": "AGG",
                        "regularMarketPrice": 98.50,
                        "regularMarketChangePercent": -0.12,
                        "currency": "USD",
                    }
                }
            ]
        }
    }

    # Only AGG succeeds; rest fail with 500
    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/AGG").mock(
        return_value=httpx.Response(200, json=chart_ok)
    )
    respx.get(url__regex=r".*finance/chart/(?!AGG).*").mock(
        return_value=httpx.Response(500)
    )

    result = await fetch_bond_indices(fetcher)

    assert "indices" in result
    # Only AGG should survive
    assert len(result["indices"]) >= 1
    assert result["indices"][0]["symbol"] == "AGG"
