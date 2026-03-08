"""Tests for analysis.macro_composite — macro market composite scoring."""

import httpx
import pytest
import respx

from world_intel_mcp.fetcher import Fetcher


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

_FEAR_GREED = {"data": [{"value": "72", "value_classification": "Greed"}]}

_MEMPOOL_FEES = {
    "fastestFee": 25,
    "halfHourFee": 15,
    "hourFee": 10,
    "economyFee": 5,
    "minimumFee": 1,
}


def _yahoo_chart(symbol: str, price: float, prev: float) -> dict:
    return {
        "chart": {
            "result": [
                {
                    "meta": {
                        "symbol": symbol,
                        "regularMarketPrice": price,
                        "previousClose": prev,
                        "currency": "USD",
                    }
                }
            ]
        }
    }


_BTC_DOMINANCE = {"data": {"market_cap_percentage": {"btc": 54.3}}}

# Sector ETFs — all 11
_SECTOR_PRICES = {
    "XLK": (210.0, 208.0),  # Technology +0.96%
    "XLF": (42.0, 41.5),  # Financials +1.2%
    "XLE": (88.0, 89.0),  # Energy -1.1%
    "XLV": (145.0, 144.0),  # Healthcare +0.69%
    "XLI": (120.0, 119.0),  # Industrials +0.84%
    "XLC": (82.0, 81.0),  # Communication +1.23%
    "XLY": (185.0, 184.0),  # Consumer Disc +0.54%
    "XLP": (76.0, 76.5),  # Consumer Staples -0.65%
    "XLRE": (40.0, 40.5),  # Real Estate -1.23%
    "XLU": (68.0, 68.5),  # Utilities -0.73%
    "XLB": (85.0, 84.0),  # Materials +1.19%
}

# BTC historical prices (200+ daily points)
_BTC_PRICES = [[i * 86400000, 40000 + i * 150] for i in range(201)]


# ---------------------------------------------------------------------------
# Helper to set up all mocks
# ---------------------------------------------------------------------------


def _mock_all_endpoints() -> None:
    """Register respx mocks for every upstream used by macro_composite."""
    # Fear & Greed
    respx.get("https://api.alternative.me/fng/").mock(
        return_value=httpx.Response(200, json=_FEAR_GREED)
    )
    # Mempool
    respx.get("https://mempool.space/api/v1/fees/recommended").mock(
        return_value=httpx.Response(200, json=_MEMPOOL_FEES)
    )
    # Macro symbols: DXY, VIX, Gold, 10Y
    for symbol, price, prev in [
        ("DX-Y.NYB", 103.2, 103.0),
        ("%5EVIX", 16.5, 17.0),  # ^VIX URL-encoded
        ("GC%3DF", 2050.0, 2040.0),  # GC=F URL-encoded
        ("%5ETNX", 4.25, 4.20),  # ^TNX URL-encoded
    ]:
        respx.get(f"https://query1.finance.yahoo.com/v8/finance/chart/{symbol}").mock(
            return_value=httpx.Response(200, json=_yahoo_chart(symbol, price, prev))
        )
    # BTC dominance
    respx.get("https://api.coingecko.com/api/v3/global").mock(
        return_value=httpx.Response(200, json=_BTC_DOMINANCE)
    )
    # Sector ETFs
    for sym, (price, prev) in _SECTOR_PRICES.items():
        respx.get(f"https://query1.finance.yahoo.com/v8/finance/chart/{sym}").mock(
            return_value=httpx.Response(200, json=_yahoo_chart(sym, price, prev))
        )
    # BTC technicals (CoinGecko market_chart)
    respx.get("https://api.coingecko.com/api/v3/coins/bitcoin/market_chart").mock(
        return_value=httpx.Response(200, json={"prices": _BTC_PRICES})
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_macro_composite_full(fetcher: Fetcher) -> None:
    """Test macro composite with all upstreams returning data."""
    from world_intel_mcp.analysis.macro_composite import fetch_macro_composite

    _mock_all_endpoints()

    result = await fetch_macro_composite(fetcher)

    assert result["source"] == "composite"
    assert "verdict" in result
    assert result["verdict"] in (
        "STRONG_CAUTION",
        "CAUTIOUS",
        "NEUTRAL",
        "CONSTRUCTIVE",
        "RISK_ON",
    )
    assert 0 <= result["score"] <= 100
    assert "fetched_at" in result

    # Check signal structure
    signals = result["signals"]
    assert signals["fear_greed"]["value"] == 72
    assert signals["fear_greed"]["weight"] == 0.25
    assert signals["vix"]["value"] == 16.5
    assert signals["vix"]["label"] == "calm"
    assert signals["dxy"]["value"] == 103.2
    assert signals["dxy"]["label"] == "neutral"
    assert signals["yield_10y"]["value"] == 4.25
    assert signals["yield_10y"]["label"] == "elevated"

    # Sector breadth: 7 positive, 4 negative
    assert signals["sector_breadth"]["positive"] == 7
    assert signals["sector_breadth"]["negative"] == 4

    # BTC signal should exist
    assert "signal" in signals["btc"]
    assert "mayer" in signals["btc"]

    # Top/bottom sectors
    assert len(result["top_sectors"]) <= 3
    assert len(result["bottom_sectors"]) <= 3


@respx.mock
@pytest.mark.asyncio
async def test_fetch_macro_composite_all_sources_fail(fetcher: Fetcher) -> None:
    """Test that total upstream failure returns a valid neutral result."""
    from world_intel_mcp.analysis.macro_composite import fetch_macro_composite

    # Mock everything to fail
    respx.get("https://api.alternative.me/fng/").mock(return_value=httpx.Response(500))
    respx.get("https://mempool.space/api/v1/fees/recommended").mock(
        return_value=httpx.Response(500)
    )
    respx.get(url__regex=r"query1\.finance\.yahoo\.com").mock(
        return_value=httpx.Response(500)
    )
    respx.get("https://api.coingecko.com/api/v3/global").mock(
        return_value=httpx.Response(500)
    )
    respx.get("https://api.coingecko.com/api/v3/coins/bitcoin/market_chart").mock(
        return_value=httpx.Response(500)
    )

    result = await fetch_macro_composite(fetcher)

    assert result["source"] == "composite"
    assert result["verdict"] in (
        "STRONG_CAUTION",
        "CAUTIOUS",
        "NEUTRAL",
        "CONSTRUCTIVE",
        "RISK_ON",
    )
    assert 0 <= result["score"] <= 100


# ---------------------------------------------------------------------------
# Unit tests for classification helpers
# ---------------------------------------------------------------------------


def test_classify_vix() -> None:
    from world_intel_mcp.analysis.macro_composite import _classify_vix

    label, score = _classify_vix(12.0)
    assert label == "complacent"
    assert score == 90.0

    label, score = _classify_vix(18.0)
    assert label == "calm"

    label, score = _classify_vix(25.0)
    assert label == "cautious"

    label, score = _classify_vix(35.0)
    assert label == "fear"

    label, score = _classify_vix(None)
    assert label == "unavailable"


def test_classify_dxy() -> None:
    from world_intel_mcp.analysis.macro_composite import _classify_dxy

    label, _ = _classify_dxy(98.0)
    assert label == "weak dollar"

    label, _ = _classify_dxy(103.0)
    assert label == "neutral"

    label, _ = _classify_dxy(108.0)
    assert label == "strong dollar"


def test_classify_yield() -> None:
    from world_intel_mcp.analysis.macro_composite import _classify_yield

    label, _ = _classify_yield(2.5)
    assert label == "accommodative"

    label, _ = _classify_yield(3.5)
    assert label == "moderate"

    label, _ = _classify_yield(4.5)
    assert label == "elevated"

    label, _ = _classify_yield(5.5)
    assert label == "restrictive"


def test_classify_btc() -> None:
    from world_intel_mcp.analysis.macro_composite import _classify_btc

    label, score, mayer = _classify_btc(
        {"cross_signal": "golden_cross", "mayer_multiple": 1.2}
    )
    assert label == "bullish"
    assert score == 75.0

    label, score, mayer = _classify_btc(
        {"cross_signal": "death_cross", "mayer_multiple": 0.7}
    )
    assert label == "undervalued"  # Mayer < 0.8 overrides
    assert score == 45.0  # 25 + 20

    label, score, mayer = _classify_btc(
        {"cross_signal": "golden_cross", "mayer_multiple": 2.5}
    )
    assert label == "overheated"  # Mayer > 2.4 overrides
    assert score == 55.0  # 75 - 20


def test_verdict_mapping() -> None:
    from world_intel_mcp.analysis.macro_composite import _verdict

    assert _verdict(90) == "RISK_ON"
    assert _verdict(70) == "CONSTRUCTIVE"
    assert _verdict(50) == "NEUTRAL"
    assert _verdict(30) == "CAUTIOUS"
    assert _verdict(10) == "STRONG_CAUTION"


def test_compute_sector_breadth() -> None:
    from world_intel_mcp.analysis.macro_composite import _compute_sector_breadth

    heatmap = {
        "sectors": [
            {"name": "Tech", "change_pct": 1.5},
            {"name": "Energy", "change_pct": -0.5},
            {"name": "Health", "change_pct": 0.3},
        ]
    }
    pos, neg, score = _compute_sector_breadth(heatmap)
    assert pos == 2
    assert neg == 1
    assert round(score, 1) == 66.7

    pos, neg, score = _compute_sector_breadth({})
    assert pos == 0
    assert neg == 0
    assert score == 50.0
