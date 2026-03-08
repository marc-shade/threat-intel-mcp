"""Tests for earnings source module — uses respx to mock HTTP calls."""

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
# Earnings Calendar
# ---------------------------------------------------------------------------


def _make_quote_summary(
    symbol: str,
    earnings_date_raw: int,
    earnings_date_fmt: str,
    eps_average: float,
    eps_actual_prev: float,
) -> dict:
    """Build a realistic Yahoo quoteSummary response for calendarEvents."""
    return {
        "quoteSummary": {
            "result": [
                {
                    "calendarEvents": {
                        "earnings": {
                            "earningsDate": [
                                {"raw": earnings_date_raw, "fmt": earnings_date_fmt}
                            ],
                            "earningsAverage": {
                                "raw": eps_average,
                                "fmt": str(eps_average),
                            },
                        }
                    },
                    "earningsHistory": {
                        "history": [
                            {
                                "quarter": {"raw": 1735603200, "fmt": "2024-12-31"},
                                "epsEstimate": {"raw": 2.10, "fmt": "2.10"},
                                "epsActual": {
                                    "raw": eps_actual_prev,
                                    "fmt": str(eps_actual_prev),
                                },
                                "surprisePercent": {"raw": 0.038, "fmt": "3.8%"},
                            }
                        ],
                    },
                }
            ],
            "error": None,
        }
    }


@respx.mock
@pytest.mark.asyncio
async def test_fetch_earnings_calendar(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.earnings import fetch_earnings_calendar

    # Mock all 20 symbols — give AAPL and MSFT earnings dates, rest return
    # empty calendarEvents (so they get filtered out).
    aapl_resp = _make_quote_summary("AAPL", 1777180800, "2026-04-24", 2.35, 2.18)
    msft_resp = _make_quote_summary("MSFT", 1777440000, "2026-04-27", 3.22, 3.10)

    no_earnings_resp = {
        "quoteSummary": {
            "result": [
                {
                    "calendarEvents": {"earnings": {}},
                    "earningsHistory": {"history": []},
                }
            ],
            "error": None,
        }
    }

    respx.get("https://query1.finance.yahoo.com/v10/finance/quoteSummary/AAPL").mock(
        return_value=httpx.Response(200, json=aapl_resp)
    )

    respx.get("https://query1.finance.yahoo.com/v10/finance/quoteSummary/MSFT").mock(
        return_value=httpx.Response(200, json=msft_resp)
    )

    # All other symbols return no earnings
    respx.get(url__regex=r".*quoteSummary/(?!AAPL|MSFT).*").mock(
        return_value=httpx.Response(200, json=no_earnings_resp)
    )

    result = await fetch_earnings_calendar(fetcher, days_ahead=60)

    assert "upcoming" in result
    assert "this_week" in result
    assert result["source"] == "yahoo-finance"
    assert result["fetched_at"] is not None

    # Should have exactly 2 upcoming earnings (AAPL and MSFT)
    assert len(result["upcoming"]) == 2

    # Should be sorted by date — AAPL (Apr 24) before MSFT (Apr 27)
    assert result["upcoming"][0]["symbol"] == "AAPL"
    assert result["upcoming"][0]["earnings_date"] == "2026-04-24"
    assert result["upcoming"][0]["eps_estimate"] == 2.35
    assert result["upcoming"][0]["eps_previous"] == 2.18

    assert result["upcoming"][1]["symbol"] == "MSFT"
    assert result["upcoming"][1]["earnings_date"] == "2026-04-27"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_earnings_calendar_all_fail(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.earnings import fetch_earnings_calendar

    # All symbols return HTTP 500
    respx.get(url__regex=r".*quoteSummary/.*").mock(return_value=httpx.Response(500))

    result = await fetch_earnings_calendar(fetcher)

    assert result["upcoming"] == []
    assert result["this_week"] == []
    assert result["source"] == "yahoo-finance"


# ---------------------------------------------------------------------------
# Earnings Surprise
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_earnings_surprise(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.earnings import fetch_earnings_surprise

    surprise_resp = {
        "quoteSummary": {
            "result": [
                {
                    "earningsHistory": {
                        "history": [
                            {
                                "quarter": {"raw": 1727654400, "fmt": "2024-09-30"},
                                "epsEstimate": {"raw": 1.95, "fmt": "1.95"},
                                "epsActual": {"raw": 2.05, "fmt": "2.05"},
                                "surprisePercent": {"raw": 0.0513, "fmt": "5.13%"},
                            },
                            {
                                "quarter": {"raw": 1735603200, "fmt": "2024-12-31"},
                                "epsEstimate": {"raw": 2.10, "fmt": "2.10"},
                                "epsActual": {"raw": 2.18, "fmt": "2.18"},
                                "surprisePercent": {"raw": 0.038, "fmt": "3.8%"},
                            },
                        ],
                    },
                    "earningsTrend": {
                        "trend": [
                            {
                                "period": "0q",
                                "earningsEstimate": {
                                    "avg": {"raw": 2.35, "fmt": "2.35"},
                                },
                            },
                            {
                                "period": "+1q",
                                "earningsEstimate": {
                                    "avg": {"raw": 2.42, "fmt": "2.42"},
                                },
                            },
                        ],
                    },
                }
            ],
            "error": None,
        }
    }

    respx.get("https://query1.finance.yahoo.com/v10/finance/quoteSummary/AAPL").mock(
        return_value=httpx.Response(200, json=surprise_resp)
    )

    result = await fetch_earnings_surprise(fetcher, symbol="AAPL")

    assert result["symbol"] == "AAPL"
    assert result["source"] == "yahoo-finance"
    assert result["fetched_at"] is not None

    # History
    assert len(result["history"]) == 2
    h0 = result["history"][0]
    assert h0["eps_estimate"] == 1.95
    assert h0["eps_actual"] == 2.05
    assert h0["surprise_pct"] == 0.0513
    assert h0["quarter"] == "Q3 2024"

    h1 = result["history"][1]
    assert h1["quarter"] == "Q4 2024"
    assert h1["eps_actual"] == 2.18

    # Trend
    assert result["trend"]["current_quarter_estimate"] == 2.35
    assert result["trend"]["next_quarter_estimate"] == 2.42


@respx.mock
@pytest.mark.asyncio
async def test_fetch_earnings_surprise_no_data(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.earnings import fetch_earnings_surprise

    # API returns 500
    respx.get("https://query1.finance.yahoo.com/v10/finance/quoteSummary/XYZ").mock(
        return_value=httpx.Response(500)
    )

    result = await fetch_earnings_surprise(fetcher, symbol="XYZ")

    assert result["symbol"] == "XYZ"
    assert result["history"] == []
    assert result["trend"]["current_quarter_estimate"] is None
    assert result["trend"]["next_quarter_estimate"] is None
    assert result["source"] == "yahoo-finance"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_earnings_surprise_missing_surprise_pct(fetcher: Fetcher) -> None:
    """If Yahoo omits surprisePercent, the module should compute it."""
    from world_intel_mcp.sources.earnings import fetch_earnings_surprise

    resp = {
        "quoteSummary": {
            "result": [
                {
                    "earningsHistory": {
                        "history": [
                            {
                                "quarter": {"raw": 1735603200, "fmt": "2024-12-31"},
                                "epsEstimate": {"raw": 2.00, "fmt": "2.00"},
                                "epsActual": {"raw": 2.20, "fmt": "2.20"},
                                # No surprisePercent field
                            },
                        ],
                    },
                    "earningsTrend": {"trend": []},
                }
            ],
            "error": None,
        }
    }

    respx.get("https://query1.finance.yahoo.com/v10/finance/quoteSummary/MSFT").mock(
        return_value=httpx.Response(200, json=resp)
    )

    result = await fetch_earnings_surprise(fetcher, symbol="MSFT")

    assert len(result["history"]) == 1
    # (2.20 - 2.00) / 2.00 * 100 = 10.0
    assert result["history"][0]["surprise_pct"] == 10.0
