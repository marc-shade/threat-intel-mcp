"""Bond market data sources for world-intel-mcp.

Provides US Treasury yield curve data (via Treasury Fiscal Data API, FRED,
or Yahoo Finance fallback) and bond ETF index quotes.  Every function takes
a Fetcher instance as its first argument and returns a dict.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.sources.bonds")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TREASURY_URL = (
    "https://api.fiscaldata.treasury.gov/services/api/fiscal_service"
    "/v2/accounting/od/avg_interest_rates"
)

_FRED_URL = "https://api.stlouisfed.org/fred/series/observations"

_YAHOO_CHART_URL = "https://query1.finance.yahoo.com/v8/finance/chart/{symbol}"

# FRED series IDs for individual Treasury yields (1-month through 30-year).
_FRED_YIELD_SERIES: dict[str, str] = {
    "DGS1MO": "1M",
    "DGS3MO": "3M",
    "DGS6MO": "6M",
    "DGS1": "1Y",
    "DGS2": "2Y",
    "DGS5": "5Y",
    "DGS10": "10Y",
    "DGS20": "20Y",
    "DGS30": "30Y",
}

# Yahoo Finance Treasury yield symbols (fewer maturities, no key required).
_YAHOO_YIELD_SYMBOLS: dict[str, str] = {
    "^IRX": "3M",
    "^FVX": "5Y",
    "^TNX": "10Y",
    "^TYX": "30Y",
}

# Bond ETF index symbols.
_BOND_INDICES: dict[str, str] = {
    "AGG": "US Aggregate Bond",
    "TLT": "20+ Year Treasury",
    "HYG": "High Yield Corporate",
    "LQD": "Investment Grade Corporate",
    "TIP": "TIPS",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _fetch_yahoo_quote(
    fetcher: Fetcher,
    symbol: str,
    cache_key: str,
    cache_ttl: int,
) -> dict | None:
    """Fetch a single Yahoo Finance v8 chart quote and extract meta fields."""
    url = _YAHOO_CHART_URL.format(symbol=symbol)
    data = await fetcher.get_json(
        url,
        source="yahoo-finance",
        cache_key=cache_key,
        cache_ttl=cache_ttl,
        params={"range": "1d", "interval": "5m"},
        yahoo_rate_limit=True,
    )
    if not isinstance(data, dict):
        return None

    try:
        meta = data["chart"]["result"][0]["meta"]
        price = meta.get("regularMarketPrice")
        change_pct = meta.get("regularMarketChangePercent")
        if change_pct is None and price is not None:
            prev = meta.get("previousClose") or meta.get("chartPreviousClose")
            if prev and prev > 0:
                change_pct = round(((price - prev) / prev) * 100, 4)
        return {
            "symbol": symbol,
            "price": price,
            "change_pct": change_pct,
            "currency": meta.get("currency"),
        }
    except (KeyError, IndexError, TypeError):
        logger.warning("Unexpected Yahoo chart structure for %s", symbol)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def fetch_yield_curve(fetcher: Fetcher) -> dict:
    """Fetch US Treasury yield curve data.

    Strategy:
    1. Always fetch from the Treasury Fiscal Data API for average interest rates.
    2. If ``FRED_API_KEY`` is set, fetch individual constant-maturity yields
       from FRED (9 maturities from 1-month to 30-year).
    3. Otherwise, fall back to Yahoo Finance for 4 key maturities (3M, 5Y,
       10Y, 30Y).

    Returns a dict with ``yields`` list, ``spread_2s10s``, ``spread_3m10y``,
    ``inverted`` flag, and metadata.
    """
    # --- Treasury Fiscal Data API (always attempted) -------------------------
    treasury_data = await fetcher.get_json(
        _TREASURY_URL,
        source="treasury",
        cache_key="bonds:yield-curve:treasury",
        cache_ttl=3600,
        params={
            "sort": "-record_date",
            "page[size]": "20",
        },
    )

    # --- Individual maturity yields (FRED or Yahoo) --------------------------
    fred_key = os.environ.get("FRED_API_KEY")
    yields: list[dict] = []

    if fred_key:
        yields = await _fetch_yields_from_fred(fetcher, fred_key)
    else:
        yields = await _fetch_yields_from_yahoo(fetcher)

    # --- Compute spreads -----------------------------------------------------
    yield_map: dict[str, float] = {
        y["maturity"]: y["rate"] for y in yields if y["rate"] is not None
    }

    rate_2y = yield_map.get("2Y")
    rate_3m = yield_map.get("3M")
    rate_10y = yield_map.get("10Y")

    spread_2s10s: float | None = None
    spread_3m10y: float | None = None
    inverted = False

    if rate_2y is not None and rate_10y is not None:
        spread_2s10s = round(rate_10y - rate_2y, 4)
    if rate_3m is not None and rate_10y is not None:
        spread_3m10y = round(rate_10y - rate_3m, 4)

    if spread_2s10s is not None and spread_2s10s < 0:
        inverted = True
    elif spread_3m10y is not None and spread_3m10y < 0:
        inverted = True

    # --- Parse Treasury Fiscal Data for supplementary info -------------------
    treasury_records: list[dict] = []
    if isinstance(treasury_data, dict):
        try:
            treasury_records = treasury_data.get("data", [])
        except (AttributeError, TypeError):
            pass

    return {
        "yields": yields,
        "spread_2s10s": spread_2s10s,
        "spread_3m10y": spread_3m10y,
        "inverted": inverted,
        "treasury_records": len(treasury_records),
        "fetched_at": _utc_now_iso(),
        "source": "treasury",
    }


async def _fetch_yields_from_fred(
    fetcher: Fetcher,
    api_key: str,
) -> list[dict]:
    """Fetch Treasury yields from FRED (9 maturities)."""

    async def _fetch_one(series_id: str, maturity: str) -> dict:
        data = await fetcher.get_json(
            _FRED_URL,
            source="fred",
            cache_key=f"bonds:fred:{series_id}",
            cache_ttl=3600,
            params={
                "series_id": series_id,
                "api_key": api_key,
                "file_type": "json",
                "sort_order": "desc",
                "limit": 1,
            },
        )
        rate: float | None = None
        date: str | None = None
        if isinstance(data, dict):
            try:
                obs = data.get("observations", [])
                if obs:
                    val = obs[0].get("value")
                    date = obs[0].get("date")
                    if val not in (None, ".", ""):
                        rate = float(val)
            except (KeyError, TypeError, ValueError, IndexError) as exc:
                logger.warning("Failed to parse FRED %s: %s", series_id, exc)
        return {"maturity": maturity, "rate": rate, "date": date, "series": series_id}

    tasks = [
        _fetch_one(series_id, maturity)
        for series_id, maturity in _FRED_YIELD_SERIES.items()
    ]
    return list(await asyncio.gather(*tasks))


async def _fetch_yields_from_yahoo(fetcher: Fetcher) -> list[dict]:
    """Fetch Treasury yields from Yahoo Finance (4 maturities, no key)."""

    async def _fetch_one(symbol: str, maturity: str) -> dict:
        quote = await _fetch_yahoo_quote(
            fetcher,
            symbol,
            f"bonds:yahoo:{symbol}",
            3600,
        )
        rate: float | None = None
        if quote is not None and quote.get("price") is not None:
            # Yahoo yields are quoted as price (e.g., 4.52 means 4.52%)
            rate = quote["price"]
        return {"maturity": maturity, "rate": rate, "symbol": symbol}

    tasks = [
        _fetch_one(symbol, maturity)
        for symbol, maturity in _YAHOO_YIELD_SYMBOLS.items()
    ]
    return list(await asyncio.gather(*tasks))


async def fetch_bond_indices(fetcher: Fetcher) -> dict:
    """Fetch bond ETF index quotes from Yahoo Finance.

    Covers AGG (US Agg), TLT (Long Treasury), HYG (High Yield Corp),
    LQD (Investment Grade Corp), and TIP (TIPS).

    Returns::

        {"indices": [{symbol, name, price, change_pct}], ...}
    """
    tasks = [
        _fetch_yahoo_quote(fetcher, sym, f"bonds:index:{sym}", 1800)
        for sym in _BOND_INDICES
    ]
    results = await asyncio.gather(*tasks)

    indices: list[dict] = []
    for sym, quote in zip(_BOND_INDICES, results):
        if quote is None:
            continue
        indices.append(
            {
                "symbol": sym,
                "name": _BOND_INDICES[sym],
                "price": quote["price"],
                "change_pct": quote["change_pct"],
            }
        )

    return {
        "indices": indices,
        "fetched_at": _utc_now_iso(),
        "source": "yahoo-finance",
    }
