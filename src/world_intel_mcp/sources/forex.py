"""Foreign exchange rate data from the European Central Bank.

Uses the Frankfurter API (free ECB daily reference rate mirror) to provide
live forex rates, historical time-series, and major cross-rate calculations.
"""

import logging
from datetime import datetime, timedelta, timezone

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.sources.forex")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FRANKFURTER_LATEST = "https://api.frankfurter.dev/v1/latest"
_FRANKFURTER_HISTORY = "https://api.frankfurter.dev/v1/{start}..{end}"

_MAJOR_SYMBOLS = "EUR,GBP,JPY,CHF,AUD,CAD,NZD,CNY"

# Trade-weighted USD index proxy weights (simplified, based on DXY composition)
# DXY weights: EUR 57.6%, JPY 13.6%, GBP 11.9%, CAD 9.1%, SEK 4.2%, CHF 3.6%
# We use what's available from our major pairs:
_DXY_WEIGHTS: dict[str, float] = {
    "EUR": 0.576,
    "JPY": 0.136,
    "GBP": 0.119,
    "CAD": 0.091,
    "CHF": 0.036,
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def fetch_forex_rates(
    fetcher: Fetcher,
    base: str = "USD",
    symbols: str | None = None,
) -> dict:
    """Fetch latest ECB daily reference exchange rates.

    Args:
        fetcher: Shared HTTP fetcher.
        base: Base currency code (default ``"USD"``).
        symbols: Comma-separated target currencies (e.g. ``"EUR,GBP,JPY"``).
                 If *None*, returns all available currencies.

    Returns:
        Dict with ``base``, ``date``, ``rates``, plus metadata.
    """
    params: dict[str, str] = {"base": base}
    if symbols:
        params["symbols"] = symbols

    data = await fetcher.get_json(
        _FRANKFURTER_LATEST,
        source="ecb-forex",
        cache_key=f"forex:rates:{base}",
        cache_ttl=1800,
        params=params,
    )

    if not isinstance(data, dict):
        return {
            "base": base,
            "date": None,
            "rates": {},
            "fetched_at": _utc_now_iso(),
            "source": "ecb-forex",
        }

    return {
        "base": data.get("base", base),
        "date": data.get("date"),
        "rates": data.get("rates", {}),
        "fetched_at": _utc_now_iso(),
        "source": "ecb-forex",
    }


async def fetch_forex_timeseries(
    fetcher: Fetcher,
    base: str = "USD",
    symbol: str = "EUR",
    days: int = 30,
) -> dict:
    """Fetch historical exchange rate time-series from ECB.

    Args:
        fetcher: Shared HTTP fetcher.
        base: Base currency code.
        symbol: Target currency code.
        days: Number of days of history (default 30).

    Returns:
        Dict with ``rates`` list, ``trend`` summary, plus metadata.
    """
    today = datetime.now(timezone.utc).date()
    start_date = today - timedelta(days=days)

    url = _FRANKFURTER_HISTORY.format(
        start=start_date.isoformat(), end=today.isoformat()
    )
    params: dict[str, str] = {"base": base, "symbols": symbol}

    data = await fetcher.get_json(
        url,
        source="ecb-forex",
        cache_key=f"forex:history:{base}:{symbol}:{days}",
        cache_ttl=3600,
        params=params,
    )

    result: dict = {
        "base": base,
        "symbol": symbol,
        "days": days,
        "rates": [],
        "trend": None,
        "fetched_at": _utc_now_iso(),
        "source": "ecb-forex",
    }

    if not isinstance(data, dict):
        return result

    try:
        raw_rates = data.get("rates", {})
        # Frankfurter returns {"rates": {"2026-03-01": {"EUR": 0.92}, ...}}
        sorted_dates = sorted(raw_rates.keys())
        rate_list: list[dict] = []
        for date_str in sorted_dates:
            day_rates = raw_rates[date_str]
            rate_val = day_rates.get(symbol)
            if rate_val is not None:
                rate_list.append({"date": date_str, "rate": rate_val})

        result["rates"] = rate_list

        # Compute trend
        if len(rate_list) >= 2:
            start_rate = rate_list[0]["rate"]
            end_rate = rate_list[-1]["rate"]
            change_pct = (
                round(((end_rate - start_rate) / start_rate) * 100, 4)
                if start_rate
                else 0
            )
            result["trend"] = {
                "start": start_rate,
                "end": end_rate,
                "change_pct": change_pct,
            }
    except (KeyError, TypeError, ValueError) as exc:
        logger.warning(
            "Failed to parse ECB timeseries for %s/%s: %s", base, symbol, exc
        )

    return result


async def fetch_major_crosses(fetcher: Fetcher) -> dict:
    """Fetch USD-based rates for the 8 major currency pairs and compute crosses.

    Returns major pairs, derived cross rates (EUR/GBP, EUR/JPY, GBP/JPY),
    and a DXY-proxy trade-weighted USD strength estimate.
    """
    rates_data = await fetch_forex_rates(
        fetcher,
        base="USD",
        symbols=_MAJOR_SYMBOLS,
    )

    rates = rates_data.get("rates", {})

    # Build major pairs list
    major_pairs: list[dict] = []
    for sym in _MAJOR_SYMBOLS.split(","):
        rate = rates.get(sym)
        if rate is not None:
            major_pairs.append({"pair": f"USD/{sym}", "rate": rate})

    # Compute cross rates from USD-based rates
    # Cross rate: A/B = (USD/B) / (USD/A)
    cross_rates: dict[str, float | None] = {}
    eur = rates.get("EUR")
    gbp = rates.get("GBP")
    jpy = rates.get("JPY")

    if eur and gbp:
        cross_rates["EUR/GBP"] = round(gbp / eur, 6)
    if eur and jpy:
        cross_rates["EUR/JPY"] = round(jpy / eur, 4)
    if gbp and jpy:
        cross_rates["GBP/JPY"] = round(jpy / gbp, 4)

    # DXY proxy: trade-weighted geometric average
    # DXY = product(rate^weight) — but ECB gives USD/X, while DXY uses X/USD for some.
    # For simplicity, use inverse rates (since higher USD/EUR means weaker dollar):
    # DXY proxy = 100 * product((1/rate)^weight) for available pairs
    dxy_proxy: float | None = None
    try:
        product = 1.0
        total_weight = 0.0
        for sym, weight in _DXY_WEIGHTS.items():
            rate = rates.get(sym)
            if rate and rate > 0:
                # USD/X rate: higher means X is cheaper, i.e. USD is stronger
                # DXY convention: higher = stronger USD
                # Invert because USD/EUR > 1 means EUR costs more than 1 USD
                product *= (1.0 / rate) ** weight
                total_weight += weight
        if total_weight > 0:
            # Normalize if not all weights present
            product = (
                product ** (1.0 / total_weight) if total_weight < 0.95 else product
            )
            dxy_proxy = round(product * 100, 4)
    except (TypeError, ValueError, ZeroDivisionError) as exc:
        logger.warning("Failed to compute DXY proxy: %s", exc)

    return {
        "major_pairs": major_pairs,
        "cross_rates": cross_rates,
        "dxy_proxy": dxy_proxy,
        "date": rates_data.get("date"),
        "fetched_at": _utc_now_iso(),
        "source": "ecb-forex",
    }
