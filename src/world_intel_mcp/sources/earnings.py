"""Earnings calendar and surprise data for world-intel-mcp.

Fetches upcoming earnings dates and historical earnings surprises for
mega-cap stocks via Yahoo Finance quoteSummary API.  Every function takes
a Fetcher instance as its first argument and returns a dict.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.sources.earnings")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_YAHOO_SUMMARY_URL = (
    "https://query1.finance.yahoo.com/v10/finance/quoteSummary/{symbol}"
)

# Top 20 mega-cap stocks to check for upcoming earnings.
_MEGACAP_SYMBOLS = [
    "AAPL",
    "MSFT",
    "GOOGL",
    "AMZN",
    "NVDA",
    "META",
    "TSLA",
    "BRK-B",
    "JPM",
    "V",
    "UNH",
    "MA",
    "HD",
    "PG",
    "JNJ",
    "LLY",
    "ABBV",
    "XOM",
    "CVX",
    "BAC",
]

_BATCH_SIZE = 5  # Concurrent requests per batch to respect Yahoo rate limits.


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_earnings_date(raw: dict | None) -> str | None:
    """Extract an ISO date string from a Yahoo calendarEvents earnings date."""
    if raw is None:
        return None
    # Yahoo returns {"raw": 1714003200, "fmt": "2026-04-24"}
    fmt = raw.get("fmt")
    if fmt:
        return fmt
    raw_ts = raw.get("raw")
    if raw_ts is not None:
        try:
            return datetime.fromtimestamp(int(raw_ts), tz=timezone.utc).strftime(
                "%Y-%m-%d"
            )
        except (ValueError, TypeError, OSError):
            pass
    return None


def _parse_float(raw: dict | float | None) -> float | None:
    """Extract a float from a Yahoo value object or plain number."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, dict):
        val = raw.get("raw")
        if val is not None:
            try:
                return float(val)
            except (ValueError, TypeError):
                pass
    return None


def _parse_quarter_label(date_str: str | None) -> str | None:
    """Convert a date string like '2025-12-31' to a quarter label like 'Q4 2025'."""
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        q = (dt.month - 1) // 3 + 1
        return f"Q{q} {dt.year}"
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def fetch_earnings_calendar(
    fetcher: Fetcher,
    days_ahead: int = 7,
) -> dict:
    """Fetch upcoming earnings announcements for mega-cap stocks.

    Checks each symbol's ``calendarEvents`` and ``earningsHistory`` modules
    via Yahoo Finance quoteSummary.  Requests are batched (5 at a time) to
    respect Yahoo rate limits.

    Args:
        fetcher: Shared HTTP fetcher.
        days_ahead: Number of days to look ahead for "this_week" filtering.

    Returns a dict with ``upcoming`` (all found earnings dates sorted by
    date), ``this_week`` (subset within *days_ahead*), and metadata.
    """
    now = datetime.now(timezone.utc)
    cutoff = now + timedelta(days=days_ahead)

    async def _fetch_symbol(symbol: str) -> dict | None:
        url = _YAHOO_SUMMARY_URL.format(symbol=symbol)
        data = await fetcher.get_json(
            url,
            source="yahoo-finance",
            cache_key=f"earnings:calendar:{symbol}",
            cache_ttl=3600,
            params={"modules": "calendarEvents,earningsHistory"},
            yahoo_rate_limit=True,
        )
        if not isinstance(data, dict):
            return None
        try:
            result_obj = data["quoteSummary"]["result"][0]

            # --- Calendar events (next earnings date) ---
            cal = result_obj.get("calendarEvents", {})
            earnings = cal.get("earnings", {})
            earnings_dates = earnings.get("earningsDate", [])

            earnings_date_str: str | None = None
            if earnings_dates:
                earnings_date_str = _parse_earnings_date(earnings_dates[0])

            eps_estimate = _parse_float(earnings.get("earningsAverage"))

            # --- Company name from earnings or symbol fallback ---
            company = symbol

            # --- Most recent EPS from earningsHistory ---
            hist = result_obj.get("earningsHistory", {})
            history_records = hist.get("history", [])
            eps_previous: float | None = None
            if history_records:
                # Most recent quarter is first after sorting by date desc
                latest = history_records[-1]
                eps_previous = _parse_float(latest.get("epsActual"))

            if earnings_date_str is None:
                return None

            # Compute days until earnings
            try:
                ed = datetime.strptime(earnings_date_str, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
                days_until = (ed - now).days
            except (ValueError, TypeError):
                days_until = None

            return {
                "symbol": symbol,
                "company": company,
                "earnings_date": earnings_date_str,
                "days_until": days_until,
                "eps_estimate": eps_estimate,
                "eps_previous": eps_previous,
            }
        except (KeyError, IndexError, TypeError) as exc:
            logger.warning("Failed to parse earnings for %s: %s", symbol, exc)
            return None

    # Batch requests to respect rate limits
    all_results: list[dict | None] = []
    for i in range(0, len(_MEGACAP_SYMBOLS), _BATCH_SIZE):
        batch = _MEGACAP_SYMBOLS[i : i + _BATCH_SIZE]
        batch_results = await asyncio.gather(*[_fetch_symbol(sym) for sym in batch])
        all_results.extend(batch_results)

    # Filter and sort
    upcoming: list[dict] = [r for r in all_results if r is not None]
    upcoming.sort(key=lambda x: x.get("earnings_date") or "9999-99-99")

    # This-week subset
    this_week: list[dict] = []
    for entry in upcoming:
        ed_str = entry.get("earnings_date")
        if ed_str:
            try:
                ed = datetime.strptime(ed_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if ed <= cutoff:
                    this_week.append(entry)
            except (ValueError, TypeError):
                pass

    return {
        "upcoming": upcoming,
        "this_week": this_week,
        "fetched_at": _utc_now_iso(),
        "source": "yahoo-finance",
    }


async def fetch_earnings_surprise(
    fetcher: Fetcher,
    symbol: str,
) -> dict:
    """Fetch recent earnings surprises for a specific stock.

    Uses Yahoo Finance quoteSummary ``earningsHistory`` and
    ``earningsTrend`` modules.

    Args:
        fetcher: Shared HTTP fetcher.
        symbol: Stock ticker symbol (e.g., "AAPL").

    Returns a dict with ``history`` (past quarter surprises) and ``trend``
    (current/next quarter estimates), plus metadata.
    """
    url = _YAHOO_SUMMARY_URL.format(symbol=symbol)
    data = await fetcher.get_json(
        url,
        source="yahoo-finance",
        cache_key=f"earnings:surprise:{symbol}",
        cache_ttl=3600,
        params={"modules": "earningsHistory,earningsTrend"},
        yahoo_rate_limit=True,
    )

    result: dict = {
        "symbol": symbol,
        "history": [],
        "trend": {
            "current_quarter_estimate": None,
            "next_quarter_estimate": None,
        },
        "fetched_at": _utc_now_iso(),
        "source": "yahoo-finance",
    }

    if not isinstance(data, dict):
        return result

    try:
        summary = data["quoteSummary"]["result"][0]
    except (KeyError, IndexError, TypeError):
        return result

    # --- Earnings history (past quarter surprises) ---------------------------
    hist = summary.get("earningsHistory", {})
    for rec in hist.get("history", []):
        eps_estimate = _parse_float(rec.get("epsEstimate"))
        eps_actual = _parse_float(rec.get("epsActual"))
        surprise_pct = _parse_float(rec.get("surprisePercent"))

        quarter_date = _parse_earnings_date(rec.get("quarter"))
        quarter_label = _parse_quarter_label(quarter_date)

        # Compute surprise_pct if Yahoo didn't provide it
        if (
            surprise_pct is None
            and eps_estimate
            and eps_estimate != 0
            and eps_actual is not None
        ):
            surprise_pct = round(
                ((eps_actual - eps_estimate) / abs(eps_estimate)) * 100, 2
            )

        result["history"].append(
            {
                "quarter": quarter_label or quarter_date,
                "eps_estimate": eps_estimate,
                "eps_actual": eps_actual,
                "surprise_pct": surprise_pct,
            }
        )

    # --- Earnings trend (forward estimates) ----------------------------------
    trend = summary.get("earningsTrend", {})
    for t in trend.get("trend", []):
        period = t.get("period")
        earnings_est = t.get("earningsEstimate", {})
        avg = _parse_float(earnings_est.get("avg"))

        if period == "0q":
            result["trend"]["current_quarter_estimate"] = avg
        elif period == "+1q":
            result["trend"]["next_quarter_estimate"] = avg

    return result
