"""Company enrichment — aggregate stock, financials, news, and metadata.

Given a company name or ticker symbol, fetches data from Yahoo Finance
(quote + profile), GDELT news, SEC EDGAR filings (if available), and
GitHub (if tech company).  All sources are queried in parallel.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.analysis.company")

_YAHOO_CHART_URL = "https://query1.finance.yahoo.com/v8/finance/chart/{symbol}"
_YAHOO_SUMMARY_URL = (
    "https://query1.finance.yahoo.com/v10/finance/quoteSummary/{symbol}"
)
_GDELT_DOC_URL = "https://api.gdeltproject.org/api/v2/doc/doc"
_GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _safe(coro, label: str):
    """Run a coroutine, swallowing exceptions."""
    try:
        return await coro
    except Exception as exc:
        logger.warning("Company: %s failed: %s", label, exc)
        return None


# ---------------------------------------------------------------------------
# Sub-fetchers
# ---------------------------------------------------------------------------


async def _fetch_stock_quote(fetcher: Fetcher, symbol: str) -> dict | None:
    """Fetch price data from Yahoo Finance v8 chart API."""
    url = _YAHOO_CHART_URL.format(symbol=symbol)
    data = await fetcher.get_json(
        url,
        source="yahoo-finance",
        cache_key=f"company:quote:{symbol}",
        cache_ttl=300,
        params={"range": "5d", "interval": "1d"},
        yahoo_rate_limit=True,
    )
    if not isinstance(data, dict):
        return None
    try:
        meta = data["chart"]["result"][0]["meta"]
        price = meta.get("regularMarketPrice")
        prev = meta.get("previousClose") or meta.get("chartPreviousClose")
        change_pct = None
        if price is not None and prev and prev > 0:
            change_pct = round(((price - prev) / prev) * 100, 4)
        return {
            "price": price,
            "change_pct": change_pct,
            "volume": meta.get("regularMarketVolume"),
            "market_cap": meta.get("marketCap"),
        }
    except (KeyError, IndexError, TypeError):
        logger.warning("Unexpected Yahoo chart structure for %s", symbol)
        return None


async def _fetch_company_info(fetcher: Fetcher, symbol: str) -> dict | None:
    """Fetch company profile + financials from Yahoo quoteSummary."""
    url = _YAHOO_SUMMARY_URL.format(symbol=symbol)
    data = await fetcher.get_json(
        url,
        source="yahoo-finance",
        cache_key=f"company:info:{symbol}",
        cache_ttl=1800,
        params={"modules": "assetProfile,financialData,defaultKeyStatistics"},
        yahoo_rate_limit=True,
    )
    if not isinstance(data, dict):
        return None
    try:
        result = data["quoteSummary"]["result"][0]
        profile = result.get("assetProfile", {})
        fin = result.get("financialData", {})
        stats = result.get("defaultKeyStatistics", {})
        return {
            "sector": profile.get("sector"),
            "industry": profile.get("industry"),
            "employees": profile.get("fullTimeEmployees"),
            "website": profile.get("website"),
            "description": profile.get("longBusinessSummary"),
            "revenue": _raw_val(fin.get("totalRevenue")),
            "profit_margin": _raw_val(fin.get("profitMargins")),
            "pe_ratio": _raw_val(stats.get("forwardPE") or stats.get("trailingPE")),
            "market_cap": _raw_val(stats.get("marketCap")),
        }
    except (KeyError, IndexError, TypeError):
        logger.warning("Unexpected Yahoo quoteSummary structure for %s", symbol)
        return None


def _raw_val(field) -> float | int | None:
    """Extract raw value from Yahoo quoteSummary nested dicts."""
    if field is None:
        return None
    if isinstance(field, dict):
        return field.get("raw")
    return field


async def _fetch_company_news(fetcher: Fetcher, query: str) -> list[dict]:
    """Fetch recent news about the company from GDELT."""
    data = await fetcher.get_json(
        _GDELT_DOC_URL,
        source="gdelt",
        cache_key=f"company:news:{query}",
        cache_ttl=1800,
        params={
            "query": f'"{query}"',
            "mode": "artlist",
            "maxrecords": "5",
            "format": "json",
        },
    )
    if not isinstance(data, dict):
        return []
    articles = data.get("articles", [])
    results: list[dict] = []
    for art in articles[:5]:
        results.append(
            {
                "title": art.get("title"),
                "url": art.get("url"),
                "date": art.get("seendate"),
            }
        )
    return results


async def _fetch_sec_filings(fetcher: Fetcher, ticker: str) -> list[dict] | None:
    """Try to fetch SEC filings via the sec_edgar source module (lazy import)."""
    try:
        from ..sources.sec_edgar import fetch_company_filings
    except ImportError:
        return None
    try:
        result = await fetch_company_filings(fetcher, ticker, limit=5)
        return result.get("filings", [])
    except Exception as exc:
        logger.warning("SEC filings fetch failed for %s: %s", ticker, exc)
        return None


async def _fetch_github_repos(fetcher: Fetcher, query: str) -> list[dict]:
    """Search GitHub for repositories related to the company."""
    data = await fetcher.get_json(
        _GITHUB_SEARCH_URL,
        source="github",
        cache_key=f"company:github:{query}",
        cache_ttl=1800,
        params={"q": query, "sort": "stars", "per_page": "3"},
    )
    if not isinstance(data, dict):
        return []
    items = data.get("items", [])
    results: list[dict] = []
    query_lower = query.lower()
    for repo in items[:3]:
        owner = (repo.get("owner", {}).get("login") or "").lower()
        name = (repo.get("full_name") or "").lower()
        # Only include if the org/owner or repo name plausibly matches
        if query_lower in owner or query_lower in name:
            results.append(
                {
                    "name": repo.get("full_name"),
                    "stars": repo.get("stargazers_count"),
                    "url": repo.get("html_url"),
                }
            )
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def fetch_company_profile(fetcher: Fetcher, query: str) -> dict:
    """Build a composite company profile from multiple data sources.

    Args:
        fetcher: Shared HTTP fetcher with caching and circuit breaking.
        query: Ticker symbol (e.g. "AAPL") or company name.

    Returns:
        Dict with stock, financials, news, SEC filings, and GitHub data.
    """
    symbol = query.upper().strip()

    (
        stock_data,
        info_data,
        news_data,
        sec_data,
        github_data,
    ) = await asyncio.gather(
        _safe(_fetch_stock_quote(fetcher, symbol), "stock_quote"),
        _safe(_fetch_company_info(fetcher, symbol), "company_info"),
        _safe(_fetch_company_news(fetcher, query), "company_news"),
        _safe(_fetch_sec_filings(fetcher, symbol), "sec_filings"),
        _safe(_fetch_github_repos(fetcher, query), "github_repos"),
    )

    # Build stock section
    stock = stock_data if stock_data else {}

    # Build financials section from company info
    financials: dict = {}
    company_name = symbol
    sector = None
    industry = None
    if info_data:
        company_name = (
            info_data.get("description", symbol)[:80]
            if info_data.get("description")
            else symbol
        )
        sector = info_data.get("sector")
        industry = info_data.get("industry")
        financials = {
            "revenue": info_data.get("revenue"),
            "profit_margin": info_data.get("profit_margin"),
            "pe_ratio": info_data.get("pe_ratio"),
            "employees": info_data.get("employees"),
        }
        # Merge market cap from info if not in stock quote
        if not stock.get("market_cap") and info_data.get("market_cap"):
            stock["market_cap"] = info_data["market_cap"]

    result: dict = {
        "query": query,
        "ticker": symbol,
        "company_name": company_name,
        "sector": sector,
        "industry": industry,
        "stock": stock,
        "financials": financials,
        "recent_news": news_data if news_data else [],
    }

    if sec_data is not None:
        result["sec_filings"] = sec_data

    if github_data:
        result["github"] = github_data

    result["fetched_at"] = _utc_now_iso()
    result["source"] = "composite"

    return result
