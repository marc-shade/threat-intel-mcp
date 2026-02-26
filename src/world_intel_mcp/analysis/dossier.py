"""Comprehensive country intelligence dossier.

Aggregates data from multiple sources into a single country profile:
country brief (World Bank + ACLED), stock index, election calendar,
sanctions exposure, news mentions, and associated hotspots/conflict zones.

All sub-queries are run in parallel for speed.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

logger = logging.getLogger("world-intel-mcp.analysis.dossier")

# Minimal ISO-2 <-> ISO-3 mapping for the 22 tier-1 countries + major extras.
_ISO2_TO_ISO3: dict[str, str] = {
    "US": "USA", "CN": "CHN", "RU": "RUS", "UA": "UKR", "SY": "SYR",
    "YE": "YEM", "MM": "MMR", "SD": "SDN", "NG": "NGA", "AF": "AFG",
    "IQ": "IRQ", "IR": "IRN", "TW": "TWN", "KP": "PRK", "IL": "ISR",
    "PS": "PSE", "LB": "LBN", "ET": "ETH", "CD": "COD", "PK": "PAK",
    "IN": "IND", "MX": "MEX", "GB": "GBR", "DE": "DEU", "FR": "FRA",
    "JP": "JPN", "KR": "KOR", "BR": "BRA", "AU": "AUS", "CA": "CAN",
    "SA": "SAU", "TR": "TUR", "EG": "EGY", "ZA": "ZAF", "ID": "IDN",
    "TH": "THA", "VN": "VNM", "PH": "PHL", "PL": "POL", "IT": "ITA",
    "ES": "ESP", "SE": "SWE", "NO": "NOR", "CH": "CHE", "NL": "NLD",
    "BE": "BEL", "AR": "ARG", "CL": "CHL", "CO": "COL", "PE": "PER",
}
_ISO3_TO_ISO2: dict[str, str] = {v: k for k, v in _ISO2_TO_ISO3.items()}


def _normalize_country(code: str) -> tuple[str, str]:
    """Return (iso2, iso3) from either format. Raises ValueError if unknown."""
    code = code.upper().strip()
    if len(code) == 2:
        iso2 = code
        iso3 = _ISO2_TO_ISO3.get(code)
        if iso3 is None:
            raise ValueError(f"Unknown ISO-2 code: {code}")
        return iso2, iso3
    if len(code) == 3:
        iso3 = code
        iso2 = _ISO3_TO_ISO2.get(code)
        if iso2 is None:
            raise ValueError(f"Unknown ISO-3 code: {code}")
        return iso2, iso3
    raise ValueError(f"Country code must be 2 or 3 characters: {code}")


async def _safe(coro, label: str) -> dict:
    """Run a coroutine, catching exceptions."""
    try:
        return await coro
    except Exception as exc:
        logger.warning("Dossier: %s failed: %s", label, exc)
        return {"_error": str(exc)}


async def fetch_country_dossier(
    fetcher,
    country: str = "US",
) -> dict:
    """Build a comprehensive country intelligence dossier.

    Pulls from 6 sources in parallel:
      1. Country brief (World Bank GDP/inflation + ACLED conflict)
      2. Stock market index (Yahoo Finance)
      3. Election calendar (curated dataset)
      4. Sanctions exposure (OFAC SDN search)
      5. Recent news mentions (RSS feeds)
      6. Country config (baseline risk, hotspots, conflict zones)

    Args:
        fetcher: Shared HTTP fetcher with caching and circuit breaking.
        country: ISO-2 or ISO-3 country code (e.g. "US", "USA", "UA", "UKR").

    Returns:
        Dict with sections: overview, economy, markets, elections, sanctions,
        news, security, and metadata.
    """
    now = datetime.now(timezone.utc)

    try:
        iso2, iso3 = _normalize_country(country)
    except ValueError as exc:
        return {
            "error": str(exc),
            "hint": "Use ISO-2 (US, UA) or ISO-3 (USA, UKR) codes",
            "source": "country-dossier",
            "timestamp": now.isoformat(),
        }

    # Lazy imports to avoid circular deps
    from ..sources.intelligence import fetch_country_brief
    from ..sources.markets import fetch_country_stocks
    from ..sources.elections import fetch_election_calendar
    from ..sources.sanctions import fetch_sanctions_search
    from ..sources.news import fetch_news_feed
    from ..config.countries import TIER1_COUNTRIES, INTEL_HOTSPOTS, CONFLICT_ZONES

    # Run all data fetches in parallel
    (
        brief_data,
        stock_data,
        election_data,
        sanctions_data,
        news_data,
    ) = await asyncio.gather(
        _safe(fetch_country_brief(fetcher, country_code=iso2), "country_brief"),
        _safe(fetch_country_stocks(fetcher, country=iso3), "country_stocks"),
        _safe(fetch_election_calendar(fetcher, country=iso3), "elections"),
        _safe(fetch_sanctions_search(fetcher, query=iso3, limit=10), "sanctions"),
        _safe(fetch_news_feed(fetcher, category="all", limit=200), "news_feed"),
    )

    # --- Section 1: Overview ---
    country_config = TIER1_COUNTRIES.get(iso3, {})
    country_name = country_config.get("name", iso3)

    overview = {
        "country": country_name,
        "iso2": iso2,
        "iso3": iso3,
        "baseline_risk": country_config.get("baseline_risk"),
        "event_multiplier": country_config.get("event_multiplier"),
    }

    # --- Section 2: Economy (from country brief) ---
    economy = {}
    if "_error" not in brief_data:
        supporting = brief_data.get("supporting_data", {})
        economy = {
            "gdp": supporting.get("gdp", []),
            "inflation": supporting.get("inflation", []),
            "conflict_events_30d": supporting.get("conflict_events_count", 0),
            "llm_available": brief_data.get("llm_available", False),
            "brief_text": brief_data.get("brief", ""),
        }
    else:
        economy = {"_error": brief_data["_error"]}

    # --- Section 3: Markets ---
    markets = {}
    if "_error" not in stock_data and "error" not in stock_data:
        markets = {
            "ticker": stock_data.get("ticker"),
            "exchange": stock_data.get("exchange"),
            "quote": stock_data.get("quote"),
        }
    else:
        markets = {"note": stock_data.get("error", stock_data.get("_error", "unavailable"))}

    # --- Section 4: Elections ---
    elections = {}
    if "_error" not in election_data:
        country_elections = election_data.get("elections", [])
        elections = {
            "upcoming": [e for e in country_elections if e.get("status") == "upcoming"],
            "past": [e for e in country_elections if e.get("status") == "past"],
            "count": len(country_elections),
        }
    else:
        elections = {"_error": election_data["_error"]}

    # --- Section 5: Sanctions ---
    sanctions = {}
    if "_error" not in sanctions_data:
        sanctions = {
            "matches": sanctions_data.get("results", []),
            "match_count": sanctions_data.get("count", 0),
        }
    else:
        sanctions = {"_error": sanctions_data["_error"]}

    # --- Section 6: News ---
    news_mentions = []
    if "_error" not in news_data:
        country_keywords = country_config.get("keywords", [country_name.lower()])
        for article in news_data.get("articles", []):
            title = (article.get("title") or "").lower()
            if any(kw in title for kw in country_keywords):
                news_mentions.append({
                    "title": article.get("title"),
                    "source": article.get("source"),
                    "published": article.get("published"),
                    "link": article.get("link"),
                    "category": article.get("category"),
                })
                if len(news_mentions) >= 15:
                    break

    # --- Section 7: Security (hotspots + conflict zones) ---
    associated_hotspots = []
    for name, hs in INTEL_HOTSPOTS.items():
        if iso3 in hs.get("associated_countries", []):
            associated_hotspots.append({
                "name": name,
                "lat": hs["lat"],
                "lon": hs["lon"],
                "baseline_escalation": hs["baseline_escalation"],
            })

    active_conflicts = []
    for cz in CONFLICT_ZONES:
        cz_name = cz["name"].lower()
        if any(kw in cz_name for kw in country_config.get("keywords", [country_name.lower()])):
            active_conflicts.append(cz)

    security = {
        "hotspots": associated_hotspots,
        "hotspot_count": len(associated_hotspots),
        "active_conflicts": active_conflicts,
        "conflict_count": len(active_conflicts),
    }

    return {
        "overview": overview,
        "economy": economy,
        "markets": markets,
        "elections": elections,
        "sanctions": sanctions,
        "news": {
            "mentions": news_mentions,
            "mention_count": len(news_mentions),
        },
        "security": security,
        "sections": ["overview", "economy", "markets", "elections", "sanctions", "news", "security"],
        "source": "country-dossier",
        "timestamp": now.isoformat(),
    }
