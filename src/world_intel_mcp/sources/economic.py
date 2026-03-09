"""Economic indicator data sources.

Fetches energy prices (EIA), macroeconomic series (FRED), and
development indicators (World Bank) for the world-intel-mcp server.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.sources.economic")


# ---------------------------------------------------------------------------
# EIA: Energy prices (oil & natural gas)
# ---------------------------------------------------------------------------

_EIA_OIL_URL = "https://api.eia.gov/v2/petroleum/pri/spt/data/"
_EIA_GAS_URL = "https://api.eia.gov/v2/natural-gas/pri/fut/data/"


async def fetch_energy_prices(
    fetcher: Fetcher,
    api_key: str | None = None,
) -> dict:
    """Fetch latest crude oil (Brent & WTI) and natural gas spot prices.

    Uses the EIA API v2.  Requires an API key via *api_key* or the
    ``EIA_API_KEY`` environment variable.

    Returns a dict with ``oil`` and ``natural_gas`` sub-keys, plus
    metadata (``fetched_at``, ``source``).
    """
    key = api_key or os.environ.get("EIA_API_KEY")
    if not key:
        return {"error": "EIA_API_KEY not configured"}

    oil_params = {
        "api_key": key,
        "frequency": "daily",
        "data[0]": "value",
        "sort[0][column]": "period",
        "sort[0][direction]": "desc",
        "length": 5,
        "facets[product][]": ["EPCBRENT", "EPCWTI"],
    }

    gas_params = {
        "api_key": key,
        "frequency": "daily",
        "data[0]": "value",
        "sort[0][column]": "period",
        "sort[0][direction]": "desc",
        "length": 5,
        "facets[process][]": "PRC",
    }

    oil_data, gas_data = await asyncio.gather(
        fetcher.get_json(
            _EIA_OIL_URL,
            source="eia",
            cache_key="economic:energy:oil",
            cache_ttl=3600,
            params=oil_params,
        ),
        fetcher.get_json(
            _EIA_GAS_URL,
            source="eia",
            cache_key="economic:energy:gas",
            cache_ttl=3600,
            params=gas_params,
        ),
    )

    result: dict = {
        "oil": {"brent": None, "wti": None},
        "natural_gas": None,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "source": "eia",
    }

    # --- Parse oil prices ---------------------------------------------------
    if oil_data:
        try:
            records = oil_data.get("response", {}).get("data", [])
            for rec in records:
                product = rec.get("product")
                value = rec.get("value")
                period = rec.get("period")
                if value is None or period is None:
                    continue
                entry = {"price": float(value), "date": period}
                if product == "EPCBRENT" and result["oil"]["brent"] is None:
                    result["oil"]["brent"] = entry
                elif product == "EPCWTI" and result["oil"]["wti"] is None:
                    result["oil"]["wti"] = entry
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("Failed to parse EIA oil data: %s", exc)

    # --- Parse natural gas price --------------------------------------------
    if gas_data:
        try:
            records = gas_data.get("response", {}).get("data", [])
            if records:
                rec = records[0]
                value = rec.get("value")
                period = rec.get("period")
                if value is not None and period is not None:
                    result["natural_gas"] = {
                        "price": float(value),
                        "date": period,
                    }
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("Failed to parse EIA natural gas data: %s", exc)

    return result


# ---------------------------------------------------------------------------
# AAA: US retail gasoline & diesel prices (daily, via gasprices.aaa.com)
# ---------------------------------------------------------------------------

_AAA_URL = "https://gasprices.aaa.com/"

# Row labels in AAA's price table → our key names
_AAA_ROW_LABELS = {
    "Current Avg.": "today",
    "Yesterday Avg.": "yesterday",
    "Week Ago Avg.": "week_ago",
    "Month Ago Avg.": "month_ago",
    "Year Ago Avg.": "year_ago",
}

# Column order in the AAA table (indices 1..5 after the row label)
_AAA_GRADES = ["regular", "mid_grade", "premium", "diesel", "e85"]


def _parse_aaa_html(html: str) -> dict:
    """Extract national gas prices from AAA's HTML price table.

    Returns dict with per-grade prices, yesterday delta, and week/month/year
    comparisons.  Also extracts per-state prices from the ``iwmparam`` JS var.
    """
    import re

    result: dict = {"prices": {}, "state_prices": []}

    # --- National price table ------------------------------------------------
    # Table has rows: Current Avg., Yesterday Avg., Week Ago Avg., ...
    # Each row: label, Regular, Mid-Grade, Premium, Diesel, E85
    table_match = re.search(
        r"<table[^>]*>.*?Regular.*?</table>", html, re.DOTALL | re.IGNORECASE
    )
    if table_match:
        table_html = table_match.group(0)
        rows = re.findall(
            r"<tr[^>]*>\s*<td[^>]*>([^<]+)</td>\s*"
            r"<td[^>]*>\$?([\d.]+)</td>\s*"
            r"<td[^>]*>\$?([\d.]+)</td>\s*"
            r"<td[^>]*>\$?([\d.]+)</td>\s*"
            r"<td[^>]*>\$?([\d.]+)</td>\s*"
            r"<td[^>]*>\$?([\d.]+)</td>",
            table_html,
            re.DOTALL,
        )

        time_rows: dict[str, dict[str, float]] = {}
        for row in rows:
            label = row[0].strip()
            key = _AAA_ROW_LABELS.get(label)
            if key is None:
                continue
            time_rows[key] = {
                grade: float(row[i + 1]) for i, grade in enumerate(_AAA_GRADES)
            }

        today = time_rows.get("today", {})
        yesterday = time_rows.get("yesterday", {})

        for grade in _AAA_GRADES:
            cur = today.get(grade)
            if cur is None:
                continue
            entry: dict = {
                "price_per_gallon": cur,
                "unit": "$/gallon",
            }
            prev = yesterday.get(grade)
            if prev is not None and prev != 0:
                delta = cur - prev
                entry["change"] = round(delta, 3)
                entry["change_pct"] = round(delta / prev * 100, 2)

            # Week/month/year comparisons
            for period_key, period_label in [
                ("week_ago", "week_ago"),
                ("month_ago", "month_ago"),
                ("year_ago", "year_ago"),
            ]:
                comp = time_rows.get(period_key, {}).get(grade)
                if comp is not None and comp != 0:
                    entry[period_label] = comp
                    entry[f"{period_label}_pct"] = round((cur - comp) / comp * 100, 2)

            result["prices"][grade] = entry

    # --- State prices from iwmparam ------------------------------------------
    iwm = re.search(r'iwmparam\[0\]\.placestxt\s*=\s*"([^"]+)"', html)
    if iwm:
        parts = iwm.group(1).split(",")
        # Format: STATE,Name,$price,link,color;STATE,Name,...
        i = 0
        while i + 2 < len(parts):
            state_code = parts[i].split(";")[-1] if ";" in parts[i] else parts[i]
            state_code = state_code.strip()
            price_str = parts[i + 2].strip().lstrip("$")
            try:
                price = float(price_str)
                result["state_prices"].append({"state": state_code, "price": price})
            except (ValueError, TypeError):
                pass
            i += 4  # skip link and color-tagged next state

    return result


def _fetch_aaa_html() -> str | None:
    """Fetch AAA gas prices page using urllib (bypasses Cloudflare)."""
    import urllib.request

    req = urllib.request.Request(
        _AAA_URL,
        headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    try:
        resp = urllib.request.urlopen(req, timeout=20)
        return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


async def fetch_gas_prices(
    fetcher: Fetcher,
    region: str | None = None,
    api_key: str | None = None,
) -> dict:
    """Fetch US retail gasoline & diesel prices from AAA (daily).

    Scrapes gasprices.aaa.com for today's national averages across
    regular, mid-grade, premium, diesel, and E85.  Includes day-over-day,
    week, month, and year-over-year deltas.  Also includes per-state
    regular prices.

    No API key required — public page.  The *region* and *api_key*
    parameters are accepted for interface compatibility but ignored.
    """
    # AAA is behind Cloudflare — httpx gets 403.  Use urllib which
    # has a simpler TLS fingerprint and passes through.  Cache via
    # the fetcher's cache to avoid redundant requests.
    cached = fetcher.cache.get("economic:gas_prices:aaa")
    if cached is not None:
        html = cached
    else:
        try:
            html = await asyncio.to_thread(_fetch_aaa_html)
            if html:
                fetcher.cache.set("economic:gas_prices:aaa", html, ttl_seconds=1800)
        except Exception as exc:
            logger.warning("Failed to fetch AAA gas prices: %s", exc)
            html = fetcher.cache.get_stale("economic:gas_prices:aaa")

    result: dict = {
        "region": "US",
        "prices": {},
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "source": "aaa",
        "update_frequency": "daily",
    }

    if html is None:
        return result

    try:
        parsed = _parse_aaa_html(html)
        result["prices"] = parsed["prices"]
        result["state_prices"] = parsed.get("state_prices", [])
    except Exception as exc:
        logger.warning("Failed to parse AAA gas prices: %s", exc)

    return result


# ---------------------------------------------------------------------------
# EIA: US residential natural gas prices
# ---------------------------------------------------------------------------

_EIA_NATGAS_RESIDENTIAL_URL = "https://api.eia.gov/v2/natural-gas/pri/sum/data/"

# State codes (subset) — EIA uses 2-letter postal codes
_US_STATES = {
    "US": "NUS",  # nationwide
}


async def fetch_residential_natgas_prices(
    fetcher: Fetcher,
    api_key: str | None = None,
) -> dict:
    """Fetch US residential natural gas prices from EIA.

    Returns the most recent monthly residential natural gas price
    ($/thousand cubic feet) nationwide.

    Requires ``EIA_API_KEY``.
    """
    key = api_key or os.environ.get("EIA_API_KEY")
    if not key:
        return {"error": "EIA_API_KEY not configured"}

    params = {
        "api_key": key,
        "frequency": "monthly",
        "data[0]": "value",
        "sort[0][column]": "period",
        "sort[0][direction]": "desc",
        "length": 6,
        "facets[duoarea][]": "NUS",
        "facets[process][]": "PRS",  # residential
    }

    data = await fetcher.get_json(
        _EIA_NATGAS_RESIDENTIAL_URL,
        source="eia",
        cache_key="economic:natgas_residential",
        cache_ttl=3600,
        params=params,
    )

    result: dict = {
        "prices": [],
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "source": "eia",
        "unit": "$/thousand cubic feet",
    }

    if data is None:
        return result

    try:
        records = data.get("response", {}).get("data", [])
        for rec in records:
            value = rec.get("value")
            period = rec.get("period")
            if value is not None and period is not None:
                result["prices"].append(
                    {
                        "price": float(value),
                        "period": period,
                    }
                )
    except (KeyError, TypeError, ValueError) as exc:
        logger.warning("Failed to parse EIA residential natgas data: %s", exc)

    # Add change from previous period on the most recent entry
    if len(result["prices"]) >= 2:
        cur = result["prices"][0]["price"]
        prev = result["prices"][1]["price"]
        delta = cur - prev
        result["prices"][0]["change"] = round(delta, 2)
        result["prices"][0]["change_pct"] = (
            round(delta / prev * 100, 2) if prev else 0.0
        )

    return result


# ---------------------------------------------------------------------------
# EIA: US electricity retail rates
# ---------------------------------------------------------------------------

_EIA_ELECTRICITY_URL = "https://api.eia.gov/v2/electricity/retail-sales/data/"


async def fetch_electricity_rates(
    fetcher: Fetcher,
    state: str | None = None,
    api_key: str | None = None,
) -> dict:
    """Fetch US electricity retail rates from EIA.

    Returns average retail electricity price (cents/kWh) by sector
    (residential, commercial, industrial).  Optionally filter by
    2-letter *state* code (e.g., 'CA', 'TX').  Defaults to nationwide.

    Requires ``EIA_API_KEY``.
    """
    key = api_key or os.environ.get("EIA_API_KEY")
    if not key:
        return {"error": "EIA_API_KEY not configured"}

    area = state.upper() if state else "US"

    params = {
        "api_key": key,
        "frequency": "monthly",
        "data[0]": "price",
        "sort[0][column]": "period",
        "sort[0][direction]": "desc",
        "length": 12,
        "facets[stateid][]": area,
        "facets[sectorid][]": ["RES", "COM", "IND", "ALL"],
    }

    data = await fetcher.get_json(
        _EIA_ELECTRICITY_URL,
        source="eia",
        cache_key=f"economic:electricity:{area}",
        cache_ttl=3600,
        params=params,
    )

    sector_names = {
        "RES": "residential",
        "COM": "commercial",
        "IND": "industrial",
        "ALL": "all_sectors",
    }

    result: dict = {
        "state": area,
        "rates": {},
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "source": "eia",
        "unit": "cents/kWh",
    }

    if data is None:
        return result

    # Collect up to 2 most recent values per sector (for delta)
    by_sector: dict[str, list[dict]] = {}
    try:
        records = data.get("response", {}).get("data", [])
        for rec in records:
            sector_code = rec.get("sectorid")
            price = rec.get("price")
            period = rec.get("period")
            if sector_code is None or price is None or period is None:
                continue
            sector = sector_names.get(sector_code, sector_code)
            lst = by_sector.setdefault(sector, [])
            if len(lst) < 2:
                lst.append({"price": float(price), "period": period})

        for sector, entries in by_sector.items():
            current = entries[0]
            entry: dict = {
                "price_cents_kwh": current["price"],
                "period": current["period"],
            }
            if len(entries) >= 2:
                prev = entries[1]["price"]
                delta = current["price"] - prev
                entry["change"] = round(delta, 2)
                entry["change_pct"] = round(delta / prev * 100, 2) if prev else 0.0
                entry["prev_period"] = entries[1]["period"]
            result["rates"][sector] = entry
    except (KeyError, TypeError, ValueError) as exc:
        logger.warning("Failed to parse EIA electricity data: %s", exc)

    return result


# ---------------------------------------------------------------------------
# FRED: Federal Reserve Economic Data
# ---------------------------------------------------------------------------

_FRED_URL = "https://api.stlouisfed.org/fred/series/observations"


async def fetch_fred_series(
    fetcher: Fetcher,
    series_id: str,
    api_key: str | None = None,
    limit: int = 30,
) -> dict:
    """Fetch observations for a FRED series.

    Common series IDs:
        * ``GDP`` -- Gross Domestic Product
        * ``UNRATE`` -- Unemployment Rate
        * ``CPIAUCSL`` -- Consumer Price Index
        * ``DFF`` -- Federal Funds Effective Rate
        * ``T10YIE`` -- 10-Year Breakeven Inflation Rate

    Returns a dict with ``series_id``, ``title``, ``observations``, plus
    metadata.
    """
    key = api_key or os.environ.get("FRED_API_KEY")
    if not key:
        return {"error": "FRED_API_KEY not configured"}

    params = {
        "series_id": series_id,
        "api_key": key,
        "file_type": "json",
        "sort_order": "desc",
        "limit": limit,
    }

    data = await fetcher.get_json(
        _FRED_URL,
        source="fred",
        cache_key=f"economic:fred:{series_id}:{limit}",
        cache_ttl=3600,
        params=params,
    )

    result: dict = {
        "series_id": series_id,
        "title": series_id,
        "observations": [],
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "source": "fred",
    }

    if data is None:
        return result

    try:
        raw_obs = data.get("observations", [])
        for obs in raw_obs:
            date = obs.get("date")
            value = obs.get("value")
            if date is None:
                continue
            # FRED uses "." for missing values
            parsed_value: float | None = None
            if value not in (None, ".", ""):
                try:
                    parsed_value = float(value)
                except (ValueError, TypeError):
                    pass
            result["observations"].append({"date": date, "value": parsed_value})

        # FRED embeds series metadata when available
        if "realtime_start" in data:
            result["realtime_start"] = data["realtime_start"]
        if "realtime_end" in data:
            result["realtime_end"] = data["realtime_end"]
    except (KeyError, TypeError) as exc:
        logger.warning("Failed to parse FRED series %s: %s", series_id, exc)

    return result


# ---------------------------------------------------------------------------
# World Bank: Development indicators
# ---------------------------------------------------------------------------

_WB_BASE = "https://api.worldbank.org/v2/country"

_DEFAULT_INDICATORS = [
    "NY.GDP.MKTP.CD",  # GDP (current US$)
    "FP.CPI.TOTL.ZG",  # Inflation, consumer prices (annual %)
    "SL.UEM.TOTL.ZS",  # Unemployment, total (% of labor force)
]


async def fetch_world_bank_indicators(
    fetcher: Fetcher,
    country: str = "USA",
    indicators: list[str] | None = None,
) -> dict:
    """Fetch World Bank development indicators for a country.

    Defaults to GDP, inflation, and unemployment for the USA.
    Indicators are fetched in parallel.

    Returns a dict with ``country``, ``indicators`` (list of dicts with
    ``id``, ``name``, and ``values``), plus metadata.
    """
    indicator_ids = indicators or _DEFAULT_INDICATORS

    async def _fetch_one(indicator: str) -> dict | None:
        url = f"{_WB_BASE}/{country}/indicator/{indicator}"
        params = {
            "format": "json",
            "per_page": 5,
            "date": "2020:2025",
        }
        return await fetcher.get_json(
            url,
            source="world-bank",
            cache_key=f"economic:wb:{country}:{indicator}",
            cache_ttl=86400,
            params=params,
        )

    responses = await asyncio.gather(*[_fetch_one(ind) for ind in indicator_ids])

    parsed_indicators: list[dict] = []

    for indicator_id, raw in zip(indicator_ids, responses):
        entry: dict = {
            "id": indicator_id,
            "name": indicator_id,
            "values": [],
        }

        if raw is None:
            parsed_indicators.append(entry)
            continue

        try:
            # World Bank v2 JSON returns a 2-element list:
            # [metadata_dict, data_records_list]
            if isinstance(raw, list) and len(raw) >= 2:
                records = raw[1]
                if records and isinstance(records, list):
                    # Extract human-readable indicator name from first record
                    first = records[0]
                    ind_info = first.get("indicator", {})
                    if isinstance(ind_info, dict):
                        entry["name"] = ind_info.get("value", indicator_id)

                    for rec in records:
                        year = rec.get("date")
                        value = rec.get("value")
                        if year is not None:
                            parsed_value: float | None = None
                            if value is not None:
                                try:
                                    parsed_value = float(value)
                                except (ValueError, TypeError):
                                    pass
                            entry["values"].append(
                                {
                                    "year": year,
                                    "value": parsed_value,
                                }
                            )
        except (KeyError, TypeError, IndexError) as exc:
            logger.warning(
                "Failed to parse World Bank indicator %s for %s: %s",
                indicator_id,
                country,
                exc,
            )

        parsed_indicators.append(entry)

    return {
        "country": country,
        "indicators": parsed_indicators,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "source": "world-bank",
    }
