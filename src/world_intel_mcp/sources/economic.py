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
            records = (
                oil_data.get("response", {}).get("data", [])
            )
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
            records = (
                gas_data.get("response", {}).get("data", [])
            )
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
    "NY.GDP.MKTP.CD",   # GDP (current US$)
    "FP.CPI.TOTL.ZG",   # Inflation, consumer prices (annual %)
    "SL.UEM.TOTL.ZS",   # Unemployment, total (% of labor force)
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

    responses = await asyncio.gather(
        *[_fetch_one(ind) for ind in indicator_ids]
    )

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
                            entry["values"].append({
                                "year": year,
                                "value": parsed_value,
                            })
        except (KeyError, TypeError, IndexError) as exc:
            logger.warning(
                "Failed to parse World Bank indicator %s for %s: %s",
                indicator_id, country, exc,
            )

        parsed_indicators.append(entry)

    return {
        "country": country,
        "indicators": parsed_indicators,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "source": "world-bank",
    }
