"""Climate anomaly data source for world-intel-mcp.

Provides temperature and precipitation anomaly monitoring across 15 global
climate zones using the Open-Meteo Archive API. No API key required.

Anomalies are computed by comparing the most recent 7-day period against
the same 7-day window from the previous year (baseline).
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.sources.climate")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ARCHIVE_URL = "https://archive-api.open-meteo.com/v1/archive"

CLIMATE_ZONES = {
    "arctic": {"lat": 80.0, "lon": 0.0, "name": "Arctic (Svalbard)"},
    "subarctic_siberia": {"lat": 65.0, "lon": 100.0, "name": "Subarctic Siberia"},
    "northern_europe": {"lat": 55.0, "lon": 15.0, "name": "Northern Europe"},
    "mediterranean": {"lat": 38.0, "lon": 20.0, "name": "Mediterranean Basin"},
    "sahel": {"lat": 14.0, "lon": 0.0, "name": "Sahel Region"},
    "middle_east": {"lat": 30.0, "lon": 45.0, "name": "Middle East"},
    "south_asia": {"lat": 25.0, "lon": 78.0, "name": "South Asia (India)"},
    "east_asia": {"lat": 35.0, "lon": 116.0, "name": "East Asia (Beijing)"},
    "southeast_asia": {"lat": 2.0, "lon": 105.0, "name": "Southeast Asia"},
    "australia": {"lat": -25.0, "lon": 135.0, "name": "Central Australia"},
    "amazon": {"lat": -3.0, "lon": -60.0, "name": "Amazon Basin"},
    "us_midwest": {"lat": 40.0, "lon": -90.0, "name": "US Midwest"},
    "us_southwest": {"lat": 33.0, "lon": -112.0, "name": "US Southwest"},
    "antarctica": {"lat": -75.0, "lon": 0.0, "name": "Antarctica"},
    "pacific_enso": {"lat": 0.0, "lon": -150.0, "name": "Pacific ENSO Region"},
}

_CACHE_TTL = 1800  # 30 minutes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_avg(values: list[float | None]) -> float:
    """Return mean of non-None numeric values, or 0.0 if empty."""
    clean = [v for v in values if v is not None]
    if not clean:
        return 0.0
    return sum(clean) / len(clean)


def _safe_sum(values: list[float | None]) -> float:
    """Return sum of non-None numeric values, or 0.0 if empty."""
    return sum(v for v in values if v is not None)


def _compute_anomalies(
    current_data: dict,
    baseline_data: dict,
) -> dict:
    """Compute temperature and precipitation anomalies between two periods.

    Returns dict with current/baseline averages and anomaly values.
    """
    cur_daily = current_data.get("daily", {})
    base_daily = baseline_data.get("daily", {})

    cur_max = cur_daily.get("temperature_2m_max", [])
    cur_min = cur_daily.get("temperature_2m_min", [])
    cur_precip = cur_daily.get("precipitation_sum", [])

    base_max = base_daily.get("temperature_2m_max", [])
    base_min = base_daily.get("temperature_2m_min", [])
    base_precip = base_daily.get("precipitation_sum", [])

    # Average temperature: mean of (daily_max + daily_min) / 2 across the period
    cur_temps = [
        (mx + mn) / 2
        for mx, mn in zip(cur_max, cur_min)
        if mx is not None and mn is not None
    ]
    base_temps = [
        (mx + mn) / 2
        for mx, mn in zip(base_max, base_min)
        if mx is not None and mn is not None
    ]

    current_avg_temp = _safe_avg(cur_temps)
    baseline_avg_temp = _safe_avg(base_temps)
    temp_anomaly = round(current_avg_temp - baseline_avg_temp, 2)

    # Precipitation totals
    current_precip_mm = round(_safe_sum(cur_precip), 2)
    baseline_precip_mm = round(_safe_sum(base_precip), 2)

    # Percentage anomaly (guard against near-zero baseline)
    precip_anomaly_pct = round(
        ((current_precip_mm - baseline_precip_mm)
         / max(baseline_precip_mm, 0.1))
        * 100,
        1,
    )

    # Significant anomaly flags
    is_significant = abs(temp_anomaly) > 3.0 or abs(precip_anomaly_pct) > 100

    return {
        "current_avg_temp_c": round(current_avg_temp, 2),
        "baseline_avg_temp_c": round(baseline_avg_temp, 2),
        "temp_anomaly_c": temp_anomaly,
        "current_precip_mm": current_precip_mm,
        "baseline_precip_mm": baseline_precip_mm,
        "precip_anomaly_pct": precip_anomaly_pct,
        "is_significant": is_significant,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def fetch_climate_anomalies(
    fetcher: Fetcher,
    zones: list[str] | None = None,
) -> dict:
    """Fetch temperature and precipitation anomalies for global climate zones.

    Compares the most recent 7-day window against the same dates from the
    previous year using the Open-Meteo Archive API. No API key required.

    Args:
        fetcher: Shared HTTP fetcher with caching and circuit breaking.
        zones: Optional list of zone keys to fetch. If None, all 15 zones
               are fetched in parallel.

    Returns:
        Dict with per-zone anomaly data, list of significant anomalies,
        source identifier, and ISO 8601 UTC timestamp.
    """
    now = datetime.now(timezone.utc)
    current_end = (now - timedelta(days=1)).strftime("%Y-%m-%d")
    current_start = (now - timedelta(days=7)).strftime("%Y-%m-%d")

    baseline_end_dt = now - timedelta(days=1) - timedelta(days=365)
    baseline_start_dt = now - timedelta(days=7) - timedelta(days=365)
    baseline_end = baseline_end_dt.strftime("%Y-%m-%d")
    baseline_start = baseline_start_dt.strftime("%Y-%m-%d")

    # Determine which zones to fetch
    if zones is not None:
        target_zones = {
            k: v for k, v in CLIMATE_ZONES.items() if k in zones
        }
        if not target_zones:
            logger.warning("No valid zone keys in %s", zones)
            return {
                "zones": {},
                "significant_anomalies": [],
                "source": "open-meteo",
                "timestamp": _utc_now_iso(),
            }
    else:
        target_zones = dict(CLIMATE_ZONES)

    async def _fetch_zone(zone_key: str, zone_info: dict) -> tuple[str, dict | None]:
        """Fetch current and baseline data for a single zone, compute anomalies."""
        lat = zone_info["lat"]
        lon = zone_info["lon"]

        common_params = {
            "latitude": lat,
            "longitude": lon,
            "daily": "temperature_2m_max,temperature_2m_min,precipitation_sum",
            "timezone": "UTC",
        }

        current_params = {
            **common_params,
            "start_date": current_start,
            "end_date": current_end,
        }
        baseline_params = {
            **common_params,
            "start_date": baseline_start,
            "end_date": baseline_end,
        }

        # Fetch current and baseline periods in parallel
        current_data, baseline_data = await asyncio.gather(
            fetcher.get_json(
                url=_ARCHIVE_URL,
                source="open-meteo",
                cache_key=f"climate:anomalies:{zone_key}:current",
                cache_ttl=_CACHE_TTL,
                params=current_params,
            ),
            fetcher.get_json(
                url=_ARCHIVE_URL,
                source="open-meteo",
                cache_key=f"climate:anomalies:{zone_key}:baseline",
                cache_ttl=_CACHE_TTL,
                params=baseline_params,
            ),
        )

        if current_data is None or baseline_data is None:
            logger.warning(
                "Open-Meteo returned no data for zone %s (current=%s, baseline=%s)",
                zone_key,
                current_data is not None,
                baseline_data is not None,
            )
            return (zone_key, None)

        anomalies = _compute_anomalies(current_data, baseline_data)

        return (zone_key, {
            "name": zone_info["name"],
            "lat": lat,
            "lon": lon,
            **anomalies,
        })

    # Fetch all target zones in parallel
    tasks = [
        _fetch_zone(zone_key, zone_info)
        for zone_key, zone_info in target_zones.items()
    ]
    results = await asyncio.gather(*tasks)

    # Assemble response
    zone_results: dict[str, dict] = {}
    significant_anomalies: list[str] = []

    for zone_key, zone_data in results:
        if zone_data is None:
            continue
        zone_results[zone_key] = zone_data
        if zone_data["is_significant"]:
            significant_anomalies.append(zone_key)

    response = {
        "zones": zone_results,
        "significant_anomalies": significant_anomalies,
        "source": "open-meteo",
        "timestamp": _utc_now_iso(),
    }

    # Cache composite result
    cache_label = "selected" if zones is not None else "all"
    fetcher.cache.set(
        f"climate:anomalies:{cache_label}",
        response,
        _CACHE_TTL,
    )

    return response
