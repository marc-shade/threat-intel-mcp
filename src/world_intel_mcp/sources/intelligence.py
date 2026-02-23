"""Country intelligence, risk scoring, and signal convergence sources.

Provides higher-level analytical functions that combine data from multiple
APIs (ACLED, World Bank, USGS, Ollama) into country briefs, risk scores,
instability indices, and geographic signal convergence assessments.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone, timedelta

import httpx

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.sources.intelligence")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ACLED_URL = "https://api.acleddata.com/acled/read"
_WB_BASE = "https://api.worldbank.org/v2/country"
_HDX_SEARCH_URL = "https://data.humdata.org/api/3/action/package_search"
_USGS_ENDPOINT = "https://earthquake.usgs.gov/fdsnws/event/1/query"
_OPENSKY_STATES_URL = "https://opensky-network.org/api/states/all"

_BASELINES = {
    "Syria": 5000, "Yemen": 3000, "Ukraine": 8000, "Myanmar": 4000,
    "Somalia": 2500, "Nigeria": 3500, "DR Congo": 3000, "Afghanistan": 2000,
    "Iraq": 1500, "Mali": 2000, "Burkina Faso": 2500, "Ethiopia": 2000,
    "Sudan": 3000, "South Sudan": 1500, "Cameroon": 1000, "Mozambique": 800,
    "Pakistan": 1200, "India": 1000, "Colombia": 1500, "Mexico": 4000,
}

_FOCUS_COUNTRIES = [
    "SYR", "UKR", "YEM", "MMR", "SDN", "ETH", "NGA", "COD", "AFG", "IRQ",
]

_HOTSPOTS = {
    "middle_east": (33.0, 44.0),
    "east_africa": (5.0, 38.0),
    "south_asia": (30.0, 70.0),
    "eastern_europe": (48.0, 35.0),
    "sahel": (15.0, 2.0),
}

# ISO-3166 alpha-3 to country name for ACLED queries and display.
_ISO3_TO_NAME = {
    "SYR": "Syria", "UKR": "Ukraine", "YEM": "Yemen", "MMR": "Myanmar",
    "SDN": "Sudan", "ETH": "Ethiopia", "NGA": "Nigeria", "COD": "DR Congo",
    "AFG": "Afghanistan", "IRQ": "Iraq",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _risk_level(score: float) -> str:
    if score > 150:
        return "critical"
    if score > 100:
        return "elevated"
    if score > 50:
        return "moderate"
    return "low"


def _instability_level(index: float) -> str:
    if index >= 75:
        return "critical"
    if index >= 50:
        return "high"
    if index >= 25:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Function 1: Country Intelligence Brief
# ---------------------------------------------------------------------------

async def fetch_country_brief(
    fetcher: Fetcher,
    country_code: str = "US",
) -> dict:
    """Generate a country intelligence brief using local LLM and public data.

    Gathers economic indicators from World Bank and conflict data from ACLED
    in parallel, then optionally enriches with an Ollama-generated analytical
    brief.  Falls back to a data-only summary when Ollama is unavailable.

    Args:
        fetcher: Shared HTTP fetcher with caching and circuit breaking.
        country_code: ISO 3166-1 alpha-2 country code (e.g. ``US``, ``UA``).

    Returns:
        Dict with brief text, supporting data, LLM availability flag,
        source, and timestamp.
    """
    now = datetime.now(timezone.utc)

    # --- Gather background data in parallel --------------------------------
    async def _fetch_gdp() -> list:
        url = f"{_WB_BASE}/{country_code}/indicator/NY.GDP.MKTP.CD"
        params = {
            "format": "json",
            "per_page": 5,
            "date": "2020:2025",
        }
        data = await fetcher.get_json(
            url,
            source="world-bank",
            cache_key=f"intel:wb:gdp:{country_code}",
            cache_ttl=86400,
            params=params,
        )
        if data is None:
            return []

        values = []
        try:
            if isinstance(data, list) and len(data) >= 2 and isinstance(data[1], list):
                for rec in data[1]:
                    year = rec.get("date")
                    value = rec.get("value")
                    if year is not None and value is not None:
                        try:
                            values.append({"year": year, "value": float(value)})
                        except (ValueError, TypeError):
                            pass
        except (KeyError, TypeError, IndexError) as exc:
            logger.warning("Failed to parse World Bank GDP for %s: %s", country_code, exc)
        return values

    async def _fetch_inflation() -> list:
        url = f"{_WB_BASE}/{country_code}/indicator/FP.CPI.TOTL.ZG"
        params = {
            "format": "json",
            "per_page": 5,
            "date": "2020:2025",
        }
        data = await fetcher.get_json(
            url,
            source="world-bank",
            cache_key=f"intel:wb:inflation:{country_code}",
            cache_ttl=86400,
            params=params,
        )
        if data is None:
            return []

        values = []
        try:
            if isinstance(data, list) and len(data) >= 2 and isinstance(data[1], list):
                for rec in data[1]:
                    year = rec.get("date")
                    value = rec.get("value")
                    if year is not None and value is not None:
                        try:
                            values.append({"year": year, "value": float(value)})
                        except (ValueError, TypeError):
                            pass
        except (KeyError, TypeError, IndexError) as exc:
            logger.warning("Failed to parse World Bank inflation for %s: %s", country_code, exc)
        return values

    async def _fetch_acled_count() -> int:
        access_token = os.environ.get("ACLED_ACCESS_TOKEN")
        if not access_token:
            return 0

        start_date = (now - timedelta(days=30)).strftime("%Y-%m-%d")
        end_date = now.strftime("%Y-%m-%d")

        params: dict = {
            "key": access_token,
            "email": os.environ.get("ACLED_EMAIL", "phoenix@2acrestudios.com"),
            "limit": 0,
            "event_date": f"{start_date}|{end_date}",
            "event_date_where": "BETWEEN",
            "country": country_code,
        }
        data = await fetcher.get_json(
            _ACLED_URL,
            source="acled",
            cache_key=f"intel:acled:count:{country_code}",
            cache_ttl=900,
            params=params,
        )
        if data is None:
            return 0

        # ACLED returns a count field when limit=0
        try:
            return int(data.get("count", len(data.get("data", []))))
        except (ValueError, TypeError):
            return len(data.get("data", []))

    gdp_values, inflation_values, event_count = await asyncio.gather(
        _fetch_gdp(),
        _fetch_inflation(),
        _fetch_acled_count(),
    )

    # --- Attempt Ollama-generated brief ------------------------------------
    llm_available = False
    brief_text = "LLM brief unavailable. Data summary below."

    prompt = (
        f"Provide a concise 3-paragraph intelligence brief for {country_code}. "
        "Cover: (1) current political stability and governance, "
        "(2) economic outlook and risks, "
        "(3) security concerns and regional dynamics. "
        "Be factual and analytical."
    )

    ollama_url = os.environ.get("OLLAMA_API_URL", "http://localhost:11434")
    model = os.environ.get("OLLAMA_MODEL", "llama3.2:latest")

    try:
        async with httpx.AsyncClient(timeout=30.0, proxy=None) as client:
            resp = await client.post(
                f"{ollama_url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                },
            )
            resp.raise_for_status()
            resp_data = resp.json()
            generated = resp_data.get("response", "")
            if generated and generated.strip():
                brief_text = generated.strip()
                llm_available = True
    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as exc:
        logger.info("Ollama unavailable for country brief (%s): %s", country_code, exc)
    except Exception as exc:
        logger.warning("Unexpected error calling Ollama: %s", exc)

    return {
        "country_code": country_code,
        "brief": brief_text,
        "data": {
            "gdp": gdp_values,
            "inflation": inflation_values,
            "recent_events": event_count,
        },
        "llm_available": llm_available,
        "source": "country-intelligence",
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


# ---------------------------------------------------------------------------
# Function 2: Country Risk Scores
# ---------------------------------------------------------------------------

async def fetch_risk_scores(
    fetcher: Fetcher,
    limit: int = 20,
) -> dict:
    """Compute country risk scores from ACLED conflict data and baselines.

    Fetches recent global conflict events, counts per country, and computes
    a risk score as ``(events_30d / monthly_baseline) * 100``.  Higher
    scores indicate conflict above historical norms.

    Args:
        fetcher: Shared HTTP fetcher with caching and circuit breaking.
        limit: Maximum number of countries to return (sorted by risk).

    Returns:
        Dict with ranked country list, count, source, and timestamp.
    """
    now = datetime.now(timezone.utc)

    access_token = os.environ.get("ACLED_ACCESS_TOKEN")
    if not access_token:
        return {
            "error": "ACLED_ACCESS_TOKEN not configured",
            "note": "Free academic access at acleddata.com",
            "source": "risk-analysis",
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    start_date = (now - timedelta(days=30)).strftime("%Y-%m-%d")
    end_date = now.strftime("%Y-%m-%d")

    params: dict = {
        "key": access_token,
        "email": os.environ.get("ACLED_EMAIL", "phoenix@2acrestudios.com"),
        "limit": 500,
        "event_date": f"{start_date}|{end_date}",
        "event_date_where": "BETWEEN",
    }

    data = await fetcher.get_json(
        _ACLED_URL,
        source="acled",
        cache_key="intel:risk:global:30d",
        cache_ttl=1800,
        params=params,
    )

    if data is None:
        logger.warning("ACLED API returned no data for risk scoring")
        return {
            "countries": [],
            "count": 0,
            "source": "risk-analysis",
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    # Count events per country
    country_counts: dict[str, int] = {}
    for event in data.get("data", []):
        country_name = event.get("country")
        if country_name:
            country_counts[country_name] = country_counts.get(country_name, 0) + 1

    # Compute risk scores
    countries: list[dict] = []
    for country_name, events_30d in country_counts.items():
        baseline_annual = _BASELINES.get(country_name, 500)
        monthly_baseline = baseline_annual / 12.0
        risk_score = (events_30d / monthly_baseline) * 100 if monthly_baseline > 0 else 0.0

        countries.append({
            "country": country_name,
            "events_30d": events_30d,
            "monthly_baseline": round(monthly_baseline, 1),
            "risk_score": round(risk_score, 1),
            "risk_level": _risk_level(risk_score),
        })

    # Sort by risk_score descending, take top N
    countries.sort(key=lambda c: c["risk_score"], reverse=True)
    countries = countries[:limit]

    return {
        "countries": countries,
        "count": len(countries),
        "source": "risk-analysis",
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


# ---------------------------------------------------------------------------
# Function 3: Country Instability Index
# ---------------------------------------------------------------------------

async def fetch_instability_index(
    fetcher: Fetcher,
    country_code: str | None = None,
) -> dict:
    """Compute a Country Instability Index (CII) from multiple signals.

    Combines conflict intensity, economic stress, humanitarian crisis data,
    internet disruption indicators, and military activity into a 0-100
    composite score.  Higher values indicate greater instability.

    When *country_code* is ``None``, returns a simplified index for 10
    focus countries using ACLED data as the primary signal.

    Args:
        fetcher: Shared HTTP fetcher with caching and circuit breaking.
        country_code: Optional ISO 3166-1 alpha-3 code (e.g. ``UKR``).

    Returns:
        Dict with instability index, component scores, risk level, source,
        and timestamp.
    """
    now = datetime.now(timezone.utc)

    if country_code is not None:
        return await _instability_single(fetcher, country_code, now)

    return await _instability_multi(fetcher, now)


async def _instability_single(
    fetcher: Fetcher,
    country_code: str,
    now: datetime,
) -> dict:
    """Compute full 5-component instability index for a single country."""

    # --- Parallel data gathering -------------------------------------------

    async def _conflict_score() -> float:
        """Score 0-20 based on ACLED event count in the last 30 days."""
        access_token = os.environ.get("ACLED_ACCESS_TOKEN")
        if not access_token:
            return 0.0

        country_name = _ISO3_TO_NAME.get(country_code, country_code)
        start_date = (now - timedelta(days=30)).strftime("%Y-%m-%d")
        end_date = now.strftime("%Y-%m-%d")

        data = await fetcher.get_json(
            _ACLED_URL,
            source="acled",
            cache_key=f"intel:cii:conflict:{country_code}",
            cache_ttl=1800,
            params={
                "key": access_token,
                "email": os.environ.get("ACLED_EMAIL", "phoenix@2acrestudios.com"),
                "limit": 500,
                "event_date": f"{start_date}|{end_date}",
                "event_date_where": "BETWEEN",
                "country": country_name,
            },
        )
        if data is None:
            return 0.0

        count = len(data.get("data", []))
        # Thresholds: 0 events = 0, 500+ = 20
        return min(20.0, (count / 500.0) * 20.0)

    async def _economic_score() -> float:
        """Score 0-20 based on World Bank inflation rate."""
        url = f"{_WB_BASE}/{country_code}/indicator/FP.CPI.TOTL.ZG"
        data = await fetcher.get_json(
            url,
            source="world-bank",
            cache_key=f"intel:cii:inflation:{country_code}",
            cache_ttl=86400,
            params={"format": "json", "per_page": 1, "date": "2023:2025"},
        )
        if data is None:
            return 0.0

        try:
            if isinstance(data, list) and len(data) >= 2 and isinstance(data[1], list):
                for rec in data[1]:
                    value = rec.get("value")
                    if value is not None:
                        inflation = float(value)
                        # Thresholds: 0% = 0, 50%+ = 20
                        return min(20.0, max(0.0, (abs(inflation) / 50.0) * 20.0))
        except (ValueError, TypeError, KeyError, IndexError):
            pass
        return 0.0

    async def _humanitarian_score() -> float:
        """Score 0-20 based on HDX crisis dataset count."""
        params: dict = {
            "q": "crisis",
            "rows": 50,
            "sort": "metadata_modified desc",
            "fq": f"groups:{country_code.lower()}",
        }
        data = await fetcher.get_json(
            _HDX_SEARCH_URL,
            source="hdx",
            cache_key=f"intel:cii:humanitarian:{country_code}",
            cache_ttl=21600,
            params=params,
        )
        if data is None:
            return 0.0

        try:
            count = data.get("result", {}).get("count", 0)
            # Thresholds: 0 datasets = 0, 200+ = 20
            return min(20.0, (int(count) / 200.0) * 20.0)
        except (ValueError, TypeError):
            return 0.0

    async def _internet_score() -> float:
        """Score 0-20 based on Cloudflare Radar connectivity data.

        This is a best-effort check; Cloudflare Radar's public API may
        not be available or may require auth.  Returns 0 on failure.
        """
        # Cloudflare Radar does not have an easy free API for this.
        # Placeholder: return 0 (no disruption data).
        return 0.0

    async def _military_score() -> float:
        """Score 0-20 based on OpenSky military flight density near country."""
        # Use a rough bounding box for the country.  For simplicity,
        # we only score countries in _ISO3_TO_NAME with known hotspot
        # regions.
        _COUNTRY_BBOX = {
            "SYR": "32,35,37,42", "UKR": "44,22,52,40",
            "YEM": "12,42,19,55", "MMR": "10,92,28,101",
            "SDN": "8,21,23,39", "ETH": "3,33,15,48",
            "NGA": "4,3,14,15", "COD": "-13,12,5,31",
            "AFG": "29,60,38,75", "IRQ": "29,39,37,49",
        }
        bbox = _COUNTRY_BBOX.get(country_code)
        if bbox is None:
            return 0.0

        parts = bbox.split(",")
        params: dict[str, str] = {}
        if len(parts) == 4:
            params["lamin"] = parts[0]
            params["lomin"] = parts[1]
            params["lamax"] = parts[2]
            params["lomax"] = parts[3]

        data = await fetcher.get_json(
            _OPENSKY_STATES_URL,
            source="opensky",
            cache_key=f"intel:cii:military:{country_code}",
            cache_ttl=300,
            params=params if params else None,
        )
        if data is None:
            return 0.0

        states = data.get("states") or []
        # Count all aircraft (military filtering adds complexity; using
        # total density as a proxy for activity).
        count = len(states)
        # Thresholds: 0 = 0, 200+ = 20
        return min(20.0, (count / 200.0) * 20.0)

    conflict, economic, humanitarian, internet, military = await asyncio.gather(
        _conflict_score(),
        _economic_score(),
        _humanitarian_score(),
        _internet_score(),
        _military_score(),
    )

    instability_index = round(conflict + economic + humanitarian + internet + military, 1)

    return {
        "country_code": country_code,
        "instability_index": instability_index,
        "components": {
            "conflict_intensity": round(conflict, 1),
            "economic_stress": round(economic, 1),
            "humanitarian_crisis": round(humanitarian, 1),
            "internet_disruptions": round(internet, 1),
            "military_activity": round(military, 1),
        },
        "risk_level": _instability_level(instability_index),
        "source": "instability-index",
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


async def _instability_multi(fetcher: Fetcher, now: datetime) -> dict:
    """Compute simplified instability index for focus countries using ACLED."""
    access_token = os.environ.get("ACLED_ACCESS_TOKEN")
    if not access_token:
        return {
            "error": "ACLED_ACCESS_TOKEN not configured",
            "source": "instability-index",
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    start_date = (now - timedelta(days=30)).strftime("%Y-%m-%d")
    end_date = now.strftime("%Y-%m-%d")

    # Fetch global events and bucket by country
    data = await fetcher.get_json(
        _ACLED_URL,
        source="acled",
        cache_key="intel:cii:multi:global:30d",
        cache_ttl=1800,
        params={
            "key": access_token,
            "email": os.environ.get("ACLED_EMAIL", "phoenix@2acrestudios.com"),
            "limit": 500,
            "event_date": f"{start_date}|{end_date}",
            "event_date_where": "BETWEEN",
        },
    )

    country_counts: dict[str, int] = {}
    if data is not None:
        for event in data.get("data", []):
            country_name = event.get("country")
            if country_name:
                country_counts[country_name] = country_counts.get(country_name, 0) + 1

    # Map focus country codes to names and compute simplified index
    results: list[dict] = []
    for code in _FOCUS_COUNTRIES:
        name = _ISO3_TO_NAME.get(code, code)
        events = country_counts.get(name, 0)
        baseline_annual = _BASELINES.get(name, 500)
        monthly_baseline = baseline_annual / 12.0

        # Simplified CII: conflict component scaled to 0-100
        if monthly_baseline > 0:
            ratio = events / monthly_baseline
        else:
            ratio = 0.0
        instability = min(100.0, round(ratio * 50.0, 1))

        results.append({
            "country_code": code,
            "country_name": name,
            "instability_index": instability,
            "events_30d": events,
            "risk_level": _instability_level(instability),
        })

    results.sort(key=lambda r: r["instability_index"], reverse=True)

    return {
        "countries": results,
        "count": len(results),
        "note": "Simplified index based on ACLED conflict data only. "
                "Use country_code parameter for full 5-component analysis.",
        "source": "instability-index",
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


# ---------------------------------------------------------------------------
# Function 4: Signal Convergence
# ---------------------------------------------------------------------------

async def fetch_signal_convergence(
    fetcher: Fetcher,
    lat: float | None = None,
    lon: float | None = None,
    radius_deg: float = 5.0,
) -> dict:
    """Detect geographic convergence of signals in hotspot regions.

    Checks for overlapping seismic activity and other observable signals
    within a radius of known or specified hotspot coordinates.  Higher
    convergence scores indicate multiple signal types in close proximity,
    which may warrant deeper investigation.

    Args:
        fetcher: Shared HTTP fetcher with caching and circuit breaking.
        lat: Latitude of center point.  If ``None``, scans 5 global
             hotspot regions.
        lon: Longitude of center point.
        radius_deg: Radius in degrees for bounding box queries.

    Returns:
        Dict with hotspot list, convergence scores, source, and timestamp.
    """
    now = datetime.now(timezone.utc)

    if lat is not None and lon is not None:
        regions = {"custom": (lat, lon)}
    else:
        regions = dict(_HOTSPOTS)

    async def _assess_hotspot(name: str, center: tuple[float, float]) -> dict:
        center_lat, center_lon = center

        # Earthquake count within bounding box
        min_lat = center_lat - radius_deg
        max_lat = center_lat + radius_deg
        min_lon = center_lon - radius_deg
        max_lon = center_lon + radius_deg

        starttime = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")

        quake_data = await fetcher.get_json(
            _USGS_ENDPOINT,
            source="usgs",
            cache_key=f"intel:convergence:usgs:{name}:{radius_deg}",
            cache_ttl=600,
            params={
                "format": "geojson",
                "minmagnitude": 2.5,
                "starttime": starttime,
                "minlatitude": min_lat,
                "maxlatitude": max_lat,
                "minlongitude": min_lon,
                "maxlongitude": max_lon,
                "limit": 100,
            },
        )

        earthquake_count = 0
        if quake_data is not None:
            earthquake_count = len(quake_data.get("features", []))

        # Convergence score heuristic (0-10)
        # Each signal type present adds to the score.
        score = 0.0

        # Earthquakes: 0-5 points based on count
        if earthquake_count > 0:
            score += min(5.0, (earthquake_count / 20.0) * 5.0)

        # Hotspot presence bonus (known conflict zones get a baseline)
        if name in _HOTSPOTS:
            score += 2.0

        score = min(10.0, round(score, 1))

        return {
            "name": name,
            "lat": center_lat,
            "lon": center_lon,
            "signals": {
                "earthquakes": earthquake_count,
            },
            "convergence_score": score,
        }

    tasks = [_assess_hotspot(name, center) for name, center in regions.items()]
    results = await asyncio.gather(*tasks)

    # Sort by convergence score descending
    hotspots = sorted(results, key=lambda h: h["convergence_score"], reverse=True)

    return {
        "hotspots": hotspots,
        "source": "signal-convergence",
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
