"""Environmental events — NASA EONET and GDACS disaster alerts.

No API keys required. Public REST APIs.
"""

import logging
from datetime import datetime, timezone, timedelta

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.sources.environmental")

_EONET_EVENTS_URL = "https://eonet.gsfc.nasa.gov/api/v3/events"
_GDACS_EVENTS_URL = "https://www.gdacs.org/gdacsapi/api/events/geteventlist/SEARCH"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def fetch_environmental_events(
    fetcher: Fetcher,
    days: int = 30,
    category: str | None = None,
    limit: int = 50,
) -> dict:
    """Fetch active environmental events from NASA EONET.

    Categories: wildfires, severeStorms, volcanoes, seaLakeIce, earthquakes,
    floods, landslides, drought, dustHaze, snow, tempExtremes, waterColor,
    manmade.

    Args:
        fetcher: Shared HTTP fetcher.
        days: Lookback period in days.
        category: Optional category filter.
        limit: Max events to return.

    Returns:
        Dict with events[], count, source, timestamp.
    """
    params: dict[str, str] = {
        "days": str(days),
        "limit": str(min(limit, 100)),
        "status": "open",
    }
    if category:
        params["category"] = category

    data = await fetcher.get_json(
        _EONET_EVENTS_URL,
        source="eonet",
        cache_key=f"eonet:events:{days}:{category or 'all'}",
        cache_ttl=600,
        params=params,
    )

    if data is None or not isinstance(data, dict):
        return {"events": [], "count": 0, "source": "eonet", "timestamp": _utc_now_iso()}

    events = []
    for event in data.get("events", []):
        categories = [c.get("title", "") for c in event.get("categories", [])]

        # Get latest geometry point
        geometries = event.get("geometry", [])
        lat, lon = None, None
        if geometries:
            latest = geometries[-1]
            coords = latest.get("coordinates", [])
            if len(coords) >= 2:
                lon, lat = coords[0], coords[1]

        events.append({
            "id": event.get("id"),
            "title": event.get("title"),
            "categories": categories,
            "lat": lat,
            "lon": lon,
            "date": geometries[-1].get("date") if geometries else None,
            "sources": [s.get("url") for s in event.get("sources", [])],
            "closed": event.get("closed"),
        })

    return {
        "events": events[:limit],
        "count": len(events[:limit]),
        "source": "eonet",
        "timestamp": _utc_now_iso(),
    }


async def fetch_disaster_alerts(
    fetcher: Fetcher,
    alert_level: str | None = None,
    event_type: str | None = None,
    limit: int = 30,
) -> dict:
    """Fetch global disaster alerts from GDACS.

    Alert levels: Green, Orange, Red.
    Event types: EQ (earthquake), TC (tropical cyclone), FL (flood),
    VO (volcano), DR (drought), WF (wildfire).

    Args:
        fetcher: Shared HTTP fetcher.
        alert_level: Filter by alert level (Green, Orange, Red).
        event_type: Filter by event type code.
        limit: Max alerts to return.

    Returns:
        Dict with alerts[], count, source, timestamp.
    """
    # GDACS API returns GeoJSON
    params: dict[str, str] = {
        "fromDate": (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d"),
        "toDate": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "alertlevel": alert_level or "",
        "eventType": event_type or "",
    }
    # Remove empty params
    params = {k: v for k, v in params.items() if v}

    data = await fetcher.get_json(
        _GDACS_EVENTS_URL,
        source="gdacs",
        cache_key=f"gdacs:alerts:{alert_level or 'all'}:{event_type or 'all'}",
        cache_ttl=600,
        params=params,
    )

    if data is None or not isinstance(data, dict):
        return {"alerts": [], "count": 0, "source": "gdacs", "timestamp": _utc_now_iso()}

    alerts = []
    features = data.get("features", [])
    for feature in features[:limit]:
        props = feature.get("properties", {})
        geometry = feature.get("geometry", {})
        coords = geometry.get("coordinates", [])
        lat = coords[1] if len(coords) >= 2 else None
        lon = coords[0] if len(coords) >= 2 else None

        alerts.append({
            "event_id": props.get("eventid"),
            "event_type": props.get("eventtype"),
            "name": props.get("name") or props.get("eventname"),
            "alert_level": props.get("alertlevel"),
            "alert_score": props.get("alertscore"),
            "severity": props.get("severity", {}).get("severity_value") if isinstance(props.get("severity"), dict) else props.get("severity"),
            "country": props.get("country"),
            "lat": lat,
            "lon": lon,
            "from_date": props.get("fromdate"),
            "to_date": props.get("todate"),
            "url": props.get("url", {}).get("report") if isinstance(props.get("url"), dict) else None,
            "population_affected": props.get("population", {}).get("value") if isinstance(props.get("population"), dict) else None,
        })

    return {
        "alerts": alerts,
        "count": len(alerts),
        "source": "gdacs",
        "timestamp": _utc_now_iso(),
    }
