"""Signal aggregation per country.

Collects and normalizes signals from multiple domains into
a per-country summary for dashboard and reporting.
"""

import logging
from collections import defaultdict

logger = logging.getLogger("world-intel-mcp.analysis.signals")


def aggregate_country_signals(
    conflict_events: list[dict] | None = None,
    displacement_data: list[dict] | None = None,
    earthquake_data: list[dict] | None = None,
    fire_data: dict | None = None,
) -> dict[str, dict]:
    """Aggregate multi-domain signals by country.

    Args:
        conflict_events: ACLED/UCDP events with 'country' field.
        displacement_data: UNHCR data with 'country' field.
        earthquake_data: USGS earthquakes (uses reverse geocoding heuristic).
        fire_data: Wildfire data by region (maps to countries approximately).

    Returns:
        Dict mapping country name to signal summary.
    """
    countries: dict[str, dict] = defaultdict(lambda: {
        "conflict_events": 0,
        "fatalities": 0,
        "displaced_persons": 0,
        "earthquakes": 0,
        "max_earthquake_mag": 0.0,
        "fires": 0,
        "signal_count": 0,
        "domains": set(),
    })

    # Conflict events
    if conflict_events:
        for event in conflict_events:
            country = event.get("country")
            if not country:
                continue
            c = countries[country]
            c["conflict_events"] += 1
            fat = event.get("fatalities", 0)
            if isinstance(fat, (int, float)):
                c["fatalities"] += int(fat)
            c["domains"].add("conflict")

    # Displacement
    if displacement_data:
        for record in displacement_data:
            country = record.get("country")
            if not country:
                continue
            c = countries[country]
            total = record.get("total_displaced", 0)
            if isinstance(total, (int, float)):
                c["displaced_persons"] += int(total)
            c["domains"].add("displacement")

    # Earthquakes (approximate country from place string)
    if earthquake_data:
        for quake in earthquake_data:
            place = quake.get("place", "") or ""
            # USGS format: "123km SSE of City, Country"
            parts = place.rsplit(", ", 1)
            country = parts[-1] if len(parts) > 1 else "Unknown"
            c = countries[country]
            c["earthquakes"] += 1
            mag = quake.get("magnitude", 0) or 0
            if isinstance(mag, (int, float)) and mag > c["max_earthquake_mag"]:
                c["max_earthquake_mag"] = float(mag)
            c["domains"].add("seismology")

    # TODO: fire_data integration (requires region-to-country mapping)
    _ = fire_data

    # Compute signal counts
    result = {}
    for country, data in countries.items():
        domains = data.pop("domains")
        data["signal_count"] = len(domains)
        data["active_domains"] = sorted(domains)
        result[country] = data

    # Sort by signal count, then fatalities
    result = dict(sorted(
        result.items(),
        key=lambda x: (x[1]["signal_count"], x[1]["fatalities"]),
        reverse=True,
    ))

    return result
