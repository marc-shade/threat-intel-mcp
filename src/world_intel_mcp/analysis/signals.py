"""Signal aggregation per country.

Collects and normalizes signals from multiple domains into
a per-country summary for dashboard and reporting.

v2 adds fire, outage, military, and protest integration plus
convergence scoring.
"""

import logging
from collections import defaultdict

logger = logging.getLogger("world-intel-mcp.analysis.signals")

# Approximate region-to-country mapping for wildfire data
_FIRE_REGION_COUNTRIES: dict[str, list[str]] = {
    "north_america": ["United States", "Canada", "Mexico"],
    "south_america": ["Brazil", "Argentina", "Colombia", "Chile"],
    "europe": ["Greece", "Spain", "Portugal", "Italy", "France"],
    "africa": ["Nigeria", "DR Congo", "Ethiopia", "Sudan"],
    "middle_east": ["Syria", "Iraq", "Iran", "Yemen"],
    "south_asia": ["India", "Pakistan", "Afghanistan"],
    "east_asia": ["China", "Japan", "South Korea"],
    "southeast_asia": ["Myanmar", "Indonesia", "Philippines"],
    "oceania": ["Australia", "New Zealand"],
}


def aggregate_country_signals(
    conflict_events: list[dict] | None = None,
    displacement_data: list[dict] | None = None,
    earthquake_data: list[dict] | None = None,
    fire_data: list[dict] | None = None,
    outage_data: list[dict] | None = None,
    military_data: list[dict] | None = None,
    protest_data: list[dict] | None = None,
) -> dict[str, dict]:
    """Aggregate multi-domain signals by country.

    Args:
        conflict_events: ACLED/UCDP events with 'country' field.
        displacement_data: UNHCR data with 'country' field.
        earthquake_data: USGS earthquakes (uses reverse geocoding heuristic).
        fire_data: Wildfire data as list of dicts with optional 'country' or 'region' field.
        outage_data: Internet outages with 'countries' field (list of country codes).
        military_data: Military aircraft data with 'origin_country' field.
        protest_data: ACLED protests/riots subset with 'country' field.

    Returns:
        Dict mapping country name to signal summary with convergence scoring.
    """
    countries: dict[str, dict] = defaultdict(lambda: {
        "conflict_events": 0,
        "fatalities": 0,
        "displaced_persons": 0,
        "earthquakes": 0,
        "max_earthquake_mag": 0.0,
        "fires": 0,
        "outages": 0,
        "military_aircraft": 0,
        "protests": 0,
        "riots": 0,
        "domains": set(),
        "high_severity_count": 0,
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
                if int(fat) > 10:
                    c["high_severity_count"] += 1
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
                if int(total) > 100_000:
                    c["high_severity_count"] += 1
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
            if isinstance(mag, (int, float)):
                if mag > c["max_earthquake_mag"]:
                    c["max_earthquake_mag"] = float(mag)
                if mag >= 6.0:
                    c["high_severity_count"] += 1
            c["domains"].add("seismology")

    # Fire data
    if fire_data:
        for fire in fire_data:
            if not isinstance(fire, dict):
                continue
            country = fire.get("country")
            region = fire.get("region")
            if country:
                c = countries[country]
                c["fires"] += 1
                c["domains"].add("wildfire")
            elif region and region in _FIRE_REGION_COUNTRIES:
                # Distribute fire to first mapped country as approximation
                mapped = _FIRE_REGION_COUNTRIES[region][0]
                c = countries[mapped]
                c["fires"] += 1
                c["domains"].add("wildfire")

    # Internet outages
    if outage_data:
        for outage in outage_data:
            if not isinstance(outage, dict):
                continue
            outage_countries = outage.get("countries", [])
            if isinstance(outage_countries, str):
                outage_countries = [outage_countries]
            for oc in outage_countries:
                if oc:
                    c = countries[oc]
                    c["outages"] += 1
                    c["domains"].add("infrastructure")

    # Military flights
    if military_data:
        for aircraft in military_data:
            if not isinstance(aircraft, dict):
                continue
            country = aircraft.get("origin_country")
            if country:
                c = countries[country]
                c["military_aircraft"] += 1
                c["domains"].add("military")

    # Protests and riots
    if protest_data:
        for event in protest_data:
            if not isinstance(event, dict):
                continue
            country = event.get("country")
            if not country:
                continue
            c = countries[country]
            event_type = (event.get("event_type") or "").lower()
            if "riot" in event_type:
                c["riots"] += 1
            else:
                c["protests"] += 1
            c["domains"].add("unrest")

    # Compute signal counts and convergence scoring
    result = {}
    for country, data in countries.items():
        domains = data.pop("domains")
        unique_domains = len(domains)
        total_signal_count = (
            data["conflict_events"]
            + data["earthquakes"]
            + data["fires"]
            + data["outages"]
            + data["military_aircraft"]
            + data["protests"]
            + data["riots"]
        )
        high_severity = data.pop("high_severity_count")

        # Convergence scoring
        type_bonus = 20 * unique_domains
        count_bonus = min(30, 5 * total_signal_count)
        severity_bonus = 10 * high_severity
        convergence_score = type_bonus + count_bonus + severity_bonus

        data["signal_count"] = unique_domains
        data["total_signals"] = total_signal_count
        data["active_domains"] = sorted(domains)
        data["convergence_score"] = convergence_score
        result[country] = data

    # Sort by convergence score, then signal count
    result = dict(sorted(
        result.items(),
        key=lambda x: (x[1]["convergence_score"], x[1]["signal_count"]),
        reverse=True,
    ))

    return result
