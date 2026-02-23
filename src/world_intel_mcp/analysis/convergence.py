"""Geo-convergence detection for multi-domain signal overlap.

Detects when signals from different domains (conflict, natural disasters,
military activity) converge geographically, suggesting elevated risk.
"""

import logging
from collections import defaultdict
from math import floor

logger = logging.getLogger("world-intel-mcp.analysis.convergence")


def _grid_key(lat: float, lon: float, resolution: float = 1.0) -> tuple[int, int]:
    """Convert lat/lon to grid cell key."""
    return (int(floor(lat / resolution)), int(floor(lon / resolution)))


def detect_convergence(
    events: list[dict],
    resolution: float = 1.0,
    min_types: int = 2,
    min_total: int = 3,
) -> list[dict]:
    """Detect geographic convergence of multi-domain signals.

    Args:
        events: List of dicts with 'lat', 'lon', 'type' (domain), and optional 'weight'.
        resolution: Grid cell size in degrees.
        min_types: Minimum number of different signal types for convergence.
        min_total: Minimum total events in cell for convergence.

    Returns:
        List of convergence hotspots sorted by score descending.
    """
    grid: dict[tuple[int, int], list[dict]] = defaultdict(list)

    for event in events:
        lat = event.get("lat")
        lon = event.get("lon")
        if lat is None or lon is None:
            continue
        try:
            lat_f = float(lat)
            lon_f = float(lon)
        except (ValueError, TypeError):
            continue

        key = _grid_key(lat_f, lon_f, resolution)
        grid[key].append(event)

    hotspots = []
    for (grid_lat, grid_lon), cell_events in grid.items():
        if len(cell_events) < min_total:
            continue

        types = set()
        total_weight = 0.0
        for e in cell_events:
            types.add(e.get("type", "unknown"))
            total_weight += e.get("weight", 1.0)

        if len(types) < min_types:
            continue

        # Center of grid cell
        center_lat = (grid_lat + 0.5) * resolution
        center_lon = (grid_lon + 0.5) * resolution

        # Score: number of types * log of total events * weight
        score = len(types) * (1 + len(cell_events) ** 0.5) * (total_weight / len(cell_events))

        hotspots.append({
            "lat": round(center_lat, 2),
            "lon": round(center_lon, 2),
            "event_count": len(cell_events),
            "signal_types": sorted(types),
            "type_count": len(types),
            "total_weight": round(total_weight, 1),
            "convergence_score": round(score, 2),
        })

    hotspots.sort(key=lambda h: h["convergence_score"], reverse=True)
    return hotspots
