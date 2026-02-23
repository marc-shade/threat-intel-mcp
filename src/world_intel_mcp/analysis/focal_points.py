"""Focal point detection — identifies entities where multiple signals converge.

Pure analysis module — no I/O.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone


def detect_focal_points(
    events: list[dict],
    min_signals: int = 2,
    max_age_hours: float = 48.0,
) -> list[dict]:
    """Group events by entity, score convergence, assign urgency.

    Args:
        events: List of dicts, each with at least ``entity`` and ``type`` keys.
            Optional keys: ``timestamp``, ``country``, ``lat``, ``lon``, ``weight``.
        min_signals: Minimum number of events for an entity to qualify.
        max_age_hours: Discard events older than this (hours from now).

    Returns:
        List of focal point dicts sorted by focal_score descending. Each contains:
        entity, signal_count, signal_types, urgency, focal_score, countries, recent_events.
    """
    now = datetime.now(timezone.utc)
    grouped: dict[str, list[dict]] = defaultdict(list)

    for event in events:
        entity = event.get("entity")
        if not entity:
            continue

        # Parse timestamp and filter by age
        ts_raw = event.get("timestamp")
        hours_old = 0.0
        if ts_raw:
            try:
                if isinstance(ts_raw, str):
                    # Handle ISO format with or without timezone
                    ts_str = ts_raw.replace("Z", "+00:00")
                    ts = datetime.fromisoformat(ts_str)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                elif isinstance(ts_raw, datetime):
                    ts = ts_raw if ts_raw.tzinfo else ts_raw.replace(tzinfo=timezone.utc)
                else:
                    ts = now
                hours_old = (now - ts).total_seconds() / 3600.0
            except (ValueError, TypeError):
                hours_old = 0.0

        if hours_old > max_age_hours:
            continue

        normalized = entity.strip().lower()
        grouped[normalized].append({**event, "_hours_old": hours_old})

    focal_points: list[dict] = []

    for entity_key, entity_events in grouped.items():
        signal_count = len(entity_events)
        if signal_count < min_signals:
            continue

        # Unique signal types
        unique_types = set()
        countries: set[str] = set()
        for ev in entity_events:
            t = ev.get("type")
            if t:
                unique_types.add(t)
            c = ev.get("country")
            if c:
                countries.add(c)

        type_diversity = len(unique_types)

        # Recency weighting: more recent events contribute more
        recency_weights = []
        for ev in entity_events:
            h = ev.get("_hours_old", 0.0)
            recency_weights.append(1.0 / max(1.0, h))
        recency_weight = sum(recency_weights) / signal_count if signal_count else 0.0

        # Focal score
        focal_score = signal_count * (1 + type_diversity * 0.5) * recency_weight

        # Urgency level
        if signal_count >= 10:
            urgency = "critical"
        elif signal_count >= 5:
            urgency = "elevated"
        else:
            urgency = "watch"

        # Recent events (strip internal fields, limit to 10)
        recent = []
        for ev in sorted(entity_events, key=lambda e: e.get("_hours_old", 0))[:10]:
            clean = {k: v for k, v in ev.items() if not k.startswith("_")}
            recent.append(clean)

        # Use the original casing from the first event
        display_entity = entity_events[0].get("entity", entity_key)

        focal_points.append({
            "entity": display_entity,
            "signal_count": signal_count,
            "signal_types": sorted(unique_types),
            "urgency": urgency,
            "focal_score": round(focal_score, 2),
            "countries": sorted(countries),
            "recent_events": recent,
        })

    focal_points.sort(key=lambda fp: fp["focal_score"], reverse=True)
    return focal_points
