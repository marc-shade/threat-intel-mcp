"""Static geospatial dataset queries for world-intel-mcp.

Pure data lookups — no network I/O. Uses config/geospatial.py datasets.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..config.geospatial import (
    MILITARY_BASES,
    STRATEGIC_PORTS,
    PIPELINES,
    NUCLEAR_FACILITIES,
    query_bases,
    query_ports,
    query_pipelines,
    query_nuclear,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Public API — each returns dict matching MCP tool output shape
# ---------------------------------------------------------------------------

async def fetch_military_bases(
    operator: str | None = None,
    country: str | None = None,
    base_type: str | None = None,
    branch: str | None = None,
) -> dict:
    """Query military bases worldwide.

    Args:
        operator: Filter by operating country (USA, RUS, CHN, GBR, FRA, etc.)
        country: Filter by host country name or ISO-3 code.
        base_type: Filter by type (air_base, naval_base, army_base, etc.)
        branch: Filter by branch (USAF, US Navy, PLA Navy, etc.)

    Returns:
        Dict with bases[], count, by_operator{}, by_type{}, source, timestamp.
    """
    bases = query_bases(operator=operator, country=country, base_type=base_type, branch=branch)

    by_operator: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for b in bases:
        by_operator[b["operator"]] = by_operator.get(b["operator"], 0) + 1
        by_type[b["type"]] = by_type.get(b["type"], 0) + 1

    return {
        "bases": bases,
        "count": len(bases),
        "total_in_database": len(MILITARY_BASES),
        "by_operator": by_operator,
        "by_type": by_type,
        "filters": {
            "operator": operator,
            "country": country,
            "base_type": base_type,
            "branch": branch,
        },
        "source": "static-geospatial",
        "timestamp": _utc_now_iso(),
    }


async def fetch_strategic_ports(
    port_type: str | None = None,
    country: str | None = None,
) -> dict:
    """Query strategic ports worldwide.

    Args:
        port_type: Filter by type (container, oil, lng, naval, bulk, mixed).
        country: Filter by country name or ISO-3 code.

    Returns:
        Dict with ports[], count, by_type{}, source, timestamp.
    """
    ports = query_ports(port_type=port_type, country=country)

    by_type: dict[str, int] = {}
    for p in ports:
        by_type[p["type"]] = by_type.get(p["type"], 0) + 1

    return {
        "ports": ports,
        "count": len(ports),
        "total_in_database": len(STRATEGIC_PORTS),
        "by_type": by_type,
        "filters": {"port_type": port_type, "country": country},
        "source": "static-geospatial",
        "timestamp": _utc_now_iso(),
    }


async def fetch_pipelines(
    pipeline_type: str | None = None,
    status: str | None = None,
) -> dict:
    """Query oil, gas, and hydrogen pipelines.

    Args:
        pipeline_type: Filter by type (oil, gas, hydrogen).
        status: Filter by status (active, destroyed, proposed, etc.)

    Returns:
        Dict with pipelines[], count, by_type{}, by_status{}, source, timestamp.
    """
    pipes = query_pipelines(pipeline_type=pipeline_type, status=status)

    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for p in pipes:
        by_type[p["type"]] = by_type.get(p["type"], 0) + 1
        by_status[p["status"]] = by_status.get(p["status"], 0) + 1

    return {
        "pipelines": pipes,
        "count": len(pipes),
        "total_in_database": len(PIPELINES),
        "by_type": by_type,
        "by_status": by_status,
        "filters": {"pipeline_type": pipeline_type, "status": status},
        "source": "static-geospatial",
        "timestamp": _utc_now_iso(),
    }


async def fetch_nuclear_facilities(
    facility_type: str | None = None,
    country: str | None = None,
    status: str | None = None,
) -> dict:
    """Query nuclear power plants, enrichment sites, and research reactors.

    Args:
        facility_type: Filter by type (power, enrichment, research, reprocessing, decommissioned).
        country: Filter by country name or ISO-3 code.
        status: Filter by status (operational, construction, shutdown, etc.)

    Returns:
        Dict with facilities[], count, total_capacity_mw, by_type{}, by_status{}, source, timestamp.
    """
    facilities = query_nuclear(facility_type=facility_type, country=country, status=status)

    total_cap = sum(f.get("capacity_mw", 0) for f in facilities)
    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for f in facilities:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
        by_status[f["status"]] = by_status.get(f["status"], 0) + 1

    return {
        "facilities": facilities,
        "count": len(facilities),
        "total_in_database": len(NUCLEAR_FACILITIES),
        "total_capacity_mw": total_cap,
        "by_type": by_type,
        "by_status": by_status,
        "filters": {"facility_type": facility_type, "country": country, "status": status},
        "source": "static-geospatial",
        "timestamp": _utc_now_iso(),
    }
