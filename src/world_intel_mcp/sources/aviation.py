"""FAA airport delay data source for world-intel-mcp.

Provides real-time US airport delay information from the FAA Airport
Status Web Service (ASWS) API.  No API key required.
"""

import asyncio
import logging
from datetime import datetime, timezone

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.sources.aviation")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FAA_STATUS_URL = "https://soa.smext.faa.gov/asws/api/airport/status"

_MAJOR_AIRPORTS = [
    "ATL", "LAX", "ORD", "DFW", "DEN", "JFK", "SFO", "SEA", "LAS", "MCO",
    "EWR", "CLT", "PHX", "IAH", "MIA", "BOS", "MSP", "FLL", "DTW", "PHL",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_airport_status(code: str, data: dict) -> dict:
    """Extract structured fields from a single FAA airport status response."""
    name = data.get("Name", code)
    delay = data.get("Delay", False)

    # Normalize delay to boolean (API may return string "true"/"false")
    if isinstance(delay, str):
        delay = delay.lower() == "true"

    status_items = data.get("Status", [])
    if not isinstance(status_items, list):
        status_items = [status_items] if isinstance(status_items, dict) else []

    parsed_statuses = []
    for item in status_items:
        if not isinstance(item, dict):
            continue
        parsed_statuses.append({
            "type": item.get("Type", ""),
            "reason": item.get("Reason", ""),
            "avg_delay": item.get("AvgDelay", ""),
            "closure_begin": item.get("ClosureBegin", ""),
            "closure_end": item.get("ClosureEnd", ""),
        })

    return {
        "code": code,
        "name": name,
        "delay": delay,
        "status": parsed_statuses,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def fetch_airport_delays(fetcher: Fetcher) -> dict:
    """Fetch current US airport delays from the FAA Airport Status API.

    Queries the FAA ASWS API for each major US airport in parallel and
    returns a summary of which airports currently have active delays.

    Args:
        fetcher: Shared HTTP fetcher with caching and circuit breaking.

    Returns:
        Dict with delayed airports list, counts, source, and timestamp.
    """

    async def _fetch_one(code: str) -> tuple[str, dict | None]:
        """Fetch status for a single airport, returning (code, data|None)."""
        data = await fetcher.get_json(
            url=f"{_FAA_STATUS_URL}/{code}",
            source="faa",
            cache_key=f"aviation:faa:{code}",
            cache_ttl=300,
        )
        return code, data

    # Fetch all airports in parallel
    results = await asyncio.gather(
        *[_fetch_one(code) for code in _MAJOR_AIRPORTS],
        return_exceptions=True,
    )

    now_iso = _utc_now_iso()

    delayed: list[dict] = []
    all_airports: list[dict] = []
    errors = 0

    for result in results:
        if isinstance(result, Exception):
            logger.warning("Exception fetching airport status: %s", result)
            errors += 1
            continue

        code, data = result

        if data is None:
            logger.debug("No data returned for airport %s", code)
            errors += 1
            continue

        parsed = _parse_airport_status(code, data)
        all_airports.append(parsed)

        if parsed["delay"]:
            delayed.append(parsed)

    return {
        "delayed": delayed,
        "delayed_count": len(delayed),
        "total_checked": len(_MAJOR_AIRPORTS),
        "errors": errors,
        "source": "faa",
        "timestamp": now_iso,
    }
