"""NGA Maritime Safety Information source for world-intel-mcp.

Provides navigational warnings from the National Geospatial-Intelligence Agency
(NGA) Maritime Safety Information (MSI) broadcast warnings API.
No API key required.
"""

import logging
import os
import re
from datetime import datetime, timezone

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.sources.maritime")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_NGA_WARNINGS_URL = "https://msi.nga.mil/api/publications/broadcast-warn?output=json"

NAVAREAS = {
    "I": "UK (NE Atlantic, North Sea)",
    "II": "France (Bay of Biscay, W Africa)",
    "III": "Spain (Mediterranean W)",
    "IV": "United States (W Atlantic, Caribbean, Gulf of Mexico)",
    "V": "Brazil (SW Atlantic)",
    "VI": "Argentina (SE Atlantic)",
    "VII": "South Africa (Indian Ocean W)",
    "VIII": "India (Indian Ocean N)",
    "IX": "Pakistan (Arabian Sea, Persian Gulf)",
    "X": "Australia (Indian Ocean S)",
    "XI": "Japan (NW Pacific)",
    "XII": "United States (NE Pacific)",
    "XIII": "Russia (Arctic)",
    "XIV": "New Zealand (SW Pacific)",
    "XV": "Chile (SE Pacific)",
    "XVI": "Peru (E Pacific)",
}

_MAX_TEXT_LENGTH = 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_active(warning: dict) -> bool:
    """Return True if the warning has no cancelDate (i.e. still active)."""
    cancel = warning.get("cancelDate")
    return cancel is None or cancel == ""


def _parse_warning(warning: dict) -> dict:
    """Extract structured fields from a single NGA broadcast warning."""
    msg_year = warning.get("msgYear", "")
    msg_number = warning.get("msgNumber", "")
    warning_id = f"{msg_year}-{msg_number}" if msg_year and msg_number else None

    cancel_date = warning.get("cancelDate")
    status = "cancelled" if cancel_date else "active"

    text = warning.get("text", "") or ""
    if len(text) > _MAX_TEXT_LENGTH:
        text = text[:_MAX_TEXT_LENGTH] + "..."

    return {
        "id": warning_id,
        "navarea": warning.get("navArea", ""),
        "subregion": warning.get("subregion", ""),
        "status": status,
        "issue_date": warning.get("issueDate"),
        "cancel_date": cancel_date if cancel_date else None,
        "text": text,
        "authority": warning.get("authority", "NGA"),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def fetch_nav_warnings(
    fetcher: Fetcher,
    navarea: str | None = None,
) -> dict:
    """Fetch active navigational warnings from NGA Maritime Safety Information.

    Args:
        fetcher: Shared HTTP fetcher with caching and circuit breaking.
        navarea: Optional NAVAREA identifier (e.g. "IV", "XII") to filter by.

    Returns:
        Dict with warnings list, count, per-navarea breakdown, NAVAREA
        definitions, source, and timestamp.
    """
    cache_label = navarea.upper() if navarea else "all"
    cache_key = f"maritime:warnings:{cache_label}"

    data = await fetcher.get_json(
        url=_NGA_WARNINGS_URL,
        source="nga-msi",
        cache_key=cache_key,
        cache_ttl=3600,
    )

    now_iso = _utc_now_iso()

    if data is None:
        logger.warning("NGA MSI API returned no data")
        return {
            "warnings": [],
            "count": 0,
            "by_navarea": {},
            "navareas": NAVAREAS,
            "source": "nga-msi",
            "timestamp": now_iso,
        }

    # The API returns either a list directly or a dict with a data key
    if isinstance(data, list):
        raw_warnings = data
    elif isinstance(data, dict):
        raw_warnings = data.get("broadcast-warn", data.get("data", []))
        if isinstance(raw_warnings, dict):
            raw_warnings = [raw_warnings]
    else:
        raw_warnings = []

    # Filter to active warnings only
    active_raw = [w for w in raw_warnings if _is_active(w)]

    # Filter by NAVAREA if specified
    if navarea is not None:
        navarea_upper = navarea.upper()
        active_raw = [
            w for w in active_raw
            if str(w.get("navArea", "")).upper() == navarea_upper
        ]

    # Parse each warning into structured format
    warnings = [_parse_warning(w) for w in active_raw]

    # Sort by issue date descending (most recent first)
    def _issue_sort_key(w: dict) -> str:
        return w.get("issue_date") or ""

    warnings.sort(key=_issue_sort_key, reverse=True)

    # Summary stats: count per navarea
    by_navarea: dict[str, int] = {}
    for w in warnings:
        na = w.get("navarea", "UNKNOWN")
        by_navarea[na] = by_navarea.get(na, 0) + 1

    return {
        "warnings": warnings,
        "count": len(warnings),
        "by_navarea": by_navarea,
        "navareas": NAVAREAS,
        "source": "nga-msi",
        "timestamp": now_iso,
    }
