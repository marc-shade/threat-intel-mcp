"""USNI News Fleet and Marine Tracker source for world-intel-mcp.

Parses the USNI Fleet Tracker RSS feed for US Navy fleet disposition,
extracting carrier strike groups, ship deployments, and force posture.
No API key required — uses the public RSS category feed.
"""

import logging
import re
from datetime import datetime, timezone

from ..fetcher import Fetcher

try:
    import feedparser
except ImportError:
    feedparser = None  # type: ignore[assignment]

logger = logging.getLogger("world-intel-mcp.sources.usni_fleet")

_FEED_URL = "https://news.usni.org/category/fleet-tracker/feed"

# Regex patterns for extracting fleet data from article content
_SHIP_PATTERN = re.compile(
    r"USS\s+([\w\s.]+?)\s*\(((?:CVN|DDG|CG|LHD|LHA|LPD|LSD|SSN|SSBN|SSGN|FFG|MCM|PC|AS|ESB|ESD|EPF|AFSB|T-AO|T-AKE|T-ESB|WAGB|LCS)-?\d+)\)",
    re.IGNORECASE,
)
_USCG_PATTERN = re.compile(
    r"USCGC\s+([\w\s.]+?)\s*\((WAGB|WMSL|WPC|WPB|WLB)-?\d+\)",
    re.IGNORECASE,
)
_CSG_PATTERN = re.compile(
    r"Carrier Strike Group\s+(\d+|[A-Z]+)",
    re.IGNORECASE,
)
_ESG_PATTERN = re.compile(
    r"(?:Expeditionary Strike Group|Amphibious Ready Group)\s+(\d+|[A-Z]+)",
    re.IGNORECASE,
)
_BATTLE_FORCE_PATTERN = re.compile(
    r"(\d+)\s+ships?\s*\((\d+)\s+USS,\s*(\d+)\s+USNS\)",
    re.IGNORECASE,
)
_DEPLOYED_PATTERN = re.compile(
    r"(\d+)\s+deployed\s*\((\d+)\s+USS,\s*(\d+)\s+USNS\)",
    re.IGNORECASE,
)
_UNDERWAY_PATTERN = re.compile(
    r"(\d+)\s+underway\s*\((\d+)\s+deployed,\s*(\d+)\s+local\)",
    re.IGNORECASE,
)

# Region keywords for location classification
_REGION_KEYWORDS = {
    "Arabian Sea": "CENTCOM",
    "Persian Gulf": "CENTCOM",
    "Red Sea": "CENTCOM",
    "Gulf of Oman": "CENTCOM",
    "Gulf of Aden": "CENTCOM",
    "Mediterranean": "EUCOM",
    "Atlantic": "EUCOM",
    "North Sea": "EUCOM",
    "Baltic": "EUCOM",
    "Caribbean": "SOUTHCOM",
    "Pacific": "INDOPACOM",
    "Philippine Sea": "INDOPACOM",
    "South China Sea": "INDOPACOM",
    "East China Sea": "INDOPACOM",
    "Western Pacific": "INDOPACOM",
    "Japan": "INDOPACOM",
    "Yokosuka": "INDOPACOM",
    "Guam": "INDOPACOM",
    "Indian Ocean": "INDOPACOM",
    "Antarctica": "OTHER",
    "Arctic": "NORTHCOM",
    "San Diego": "HOMEPORT",
    "Norfolk": "HOMEPORT",
    "Mayport": "HOMEPORT",
    "Bremerton": "HOMEPORT",
}


def _classify_region(text: str) -> str:
    """Classify a text snippet into a combatant command region."""
    for keyword, region in _REGION_KEYWORDS.items():
        if keyword.lower() in text.lower():
            return region
    return "UNKNOWN"


def _extract_fleet_data(content: str) -> dict:
    """Extract structured fleet disposition from article HTML/text content."""
    ships = []
    strike_groups = []

    # Extract USS ships
    for match in _SHIP_PATTERN.finditer(content):
        name = match.group(1).strip()
        hull = match.group(2).strip()
        # Find surrounding context for region classification
        start = max(0, match.start() - 200)
        end = min(len(content), match.end() + 200)
        context = content[start:end]
        region = _classify_region(context)

        ship_type = hull.split("-")[0] if "-" in hull else hull[:3]
        type_labels = {
            "CVN": "Aircraft Carrier",
            "DDG": "Destroyer",
            "CG": "Cruiser",
            "LHD": "Amphibious Assault Ship",
            "LHA": "Amphibious Assault Ship",
            "LPD": "Amphibious Transport Dock",
            "LSD": "Dock Landing Ship",
            "SSN": "Attack Submarine",
            "SSBN": "Ballistic Missile Submarine",
            "SSGN": "Guided Missile Submarine",
            "FFG": "Frigate",
            "LCS": "Littoral Combat Ship",
            "MCM": "Mine Countermeasure",
            "ESB": "Expeditionary Sea Base",
            "ESD": "Expeditionary Transfer Dock",
            "EPF": "Expeditionary Fast Transport",
        }

        ships.append({
            "name": f"USS {name}",
            "hull_number": hull,
            "type": type_labels.get(ship_type, ship_type),
            "region": region,
        })

    # Extract USCG cutters
    for match in _USCG_PATTERN.finditer(content):
        name = match.group(1).strip()
        hull = match.group(2).strip()
        start = max(0, match.start() - 200)
        end = min(len(content), match.end() + 200)
        context = content[start:end]
        region = _classify_region(context)
        ships.append({
            "name": f"USCGC {name}",
            "hull_number": hull,
            "type": "Coast Guard Cutter",
            "region": region,
        })

    # Extract carrier strike groups
    for match in _CSG_PATTERN.finditer(content):
        strike_groups.append({"name": f"CSG-{match.group(1)}", "type": "Carrier Strike Group"})

    for match in _ESG_PATTERN.finditer(content):
        strike_groups.append({"name": f"ESG-{match.group(1)}", "type": "Expeditionary Strike Group"})

    # Extract force totals
    force_totals = {}
    bf = _BATTLE_FORCE_PATTERN.search(content)
    if bf:
        force_totals["battle_force"] = {
            "total": int(bf.group(1)),
            "uss": int(bf.group(2)),
            "usns": int(bf.group(3)),
        }
    dep = _DEPLOYED_PATTERN.search(content)
    if dep:
        force_totals["deployed"] = {
            "total": int(dep.group(1)),
            "uss": int(dep.group(2)),
            "usns": int(dep.group(3)),
        }
    uw = _UNDERWAY_PATTERN.search(content)
    if uw:
        force_totals["underway"] = {
            "total": int(uw.group(1)),
            "deployed": int(uw.group(2)),
            "local": int(uw.group(3)),
        }

    # Deduplicate ships by hull number
    seen_hulls: set[str] = set()
    unique_ships = []
    for ship in ships:
        if ship["hull_number"] not in seen_hulls:
            seen_hulls.add(ship["hull_number"])
            unique_ships.append(ship)

    # Region breakdown
    region_counts: dict[str, int] = {}
    for ship in unique_ships:
        r = ship["region"]
        region_counts[r] = region_counts.get(r, 0) + 1

    return {
        "ships": unique_ships,
        "ship_count": len(unique_ships),
        "strike_groups": strike_groups,
        "force_totals": force_totals,
        "region_breakdown": region_counts,
    }


async def fetch_usni_fleet(fetcher: Fetcher) -> dict:
    """Fetch latest USNI Fleet Tracker disposition.

    Parses the USNI News Fleet Tracker RSS feed for the most recent
    weekly fleet disposition report. Extracts ship names, hull numbers,
    strike groups, regions, and force totals.

    Returns:
        Dict with ships[], strike_groups[], force_totals, region_breakdown,
        report_date, report_url, source, timestamp.
    """
    if feedparser is None:
        return {
            "error": "feedparser not installed",
            "ships": [],
            "ship_count": 0,
            "source": "usni-fleet-tracker",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    xml = await fetcher.get_text(
        _FEED_URL,
        source="usni-fleet-tracker",
        cache_key="usni:fleet_tracker_rss",
        cache_ttl=3600,  # Weekly updates, cache for 1 hour
    )

    if not xml:
        return {
            "error": "failed to fetch USNI fleet tracker feed",
            "ships": [],
            "ship_count": 0,
            "source": "usni-fleet-tracker",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    feed = feedparser.parse(xml)

    if not feed.entries:
        return {
            "error": "no fleet tracker entries found",
            "ships": [],
            "ship_count": 0,
            "source": "usni-fleet-tracker",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # Get the most recent entry (fleet tracker article)
    entry = feed.entries[0]
    title = entry.get("title", "")
    link = entry.get("link", "")
    published = entry.get("published", "")

    # Try content:encoded first (full article), fall back to summary
    content = ""
    if hasattr(entry, "content") and entry.content:
        content = entry.content[0].get("value", "")
    if not content:
        content = entry.get("summary", entry.get("description", ""))

    # Strip HTML tags for cleaner regex matching
    clean_content = re.sub(r"<[^>]+>", " ", content)
    clean_content = re.sub(r"\s+", " ", clean_content)

    fleet_data = _extract_fleet_data(clean_content)

    return {
        **fleet_data,
        "report_title": title,
        "report_url": link,
        "report_date": published,
        "source": "usni-fleet-tracker",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
