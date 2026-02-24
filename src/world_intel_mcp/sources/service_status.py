"""Cloud service status monitoring source for world-intel-mcp.

Monitors major cloud provider status pages (AWS, Azure, GCP, Cloudflare)
via their public RSS/Atom feeds. No API keys required.
"""

import asyncio
import logging
from datetime import datetime, timezone

from ..fetcher import Fetcher

try:
    import feedparser
except ImportError:
    feedparser = None  # type: ignore[assignment]

logger = logging.getLogger("world-intel-mcp.sources.service_status")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STATUS_FEEDS: list[dict] = [
    {
        "provider": "AWS",
        "url": "https://status.aws.amazon.com/rss/all.rss",
        "icon": "aws",
    },
    {
        "provider": "Azure",
        "url": "https://azurestatuscdn.azureedge.net/en-us/status/feed/",
        "icon": "azure",
    },
    {
        "provider": "GCP",
        "url": "https://status.cloud.google.com/feed.atom",
        "icon": "gcp",
    },
    {
        "provider": "Cloudflare",
        "url": "https://www.cloudflarestatus.com/history.rss",
        "icon": "cloudflare",
    },
    {
        "provider": "GitHub",
        "url": "https://www.githubstatus.com/history.rss",
        "icon": "github",
    },
]

_CACHE_TTL = 300  # 5 minutes

_SEVERITY_KEYWORDS: dict[str, str] = {
    "major": "critical",
    "outage": "critical",
    "disruption": "high",
    "degraded": "high",
    "degradation": "high",
    "elevated error": "high",
    "partial": "medium",
    "intermittent": "medium",
    "investigating": "medium",
    "resolved": "resolved",
    "monitoring": "low",
    "maintenance": "info",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_published(entry: dict) -> str | None:
    """Parse RSS entry published date to ISO 8601."""
    import time as _time

    for field in ("published_parsed", "updated_parsed"):
        parsed_tuple = entry.get(field)
        if parsed_tuple is not None:
            try:
                epoch = _time.mktime(parsed_tuple[:9])
                dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, TypeError, OverflowError):
                pass

    return entry.get("published") or entry.get("updated")


def _classify_severity(title: str, summary: str) -> str:
    """Classify incident severity from title and summary text."""
    combined = f"{title} {summary}".lower()
    for keyword, severity in _SEVERITY_KEYWORDS.items():
        if keyword in combined:
            return severity
    return "unknown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def fetch_service_status(
    fetcher: Fetcher,
    provider: str | None = None,
    limit: int = 30,
) -> dict:
    """Monitor cloud service provider status pages.

    Fetches RSS/Atom status feeds from AWS, Azure, GCP, Cloudflare,
    and GitHub. Classifies incidents by severity.

    Args:
        fetcher: Shared HTTP fetcher with caching and circuit breaking.
        provider: Optional provider filter (aws, azure, gcp, cloudflare, github).
        limit: Maximum incidents per provider.

    Returns:
        Dict with incidents, by_provider, active_incidents, source.
    """
    if feedparser is None:
        return {
            "error": "feedparser not installed — run: pip install feedparser",
            "incidents": [],
            "count": 0,
        }

    feeds = _STATUS_FEEDS
    if provider:
        provider_lower = provider.lower().strip()
        feeds = [f for f in feeds if f["provider"].lower() == provider_lower]
        if not feeds:
            return {
                "incidents": [],
                "count": 0,
                "error": f"Unknown provider '{provider}'. Valid: {[f['provider'] for f in _STATUS_FEEDS]}",
                "source": "service-status",
                "timestamp": _utc_now_iso(),
            }

    all_incidents: list[dict] = []

    async def _fetch_provider(feed: dict) -> list[dict]:
        safe_name = feed["provider"].lower()
        xml_text = await fetcher.get_xml(
            feed["url"],
            source=f"status:{safe_name}",
            cache_key=f"status:rss:{safe_name}",
            cache_ttl=_CACHE_TTL,
        )

        if xml_text is None:
            logger.debug("No data from %s status feed", feed["provider"])
            return []

        parsed = feedparser.parse(xml_text)
        incidents: list[dict] = []

        for entry in parsed.get("entries", [])[:limit]:
            title = entry.get("title", "")
            summary = entry.get("summary") or entry.get("description") or ""
            severity = _classify_severity(title, summary)

            incidents.append({
                "provider": feed["provider"],
                "title": title,
                "link": entry.get("link", ""),
                "published": _parse_published(entry),
                "summary": summary[:300] if len(summary) > 300 else summary,
                "severity": severity,
            })

        return incidents

    tasks = [_fetch_provider(f) for f in feeds]
    results = await asyncio.gather(*tasks)
    for incidents in results:
        all_incidents.extend(incidents)

    # Sort by published descending
    all_incidents.sort(key=lambda i: i.get("published") or "", reverse=True)

    # Count by provider
    by_provider: dict[str, int] = {}
    active_count = 0
    for inc in all_incidents:
        prov = inc.get("provider", "unknown")
        by_provider[prov] = by_provider.get(prov, 0) + 1
        if inc.get("severity") not in ("resolved", "info", "unknown"):
            active_count += 1

    return {
        "incidents": all_incidents,
        "count": len(all_incidents),
        "active_incidents": active_count,
        "by_provider": by_provider,
        "providers_checked": [f["provider"] for f in feeds],
        "source": "service-status",
        "timestamp": _utc_now_iso(),
    }
