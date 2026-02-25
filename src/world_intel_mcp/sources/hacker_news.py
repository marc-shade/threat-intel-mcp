"""Hacker News top stories source for world-intel-mcp.

Uses the official HN Firebase API (no API key required).
"""

import asyncio
import logging
from datetime import datetime, timezone

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.sources.hacker_news")

_HN_TOP_URL = "https://hacker-news.firebaseio.com/v0/topstories.json"
_HN_ITEM_URL = "https://hacker-news.firebaseio.com/v0/item/{item_id}.json"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def fetch_hacker_news(
    fetcher: Fetcher,
    limit: int = 30,
) -> dict:
    """Fetch top Hacker News stories.

    Args:
        fetcher: Shared HTTP fetcher.
        limit: Number of top stories to return (max 50).

    Returns:
        Dict with stories[], count, source, timestamp.
    """
    limit = min(limit, 50)

    top_ids = await fetcher.get_json(
        _HN_TOP_URL,
        source="hackernews",
        cache_key="hn:top_ids",
        cache_ttl=300,
    )

    if top_ids is None or not isinstance(top_ids, list):
        return {"stories": [], "count": 0, "source": "hackernews", "timestamp": _utc_now_iso()}

    top_ids = top_ids[:limit]

    async def _fetch_item(item_id: int) -> dict | None:
        url = _HN_ITEM_URL.format(item_id=item_id)
        data = await fetcher.get_json(
            url,
            source="hackernews",
            cache_key=f"hn:item:{item_id}",
            cache_ttl=600,
        )
        if data is None or not isinstance(data, dict):
            return None
        return {
            "id": data.get("id"),
            "title": data.get("title", ""),
            "url": data.get("url", ""),
            "score": data.get("score", 0),
            "by": data.get("by", ""),
            "descendants": data.get("descendants", 0),
            "time": data.get("time"),
            "type": data.get("type", "story"),
        }

    tasks = [_fetch_item(item_id) for item_id in top_ids]
    results = await asyncio.gather(*tasks)

    stories = [s for s in results if s is not None]
    stories.sort(key=lambda s: s["score"], reverse=True)

    return {
        "stories": stories,
        "count": len(stories),
        "source": "hackernews",
        "timestamp": _utc_now_iso(),
    }
