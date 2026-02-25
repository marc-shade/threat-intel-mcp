"""GitHub trending repositories source for world-intel-mcp.

Uses the GitHub search API (no auth required, 10 req/min rate limit).
Approximates "trending" by searching recently created repos with high stars.
"""

import logging
from datetime import datetime, timezone, timedelta

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.sources.github_trending")

_GH_SEARCH_URL = "https://api.github.com/search/repositories"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def fetch_trending_repos(
    fetcher: Fetcher,
    language: str | None = None,
    since_days: int = 7,
    limit: int = 25,
) -> dict:
    """Fetch trending GitHub repositories by recent star activity.

    Args:
        fetcher: Shared HTTP fetcher.
        language: Optional language filter (e.g., "python", "rust").
        since_days: Look back period in days (default 7).
        limit: Number of repos to return (max 50).

    Returns:
        Dict with repos[], count, source, timestamp.
    """
    limit = min(limit, 50)
    since_date = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%d")

    query = f"created:>{since_date} stars:>10"
    if language:
        query += f" language:{language}"

    data = await fetcher.get_json(
        _GH_SEARCH_URL,
        source="github",
        cache_key=f"github:trending:{language or 'all'}:{since_days}",
        cache_ttl=600,
        params={
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": str(limit),
        },
        headers={"Accept": "application/vnd.github.v3+json"},
    )

    if data is None or not isinstance(data, dict):
        return {"repos": [], "count": 0, "source": "github", "timestamp": _utc_now_iso()}

    repos = []
    for item in data.get("items", [])[:limit]:
        repos.append({
            "name": item.get("full_name"),
            "description": (item.get("description") or "")[:200],
            "url": item.get("html_url"),
            "stars": item.get("stargazers_count", 0),
            "forks": item.get("forks_count", 0),
            "language": item.get("language"),
            "created_at": item.get("created_at"),
            "topics": item.get("topics", [])[:5],
        })

    return {
        "repos": repos,
        "count": len(repos),
        "total_matching": data.get("total_count", 0),
        "query": query,
        "source": "github",
        "timestamp": _utc_now_iso(),
    }
