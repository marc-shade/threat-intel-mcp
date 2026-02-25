"""arXiv recent papers source for world-intel-mcp.

Uses the arXiv API (no key required, rate limit ~3 req/s).
"""

import logging
import re
from datetime import datetime, timezone

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.sources.arxiv_papers")

_ARXIV_API_URL = "http://export.arxiv.org/api/query"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_arxiv_xml(xml_text: str) -> list[dict]:
    """Parse arXiv Atom XML response into paper dicts.

    Simple regex-based parsing to avoid lxml dependency.
    """
    papers = []
    entries = re.findall(r"<entry>(.*?)</entry>", xml_text, re.DOTALL)

    for entry in entries:
        title_match = re.search(r"<title>(.*?)</title>", entry, re.DOTALL)
        summary_match = re.search(r"<summary>(.*?)</summary>", entry, re.DOTALL)
        id_match = re.search(r"<id>(.*?)</id>", entry)
        published_match = re.search(r"<published>(.*?)</published>", entry)
        updated_match = re.search(r"<updated>(.*?)</updated>", entry)

        # Extract authors
        authors = re.findall(r"<author>\s*<name>(.*?)</name>", entry)

        # Extract categories
        categories = re.findall(r'<category[^>]*term="([^"]*)"', entry)

        # Extract PDF link
        pdf_match = re.search(r'<link[^>]*title="pdf"[^>]*href="([^"]*)"', entry)

        title = title_match.group(1).strip() if title_match else ""
        title = re.sub(r"\s+", " ", title)  # collapse whitespace

        summary = summary_match.group(1).strip() if summary_match else ""
        summary = re.sub(r"\s+", " ", summary)
        if len(summary) > 300:
            summary = summary[:300] + "..."

        arxiv_id = id_match.group(1) if id_match else ""
        # Extract short ID from URL
        short_id = arxiv_id.split("/abs/")[-1] if "/abs/" in arxiv_id else arxiv_id

        papers.append({
            "id": short_id,
            "title": title,
            "summary": summary,
            "authors": authors[:5],
            "categories": categories[:5],
            "published": published_match.group(1) if published_match else None,
            "updated": updated_match.group(1) if updated_match else None,
            "pdf_url": pdf_match.group(1) if pdf_match else None,
            "url": arxiv_id,
        })

    return papers


async def fetch_arxiv_papers(
    fetcher: Fetcher,
    query: str = "cat:cs.AI OR cat:cs.LG OR cat:cs.CL",
    limit: int = 25,
    sort_by: str = "submittedDate",
) -> dict:
    """Fetch recent papers from arXiv.

    Args:
        fetcher: Shared HTTP fetcher.
        query: arXiv search query (default: AI/ML/NLP categories).
        limit: Number of papers (max 50).
        sort_by: Sort field — "submittedDate", "relevance", or "lastUpdatedDate".

    Returns:
        Dict with papers[], count, source, timestamp.
    """
    limit = min(limit, 50)

    safe_query = re.sub(r"[^a-zA-Z0-9:._\s|()]", "", query)[:128]

    xml_text = await fetcher.get_xml(
        _ARXIV_API_URL,
        source="arxiv",
        cache_key=f"arxiv:{safe_query}:{sort_by}:{limit}",
        cache_ttl=900,
        timeout=20.0,
    )

    # get_xml doesn't support params, so construct URL manually
    # Actually, we need to use get_text with params
    if xml_text is None:
        # Try with full URL including params
        url = f"{_ARXIV_API_URL}?search_query={query}&sortBy={sort_by}&sortOrder=descending&max_results={limit}"
        xml_text = await fetcher.get_text(
            url,
            source="arxiv",
            cache_key=f"arxiv:{safe_query}:{sort_by}:{limit}",
            cache_ttl=900,
            timeout=20.0,
        )

    if xml_text is None:
        return {"papers": [], "count": 0, "source": "arxiv", "timestamp": _utc_now_iso()}

    papers = _parse_arxiv_xml(xml_text)

    return {
        "papers": papers[:limit],
        "count": len(papers[:limit]),
        "query": query,
        "source": "arxiv",
        "timestamp": _utc_now_iso(),
    }
