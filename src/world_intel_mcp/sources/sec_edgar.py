"""SEC EDGAR filing data sources.

Fetches SEC filings via the EDGAR Full-Text Search System (EFTS) and
the submissions API.  Free, no API key required.  SEC mandates a
User-Agent header with contact info on every request.
"""

import logging
from datetime import datetime, timedelta, timezone

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.sources.sec_edgar")

_SEC_HEADERS = {
    "User-Agent": "PhoenixAGI-WorldIntel intel@2acrestudios.com",
}

_EFTS_URL = "https://efts.sec.gov/LATEST/search-index"
_TICKERS_URL = "https://www.sec.gov/files/company_tickers.json"
_SUBMISSIONS_URL = "https://data.sec.gov/submissions"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Full-text search across all EDGAR filings
# ---------------------------------------------------------------------------


async def fetch_sec_filings(
    fetcher: Fetcher,
    query: str | None = None,
    form_type: str | None = None,
    date_range: str | None = None,
    limit: int = 25,
) -> dict:
    """Search SEC EDGAR filings via the full-text search API.

    Args:
        fetcher: Shared HTTP fetcher.
        query: Free-text search query (company name, keyword, etc.).
        form_type: Comma-separated form types to filter (e.g. ``"10-K,10-Q,8-K"``).
        date_range: Custom date range as ``"YYYY-MM-DD,YYYY-MM-DD"`` (start,end).
            Defaults to last 30 days.
        limit: Maximum number of results (capped at 100).

    Returns:
        Dict with ``query``, ``form_type``, ``filings`` list, ``total``, plus metadata.
    """
    limit = min(limit, 100)

    params: dict = {"q": query or "*", "from": 0, "size": limit}
    if form_type:
        params["forms"] = form_type

    if date_range:
        parts = date_range.split(",")
        if len(parts) == 2:
            params["dateRange"] = "custom"
            params["startdt"] = parts[0].strip()
            params["enddt"] = parts[1].strip()
    else:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=30)
        params["dateRange"] = "custom"
        params["startdt"] = start.strftime("%Y-%m-%d")
        params["enddt"] = end.strftime("%Y-%m-%d")

    cache_key = f"sec:search:{query}:{form_type}:{limit}"

    data = await fetcher.get_json(
        _EFTS_URL,
        source="sec-edgar",
        cache_key=cache_key,
        cache_ttl=1800,
        headers=_SEC_HEADERS,
        params=params,
    )

    result: dict = {
        "query": query,
        "form_type": form_type,
        "filings": [],
        "total": 0,
        "fetched_at": _utc_now_iso(),
        "source": "sec-edgar",
    }

    if not isinstance(data, dict):
        return result

    try:
        hits = data.get("hits", {})
        if not isinstance(hits, dict):
            return result
        total_raw = hits.get("total", 0)
        result["total"] = (
            total_raw.get("value", 0) if isinstance(total_raw, dict) else total_raw
        )

        for hit in hits.get("hits", []):
            if not isinstance(hit, dict):
                continue
            src = hit.get("_source", {})
            if not isinstance(src, dict):
                continue
            filing = {
                "company": src.get("display_names", [None])[0]
                if src.get("display_names")
                else src.get("entity_name"),
                "form_type": src.get("form_type", ""),
                "filed_date": src.get("file_date", ""),
                "description": src.get(
                    "display_description", src.get("description", "")
                ),
                "url": f"https://www.sec.gov/Archives/edgar/data/{src.get('entity_id', '')}/{src.get('file_num', '')}".rstrip(
                    "/"
                ),
            }
            file_id = hit.get("_id", "")
            if file_id:
                filing["url"] = (
                    f"https://www.sec.gov/Archives/edgar/data/{file_id.replace(':', '/')}"
                )
            result["filings"].append(filing)
    except (KeyError, TypeError, IndexError) as exc:
        logger.warning("Failed to parse EFTS search results: %s", exc)

    return result


# ---------------------------------------------------------------------------
# Company filings by ticker
# ---------------------------------------------------------------------------


async def _resolve_cik(fetcher: Fetcher, ticker: str) -> tuple[str | None, str | None]:
    """Resolve a stock ticker to a zero-padded CIK and company name.

    Uses the SEC company_tickers.json file (cached for 24h).
    Returns (cik_padded, company_name) or (None, None) if not found.
    """
    data = await fetcher.get_json(
        _TICKERS_URL,
        source="sec-edgar",
        cache_key="sec:company_tickers",
        cache_ttl=86400,
        headers=_SEC_HEADERS,
    )

    if not isinstance(data, dict):
        return None, None

    try:
        ticker_upper = ticker.upper()
        for entry in data.values():
            if entry.get("ticker", "").upper() == ticker_upper:
                cik = str(entry["cik_str"])
                padded = cik.zfill(10)
                return padded, entry.get("title", "")
    except (KeyError, TypeError, AttributeError) as exc:
        logger.warning("Failed to resolve ticker %s: %s", ticker, exc)

    return None, None


async def fetch_company_filings(
    fetcher: Fetcher,
    ticker: str,
    form_types: list[str] | None = None,
    limit: int = 10,
) -> dict:
    """Fetch recent SEC filings for a company by ticker symbol.

    Args:
        fetcher: Shared HTTP fetcher.
        ticker: Stock ticker symbol (e.g. ``"AAPL"``).
        form_types: Filter by form types. Defaults to ``["10-K", "10-Q", "8-K"]``.
        limit: Maximum number of filings to return.

    Returns:
        Dict with ``ticker``, ``company_name``, ``cik``, ``filings`` list, plus metadata.
    """
    allowed_forms = set(form_types or ["10-K", "10-Q", "8-K"])

    result: dict = {
        "ticker": ticker.upper(),
        "company_name": "",
        "cik": "",
        "filings": [],
        "fetched_at": _utc_now_iso(),
        "source": "sec-edgar",
    }

    cik, company_name = await _resolve_cik(fetcher, ticker)
    if cik is None:
        result["error"] = f"Ticker '{ticker}' not found in SEC company tickers"
        return result

    result["cik"] = cik
    result["company_name"] = company_name or ""

    submissions_url = f"{_SUBMISSIONS_URL}/CIK{cik}.json"

    data = await fetcher.get_json(
        submissions_url,
        source="sec-edgar",
        cache_key=f"sec:company:{ticker.upper()}:{limit}",
        cache_ttl=3600,
        headers=_SEC_HEADERS,
    )

    if not isinstance(data, dict):
        return result

    try:
        # Use company name from submissions if available
        if data.get("name"):
            result["company_name"] = data["name"]

        filings_obj = data.get("filings", {})
        recent = filings_obj.get("recent", {}) if isinstance(filings_obj, dict) else {}
        forms = recent.get("form", [])
        dates = recent.get("filingDate", [])
        primary_docs = recent.get("primaryDocument", [])
        descriptions = recent.get("primaryDocDescription", [])
        accession_numbers = recent.get("accessionNumber", [])

        count = 0
        for i in range(len(forms)):
            if count >= limit:
                break
            form = forms[i] if i < len(forms) else ""
            if form not in allowed_forms:
                continue

            accession = (
                accession_numbers[i].replace("-", "")
                if i < len(accession_numbers)
                else ""
            )
            primary_doc = primary_docs[i] if i < len(primary_docs) else ""
            filing_url = (
                f"https://www.sec.gov/Archives/edgar/data/{cik.lstrip('0')}/{accession}/{primary_doc}"
                if accession and primary_doc
                else ""
            )

            result["filings"].append(
                {
                    "form": form,
                    "filing_date": dates[i] if i < len(dates) else "",
                    "description": descriptions[i] if i < len(descriptions) else "",
                    "url": filing_url,
                }
            )
            count += 1
    except (KeyError, TypeError, IndexError) as exc:
        logger.warning("Failed to parse submissions for %s: %s", ticker, exc)

    return result


# ---------------------------------------------------------------------------
# Recent 8-K filings (material events)
# ---------------------------------------------------------------------------


async def fetch_recent_8k(
    fetcher: Fetcher,
    limit: int = 25,
) -> dict:
    """Fetch the most recent 8-K filings (material corporate events).

    8-K filings cover M&A activity, executive changes, earnings releases,
    and other material events.

    Args:
        fetcher: Shared HTTP fetcher.
        limit: Maximum number of filings to return.

    Returns:
        Dict with ``filings`` list, ``total`` count, plus metadata.
    """
    limit = min(limit, 100)

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)

    params: dict = {
        "q": "*",
        "forms": "8-K",
        "dateRange": "custom",
        "startdt": start.strftime("%Y-%m-%d"),
        "enddt": end.strftime("%Y-%m-%d"),
        "from": 0,
        "size": limit,
    }

    data = await fetcher.get_json(
        _EFTS_URL,
        source="sec-edgar",
        cache_key=f"sec:recent-8k:{limit}",
        cache_ttl=1800,
        headers=_SEC_HEADERS,
        params=params,
    )

    result: dict = {
        "filings": [],
        "total": 0,
        "fetched_at": _utc_now_iso(),
        "source": "sec-edgar",
    }

    if not isinstance(data, dict):
        return result

    try:
        hits = data.get("hits", {})
        if not isinstance(hits, dict):
            return result
        total_raw = hits.get("total", 0)
        result["total"] = (
            total_raw.get("value", 0) if isinstance(total_raw, dict) else total_raw
        )

        for hit in hits.get("hits", []):
            if not isinstance(hit, dict):
                continue
            src = hit.get("_source", {})
            filing: dict = {
                "company": src.get("display_names", [None])[0]
                if src.get("display_names")
                else src.get("entity_name"),
                "ticker": None,
                "filed_date": src.get("file_date", ""),
                "description": src.get(
                    "display_description", src.get("description", "")
                ),
                "items": src.get("items", []),
                "url": "",
            }

            # Extract ticker from display_names if present
            tickers = src.get("tickers", [])
            if tickers:
                filing["ticker"] = tickers[0]

            file_id = hit.get("_id", "")
            if file_id:
                filing["url"] = (
                    f"https://www.sec.gov/Archives/edgar/data/{file_id.replace(':', '/')}"
                )

            result["filings"].append(filing)
    except (KeyError, TypeError, IndexError) as exc:
        logger.warning("Failed to parse recent 8-K results: %s", exc)

    return result
