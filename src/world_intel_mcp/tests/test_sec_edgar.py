"""Tests for SEC EDGAR source module — uses respx to mock HTTP calls."""

import httpx
import pytest
import respx

from world_intel_mcp.fetcher import Fetcher


# ---------------------------------------------------------------------------
# fetch_sec_filings
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_sec_filings(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.sec_edgar import fetch_sec_filings

    efts_response = {
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [
                {
                    "_id": "0000320193/000032019326000015/aapl-20260101.htm",
                    "_source": {
                        "display_names": ["Apple Inc"],
                        "form_type": "10-K",
                        "file_date": "2026-01-15",
                        "display_description": "Annual report for fiscal year 2025",
                        "entity_id": "320193",
                    },
                }
            ],
        }
    }

    respx.get("https://efts.sec.gov/LATEST/search-index").mock(
        return_value=httpx.Response(200, json=efts_response)
    )

    result = await fetch_sec_filings(fetcher, query="Apple", form_type="10-K", limit=5)

    assert result["source"] == "sec-edgar"
    assert result["query"] == "Apple"
    assert result["form_type"] == "10-K"
    assert result["total"] == 1
    assert len(result["filings"]) == 1
    assert result["filings"][0]["company"] == "Apple Inc"
    assert result["filings"][0]["form_type"] == "10-K"
    assert result["filings"][0]["filed_date"] == "2026-01-15"
    assert "fetched_at" in result


@respx.mock
@pytest.mark.asyncio
async def test_fetch_sec_filings_empty(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.sec_edgar import fetch_sec_filings

    respx.get("https://efts.sec.gov/LATEST/search-index").mock(
        return_value=httpx.Response(200, json={"hits": {"total": 0, "hits": []}})
    )

    result = await fetch_sec_filings(fetcher, query="nonexistentzzzxyz")

    assert result["source"] == "sec-edgar"
    assert result["total"] == 0
    assert result["filings"] == []


@respx.mock
@pytest.mark.asyncio
async def test_fetch_sec_filings_api_failure(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.sec_edgar import fetch_sec_filings

    respx.get("https://efts.sec.gov/LATEST/search-index").mock(
        return_value=httpx.Response(500)
    )

    result = await fetch_sec_filings(fetcher, query="Apple")

    assert result["source"] == "sec-edgar"
    assert result["filings"] == []
    assert result["total"] == 0


# ---------------------------------------------------------------------------
# fetch_company_filings
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_company_filings(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.sec_edgar import fetch_company_filings

    # Mock the company tickers endpoint
    tickers_response = {
        "0": {"cik_str": 320193, "ticker": "AAPL", "title": "Apple Inc"},
        "1": {"cik_str": 789019, "ticker": "MSFT", "title": "Microsoft Corp"},
    }

    respx.get("https://www.sec.gov/files/company_tickers.json").mock(
        return_value=httpx.Response(200, json=tickers_response)
    )

    # Mock the submissions endpoint
    submissions_response = {
        "cik": "320193",
        "name": "Apple Inc",
        "filings": {
            "recent": {
                "form": ["10-K", "10-Q", "8-K", "4", "10-Q"],
                "filingDate": [
                    "2026-01-15",
                    "2025-11-01",
                    "2025-10-15",
                    "2025-10-01",
                    "2025-08-01",
                ],
                "primaryDocument": [
                    "aapl-20260101.htm",
                    "aapl-20251001q.htm",
                    "aapl-20251015-8k.htm",
                    "form4.xml",
                    "aapl-20250801q.htm",
                ],
                "primaryDocDescription": [
                    "Annual Report",
                    "Quarterly Report Q4",
                    "Current Report",
                    "Statement of Changes",
                    "Quarterly Report Q3",
                ],
                "accessionNumber": [
                    "0000320193-26-000015",
                    "0000320193-25-000090",
                    "0000320193-25-000085",
                    "0000320193-25-000080",
                    "0000320193-25-000070",
                ],
            }
        },
    }

    respx.get("https://data.sec.gov/submissions/CIK0000320193.json").mock(
        return_value=httpx.Response(200, json=submissions_response)
    )

    result = await fetch_company_filings(fetcher, ticker="AAPL", limit=10)

    assert result["source"] == "sec-edgar"
    assert result["ticker"] == "AAPL"
    assert result["company_name"] == "Apple Inc"
    assert result["cik"] == "0000320193"
    assert "fetched_at" in result

    # Should have 10-K, 10-Q, 8-K but NOT the "4" (form type filter)
    assert len(result["filings"]) == 4
    forms = [f["form"] for f in result["filings"]]
    assert "4" not in forms
    assert "10-K" in forms
    assert "10-Q" in forms
    assert "8-K" in forms

    # Verify first filing details
    first = result["filings"][0]
    assert first["form"] == "10-K"
    assert first["filing_date"] == "2026-01-15"
    assert first["description"] == "Annual Report"
    assert "320193" in first["url"]


@respx.mock
@pytest.mark.asyncio
async def test_fetch_company_filings_unknown_ticker(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.sec_edgar import fetch_company_filings

    tickers_response = {
        "0": {"cik_str": 320193, "ticker": "AAPL", "title": "Apple Inc"},
    }

    respx.get("https://www.sec.gov/files/company_tickers.json").mock(
        return_value=httpx.Response(200, json=tickers_response)
    )

    result = await fetch_company_filings(fetcher, ticker="ZZZXYZ")

    assert result["source"] == "sec-edgar"
    assert result["ticker"] == "ZZZXYZ"
    assert "error" in result
    assert result["filings"] == []


@respx.mock
@pytest.mark.asyncio
async def test_fetch_company_filings_custom_form_types(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.sec_edgar import fetch_company_filings

    tickers_response = {
        "0": {"cik_str": 789019, "ticker": "MSFT", "title": "Microsoft Corp"},
    }

    respx.get("https://www.sec.gov/files/company_tickers.json").mock(
        return_value=httpx.Response(200, json=tickers_response)
    )

    submissions_response = {
        "cik": "789019",
        "name": "Microsoft Corp",
        "filings": {
            "recent": {
                "form": ["10-K", "10-Q", "8-K"],
                "filingDate": ["2026-01-10", "2025-11-05", "2025-10-20"],
                "primaryDocument": ["msft-10k.htm", "msft-10q.htm", "msft-8k.htm"],
                "primaryDocDescription": [
                    "Annual Report",
                    "Quarterly Report",
                    "Current Report",
                ],
                "accessionNumber": [
                    "0000789019-26-000010",
                    "0000789019-25-000050",
                    "0000789019-25-000045",
                ],
            }
        },
    }

    respx.get("https://data.sec.gov/submissions/CIK0000789019.json").mock(
        return_value=httpx.Response(200, json=submissions_response)
    )

    result = await fetch_company_filings(fetcher, ticker="MSFT", form_types=["10-K"])

    assert result["ticker"] == "MSFT"
    assert len(result["filings"]) == 1
    assert result["filings"][0]["form"] == "10-K"


# ---------------------------------------------------------------------------
# fetch_recent_8k
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_recent_8k(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.sec_edgar import fetch_recent_8k

    efts_response = {
        "hits": {
            "total": {"value": 2, "relation": "eq"},
            "hits": [
                {
                    "_id": "0000320193/000032019326000020/aapl-8k.htm",
                    "_source": {
                        "display_names": ["Apple Inc"],
                        "entity_name": "Apple Inc",
                        "form_type": "8-K",
                        "file_date": "2026-03-07",
                        "display_description": "Results of Operations and Financial Condition",
                        "tickers": ["AAPL"],
                        "items": ["2.02", "9.01"],
                    },
                },
                {
                    "_id": "0000789019/000078901926000030/msft-8k.htm",
                    "_source": {
                        "entity_name": "Microsoft Corp",
                        "form_type": "8-K",
                        "file_date": "2026-03-06",
                        "description": "Entry into Material Agreement",
                        "tickers": ["MSFT"],
                        "items": ["1.01"],
                    },
                },
            ],
        }
    }

    respx.get("https://efts.sec.gov/LATEST/search-index").mock(
        return_value=httpx.Response(200, json=efts_response)
    )

    result = await fetch_recent_8k(fetcher, limit=10)

    assert result["source"] == "sec-edgar"
    assert result["total"] == 2
    assert len(result["filings"]) == 2
    assert "fetched_at" in result

    first = result["filings"][0]
    assert first["company"] == "Apple Inc"
    assert first["ticker"] == "AAPL"
    assert first["filed_date"] == "2026-03-07"
    assert first["items"] == ["2.02", "9.01"]
    assert "url" in first

    second = result["filings"][1]
    assert second["company"] == "Microsoft Corp"
    assert second["ticker"] == "MSFT"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_recent_8k_empty(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.sec_edgar import fetch_recent_8k

    respx.get("https://efts.sec.gov/LATEST/search-index").mock(
        return_value=httpx.Response(200, json={"hits": {"total": 0, "hits": []}})
    )

    result = await fetch_recent_8k(fetcher)

    assert result["source"] == "sec-edgar"
    assert result["total"] == 0
    assert result["filings"] == []


@respx.mock
@pytest.mark.asyncio
async def test_fetch_recent_8k_api_failure(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.sec_edgar import fetch_recent_8k

    respx.get("https://efts.sec.gov/LATEST/search-index").mock(
        return_value=httpx.Response(503)
    )

    result = await fetch_recent_8k(fetcher)

    assert result["source"] == "sec-edgar"
    assert result["filings"] == []
    assert result["total"] == 0
