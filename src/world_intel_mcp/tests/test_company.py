"""Tests for analysis.company — company enrichment composite."""

import httpx
import pytest
import respx

from world_intel_mcp.fetcher import Fetcher


# ---------------------------------------------------------------------------
# Fixtures: Yahoo chart + quoteSummary + GDELT + GitHub mock responses
# ---------------------------------------------------------------------------

_YAHOO_CHART_AAPL = {
    "chart": {
        "result": [
            {
                "meta": {
                    "symbol": "AAPL",
                    "regularMarketPrice": 189.50,
                    "previousClose": 187.00,
                    "regularMarketVolume": 52_000_000,
                    "marketCap": 2_950_000_000_000,
                    "currency": "USD",
                }
            }
        ]
    }
}

_YAHOO_SUMMARY_AAPL = {
    "quoteSummary": {
        "result": [
            {
                "assetProfile": {
                    "sector": "Technology",
                    "industry": "Consumer Electronics",
                    "fullTimeEmployees": 164000,
                    "website": "https://www.apple.com",
                    "longBusinessSummary": "Apple Inc. designs, manufactures, and markets smartphones and personal computers.",
                },
                "financialData": {
                    "totalRevenue": {"raw": 383_285_000_000, "fmt": "383.29B"},
                    "profitMargins": {"raw": 0.2631, "fmt": "26.31%"},
                },
                "defaultKeyStatistics": {
                    "forwardPE": {"raw": 28.5, "fmt": "28.50"},
                    "marketCap": {"raw": 2_950_000_000_000, "fmt": "2.95T"},
                },
            }
        ]
    }
}

_GDELT_NEWS = {
    "articles": [
        {
            "title": "Apple launches new AI features",
            "url": "https://example.com/apple-ai",
            "seendate": "20260308T120000Z",
        },
        {
            "title": "AAPL stock hits record high",
            "url": "https://example.com/aapl-record",
            "seendate": "20260307T100000Z",
        },
    ]
}

_GITHUB_SEARCH = {
    "items": [
        {
            "full_name": "apple/swift",
            "owner": {"login": "apple"},
            "stargazers_count": 67000,
            "html_url": "https://github.com/apple/swift",
        },
        {
            "full_name": "apple/ml-ferret",
            "owner": {"login": "apple"},
            "stargazers_count": 8200,
            "html_url": "https://github.com/apple/ml-ferret",
        },
        {
            "full_name": "someone/unrelated",
            "owner": {"login": "someone"},
            "stargazers_count": 100,
            "html_url": "https://github.com/someone/unrelated",
        },
    ]
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_company_profile_full(fetcher: Fetcher) -> None:
    """Test company profile with all sources returning data."""
    from world_intel_mcp.analysis.company import fetch_company_profile

    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/APPLE").mock(
        return_value=httpx.Response(200, json=_YAHOO_CHART_AAPL)
    )
    respx.get("https://query1.finance.yahoo.com/v10/finance/quoteSummary/APPLE").mock(
        return_value=httpx.Response(200, json=_YAHOO_SUMMARY_AAPL)
    )
    respx.get("https://api.gdeltproject.org/api/v2/doc/doc").mock(
        return_value=httpx.Response(200, json=_GDELT_NEWS)
    )
    respx.get("https://api.github.com/search/repositories").mock(
        return_value=httpx.Response(200, json=_GITHUB_SEARCH)
    )
    # SEC EDGAR ticker lookup (module exists, must be mocked)
    respx.get(url__regex=r"sec\.gov").mock(return_value=httpx.Response(200, json={}))
    respx.get(url__regex=r"data\.sec\.gov").mock(
        return_value=httpx.Response(200, json={})
    )

    result = await fetch_company_profile(fetcher, "apple")

    assert result["ticker"] == "APPLE"
    assert result["source"] == "composite"
    assert result["sector"] == "Technology"
    assert result["industry"] == "Consumer Electronics"

    # Stock data
    assert result["stock"]["price"] == 189.50
    assert result["stock"]["volume"] == 52_000_000
    assert result["stock"]["change_pct"] is not None

    # Financials
    assert result["financials"]["revenue"] == 383_285_000_000
    assert result["financials"]["profit_margin"] == 0.2631
    assert result["financials"]["pe_ratio"] == 28.5
    assert result["financials"]["employees"] == 164000

    # News
    assert len(result["recent_news"]) == 2
    assert result["recent_news"][0]["title"] == "Apple launches new AI features"

    # GitHub — only "apple" org repos should be included, not "someone/unrelated"
    assert "github" in result
    assert len(result["github"]) == 2
    assert result["github"][0]["name"] == "apple/swift"

    assert "fetched_at" in result


@respx.mock
@pytest.mark.asyncio
async def test_fetch_company_profile_partial_failure(fetcher: Fetcher) -> None:
    """Test that partial upstream failures produce a valid but incomplete result."""
    from world_intel_mcp.analysis.company import fetch_company_profile

    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/MSFT").mock(
        return_value=httpx.Response(
            200,
            json={
                "chart": {
                    "result": [
                        {
                            "meta": {
                                "symbol": "MSFT",
                                "regularMarketPrice": 420.00,
                                "previousClose": 415.00,
                                "regularMarketVolume": 25_000_000,
                                "currency": "USD",
                            }
                        }
                    ]
                }
            },
        )
    )
    # quoteSummary fails
    respx.get("https://query1.finance.yahoo.com/v10/finance/quoteSummary/MSFT").mock(
        return_value=httpx.Response(500)
    )
    # GDELT fails
    respx.get("https://api.gdeltproject.org/api/v2/doc/doc").mock(
        return_value=httpx.Response(503)
    )
    # GitHub fails
    respx.get("https://api.github.com/search/repositories").mock(
        return_value=httpx.Response(403)
    )
    # SEC EDGAR (module exists, must be mocked)
    respx.get(url__regex=r"sec\.gov").mock(return_value=httpx.Response(500))

    result = await fetch_company_profile(fetcher, "MSFT")

    assert result["ticker"] == "MSFT"
    assert result["source"] == "composite"
    # Stock should still be populated
    assert result["stock"]["price"] == 420.00
    # Financials empty when quoteSummary fails
    assert result["financials"] == {}
    # No news when GDELT fails
    assert result["recent_news"] == []
    # No github key when GitHub fails
    assert "github" not in result or result.get("github") == []


@respx.mock
@pytest.mark.asyncio
async def test_fetch_company_profile_total_failure(fetcher: Fetcher) -> None:
    """Test with all upstreams returning errors."""
    from world_intel_mcp.analysis.company import fetch_company_profile

    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/XYZ").mock(
        return_value=httpx.Response(404)
    )
    respx.get("https://query1.finance.yahoo.com/v10/finance/quoteSummary/XYZ").mock(
        return_value=httpx.Response(404)
    )
    respx.get("https://api.gdeltproject.org/api/v2/doc/doc").mock(
        return_value=httpx.Response(500)
    )
    respx.get("https://api.github.com/search/repositories").mock(
        return_value=httpx.Response(500)
    )
    # SEC EDGAR (module exists, must be mocked)
    respx.get(url__regex=r"sec\.gov").mock(return_value=httpx.Response(500))

    result = await fetch_company_profile(fetcher, "XYZ")

    assert result["ticker"] == "XYZ"
    assert result["source"] == "composite"
    assert result["stock"] == {}
    assert result["recent_news"] == []
    assert "fetched_at" in result
