"""Tests for source modules — uses respx to mock HTTP calls."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from world_intel_mcp.cache import Cache
from world_intel_mcp.circuit_breaker import CircuitBreaker
from world_intel_mcp.fetcher import Fetcher


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(db_path=tmp_path / "test_cache.db")


@pytest.fixture
def fetcher(cache: Cache) -> Fetcher:
    breaker = CircuitBreaker()
    return Fetcher(cache=cache, breaker=breaker, default_timeout=5.0)


# ---------------------------------------------------------------------------
# Markets
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_market_quotes(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.markets import fetch_market_quotes

    # Mock Yahoo Finance v8 chart response for ^GSPC
    chart_response = {
        "chart": {
            "result": [{
                "meta": {
                    "symbol": "^GSPC",
                    "regularMarketPrice": 5123.45,
                    "regularMarketChangePercent": 0.42,
                    "currency": "USD",
                }
            }]
        }
    }

    respx.get("https://query1.finance.yahoo.com/v8/finance/chart/%5EGSPC").mock(
        return_value=httpx.Response(200, json=chart_response)
    )

    result = await fetch_market_quotes(fetcher, symbols=["^GSPC"])
    assert "quotes" in result
    assert len(result["quotes"]) == 1
    assert result["quotes"][0]["symbol"] == "^GSPC"
    assert result["quotes"][0]["price"] == 5123.45
    assert result["source"] == "yahoo-finance"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_crypto_quotes(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.markets import fetch_crypto_quotes

    coins = [
        {
            "id": "bitcoin",
            "symbol": "btc",
            "name": "Bitcoin",
            "current_price": 98000,
            "market_cap": 1900000000000,
            "price_change_percentage_24h": 2.5,
            "sparkline_in_7d": {"price": [95000, 96000, 97000, 98000]},
        }
    ]

    respx.get("https://api.coingecko.com/api/v3/coins/markets").mock(
        return_value=httpx.Response(200, json=coins)
    )

    result = await fetch_crypto_quotes(fetcher, limit=5)
    assert "coins" in result
    assert len(result["coins"]) == 1
    assert result["coins"][0]["symbol"] == "btc"
    assert result["source"] == "coingecko"


# ---------------------------------------------------------------------------
# Seismology
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_earthquakes(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.seismology import fetch_earthquakes

    geojson = {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "id": "us7000abc1",
                "properties": {
                    "mag": 5.2,
                    "place": "100km SSW of Somewhere",
                    "time": 1708700000000,
                    "tsunami": 0,
                    "felt": 15,
                    "alert": "green",
                    "url": "https://earthquake.usgs.gov/earthquakes/eventpage/us7000abc1",
                },
                "geometry": {
                    "type": "Point",
                    "coordinates": [-120.5, 35.2, 10.0],
                },
            }
        ],
    }

    respx.get("https://earthquake.usgs.gov/fdsnws/event/1/query").mock(
        return_value=httpx.Response(200, json=geojson)
    )

    result = await fetch_earthquakes(fetcher, min_magnitude=4.0, hours=24)
    assert result["count"] == 1
    eq = result["earthquakes"][0]
    assert eq["magnitude"] == 5.2
    assert eq["id"] == "us7000abc1"
    assert eq["depth_km"] == 10.0
    assert eq["latitude"] == 35.2
    assert eq["longitude"] == -120.5
    assert result["source"] == "usgs"


# ---------------------------------------------------------------------------
# Wildfire
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_wildfires_no_api_key(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.wildfire import fetch_wildfires

    with patch.dict("os.environ", {}, clear=False):
        # Remove the key if present
        import os
        os.environ.pop("NASA_FIRMS_API_KEY", None)
        result = await fetch_wildfires(fetcher, api_key=None)

    assert "error" in result


@respx.mock
@pytest.mark.asyncio
async def test_fetch_wildfires_single_region(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.wildfire import fetch_wildfires

    csv_data = (
        "latitude,longitude,bright_ti4,scan,track,acq_date,acq_time,satellite,confidence,version,bright_ti5,frp,daynight\n"
        "34.5,-118.2,350.0,0.5,0.5,2024-02-23,1200,N,high,2.0,290.0,45.0,D\n"
        "34.6,-118.3,360.0,0.5,0.5,2024-02-23,1200,N,high,2.0,295.0,55.0,D\n"
        "34.5,-118.2,340.0,0.5,0.5,2024-02-23,1200,N,low,2.0,285.0,30.0,D\n"
    )

    respx.get(url__regex=r".*firms\.modaps\.eosdis\.nasa\.gov.*").mock(
        return_value=httpx.Response(200, text=csv_data)
    )

    result = await fetch_wildfires(fetcher, region="north_america", api_key="testkey")
    assert "fires_by_region" in result
    na = result["fires_by_region"]["north_america"]
    assert na["count"] == 2  # only 2 high-confidence
    assert result["total_fires"] == 2


# ---------------------------------------------------------------------------
# Economic
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_fred_series_no_key(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.economic import fetch_fred_series

    import os
    os.environ.pop("FRED_API_KEY", None)
    result = await fetch_fred_series(fetcher, series_id="UNRATE", api_key=None)
    assert "error" in result


@respx.mock
@pytest.mark.asyncio
async def test_fetch_world_bank_indicators(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.economic import fetch_world_bank_indicators

    wb_response = [
        {"page": 1, "pages": 1, "per_page": 5, "total": 2},
        [
            {"indicator": {"id": "NY.GDP.MKTP.CD", "value": "GDP"}, "date": "2023", "value": 25000000000000},
            {"indicator": {"id": "NY.GDP.MKTP.CD", "value": "GDP"}, "date": "2022", "value": 24000000000000},
        ],
    ]

    respx.get(url__regex=r".*api\.worldbank\.org.*").mock(
        return_value=httpx.Response(200, json=wb_response)
    )

    result = await fetch_world_bank_indicators(fetcher, country="USA", indicators=["NY.GDP.MKTP.CD"])
    assert "indicators" in result
    assert len(result["indicators"]) == 1
    assert result["indicators"][0]["id"] == "NY.GDP.MKTP.CD"
    assert result["source"] == "world-bank"


# ---------------------------------------------------------------------------
# Health (disease outbreaks)
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_disease_outbreaks(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.health import fetch_disease_outbreaks

    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0"><channel><title>WHO</title>
    <item>
        <title>Ebola outbreak in DRC - Update 5</title>
        <link>https://who.int/ebola-update</link>
        <pubDate>Mon, 10 Feb 2026 12:00:00 GMT</pubDate>
        <description>Ebola virus disease outbreak continues in North Kivu.</description>
    </item>
    <item>
        <title>Seasonal influenza update</title>
        <link>https://who.int/flu</link>
        <pubDate>Sun, 09 Feb 2026 08:00:00 GMT</pubDate>
        <description>Northern hemisphere flu season report.</description>
    </item>
    </channel></rss>"""

    # Mock all 3 health feeds returning same XML
    respx.get(url__regex=r".*who\.int.*").mock(
        return_value=httpx.Response(200, text=rss_xml)
    )
    respx.get(url__regex=r".*cdc\.gov.*").mock(
        return_value=httpx.Response(200, text=rss_xml)
    )
    respx.get(url__regex=r".*outbreaknewstoday.*").mock(
        return_value=httpx.Response(200, text=rss_xml)
    )

    result = await fetch_disease_outbreaks(fetcher)
    assert result["source"] == "health-outbreak-monitor"
    assert result["count"] > 0
    assert result["high_concern_count"] > 0  # "ebola" in title
    assert any(item["is_high_concern"] for item in result["items"])


# ---------------------------------------------------------------------------
# Sanctions (OFAC SDN)
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_sanctions_search(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.sanctions import fetch_sanctions_search

    csv_data = (
        '100,"DOE, John",individual,SDGT,"","","","","","","","nationality Iran; DOB 01 Jan 1970"\n'
        '101,"ACME CORP",entity,CUBA,"","","","","","","",""\n'
        '102,"SMITH, Jane",individual,SYRIA,"","","","","","","","nationality Syria"\n'
    )

    respx.get(url__regex=r".*treasury\.gov.*sdn\.csv.*").mock(
        return_value=httpx.Response(200, text=csv_data)
    )

    result = await fetch_sanctions_search(fetcher, query="DOE")
    assert result["source"] == "ofac-sdn"
    assert result["count"] == 1
    assert result["matches"][0]["name"] == "DOE, John"
    assert result["total_entities"] >= 1


@respx.mock
@pytest.mark.asyncio
async def test_fetch_sanctions_search_country_filter(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.sanctions import fetch_sanctions_search

    csv_data = (
        '100,"DOE, John",individual,SDGT,"","","","","","","","nationality Iran; DOB 01 Jan 1970"\n'
        '101,"ACME CORP",entity,CUBA,"","","","","","","",""\n'
    )

    respx.get(url__regex=r".*treasury\.gov.*sdn\.csv.*").mock(
        return_value=httpx.Response(200, text=csv_data)
    )

    result = await fetch_sanctions_search(fetcher, country="iran")
    assert result["count"] == 1
    assert result["matches"][0]["name"] == "DOE, John"


# ---------------------------------------------------------------------------
# Elections (pure data — no HTTP mocking needed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_election_calendar(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.elections import fetch_election_calendar

    result = await fetch_election_calendar(fetcher)
    assert result["source"] == "election-calendar"
    assert result["count"] > 0
    assert "elections" in result

    # Each election should have risk_score
    for election in result["elections"]:
        assert "risk_score" in election
        assert "days_until" in election
        assert election["status"] in ("past", "upcoming")


@pytest.mark.asyncio
async def test_fetch_election_calendar_country_filter(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.elections import fetch_election_calendar

    result = await fetch_election_calendar(fetcher, country="USA")
    # May or may not match depending on config data
    assert result["source"] == "election-calendar"
    assert isinstance(result["elections"], list)


# ---------------------------------------------------------------------------
# Shipping (Yahoo Finance quotes)
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_shipping_index(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.shipping import fetch_shipping_index

    chart_response = {
        "chart": {
            "result": [{
                "meta": {
                    "symbol": "BDRY",
                    "regularMarketPrice": 15.50,
                    "regularMarketChangePercent": 4.2,
                    "currency": "USD",
                }
            }]
        }
    }

    # Mock all 4 shipping symbols
    respx.get(url__regex=r".*finance\.yahoo\.com.*").mock(
        return_value=httpx.Response(200, json=chart_response)
    )

    result = await fetch_shipping_index(fetcher)
    assert result["source"] == "yahoo-finance"
    assert len(result["quotes"]) > 0
    assert isinstance(result["stress_score"], (int, float))
    assert result["assessment"] in ("low", "moderate", "elevated", "high", "extreme")


# ---------------------------------------------------------------------------
# Social (Reddit)
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_social_signals(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.social import fetch_social_signals

    reddit_response = {
        "data": {
            "children": [
                {
                    "data": {
                        "title": "Ukraine conflict escalation analysis",
                        "score": 5000,
                        "num_comments": 300,
                        "upvote_ratio": 0.95,
                        "created_utc": 1708700000,
                        "permalink": "/r/worldnews/comments/abc123/",
                        "is_self": False,
                    }
                },
                {
                    "data": {
                        "title": "US-China trade tensions rise",
                        "score": 2000,
                        "num_comments": 150,
                        "upvote_ratio": 0.88,
                        "created_utc": 1708690000,
                        "permalink": "/r/worldnews/comments/def456/",
                        "is_self": True,
                    }
                },
            ]
        }
    }

    respx.get(url__regex=r".*reddit\.com.*hot\.json.*").mock(
        return_value=httpx.Response(200, json=reddit_response)
    )

    result = await fetch_social_signals(fetcher)
    assert result["source"] == "reddit-public"
    assert result["velocity_metrics"]["total_posts"] > 0
    assert result["velocity_metrics"]["high_engagement_count"] > 0
    assert result["subreddits_queried"] == ["worldnews", "geopolitics"]


# ---------------------------------------------------------------------------
# Nuclear (USGS near test sites)
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_nuclear_monitor(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.nuclear import fetch_nuclear_monitor

    geojson = {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "id": "nn00900001",
                "properties": {
                    "mag": 2.8,
                    "place": "50km N of Test Site",
                    "time": 1708700000000,
                    "tsunami": 0,
                },
                "geometry": {
                    "type": "Point",
                    "coordinates": [129.08, 41.30, 3.0],  # Near Punggye-ri
                },
            }
        ],
    }

    # Mock USGS for all nuclear sites
    respx.get("https://earthquake.usgs.gov/fdsnws/event/1/query").mock(
        return_value=httpx.Response(200, json=geojson)
    )

    result = await fetch_nuclear_monitor(fetcher, hours=72)
    assert result["source"] == "usgs-nuclear-monitor"
    assert len(result["sites"]) == 5  # 5 nuclear test sites
    assert isinstance(result["total_flagged_events"], int)
    assert isinstance(result["critical_flags"], int)


# ---------------------------------------------------------------------------
# Infrastructure (Cloudflare + IODA fallback)
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_internet_outages_ioda_fallback(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.infrastructure import fetch_internet_outages

    # IODA response shape
    ioda_response = {
        "data": [
            {
                "entity": {"code": "US", "name": "United States"},
                "events": [
                    {
                        "id": "out-123",
                        "from": "2026-02-20T00:00:00Z",
                        "until": None,
                        "summary": "BGP outage detected",
                        "level": "country",
                    }
                ],
            }
        ]
    }

    # Cloudflare returns 403 (no token)
    respx.get(url__regex=r".*cloudflare\.com.*").mock(
        return_value=httpx.Response(403, json={"error": "unauthorized"})
    )
    # IODA responds
    respx.get(url__regex=r".*ioda\.inetintel.*").mock(
        return_value=httpx.Response(200, json=ioda_response)
    )

    import os
    os.environ.pop("CLOUDFLARE_API_TOKEN", None)

    result = await fetch_internet_outages(fetcher)
    assert result["source"] == "ioda-gatech"
    assert result["total_7d"] == 1
    assert result["ongoing_count"] == 1


@respx.mock
@pytest.mark.asyncio
async def test_fetch_cable_health(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.infrastructure import fetch_cable_health

    warnings = [
        {
            "msgYear": 2026,
            "msgNumber": 42,
            "navArea": "XII",
            "subregion": "31",
            "status": "in force",
            "issueDate": "2026-02-20",
            "text": "SUBMARINE CABLE OPERATIONS 40-30.5N/030-15.2E VESSELS ADVISED",
        }
    ]

    respx.get(url__regex=r".*nga\.mil.*broadcast-warn.*").mock(
        return_value=httpx.Response(200, json=warnings)
    )

    result = await fetch_cable_health(fetcher)
    assert result["source"] == "nga-msi"
    assert "corridors" in result
    assert len(result["corridors"]) == 6
    assert result["cable_related_warnings"] >= 1  # "cable" keyword in text


# ---------------------------------------------------------------------------
# Conflict (UCDP + ACLED)
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_ucdp_events(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.conflict import fetch_ucdp_events
    from datetime import datetime, timezone

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    ucdp_response = {
        "TotalPages": 1,
        "Result": [
            {
                "id": 12345,
                "relid": "11-1",
                "year": 2026,
                "date_start": today,
                "date_end": today,
                "country": "Ukraine",
                "region": "Europe",
                "type_of_violence": 1,
                "side_a": "Government of Ukraine",
                "side_b": "DPR",
                "best": 5,
                "high": 10,
                "low": 2,
                "latitude": 48.0,
                "longitude": 37.5,
                "source_article": "Reuters",
                "source_headline": "Fighting continues",
            }
        ],
    }

    respx.get(url__regex=r".*ucdpapi\.pcr\.uu\.se.*").mock(
        return_value=httpx.Response(200, json=ucdp_response)
    )

    result = await fetch_ucdp_events(fetcher, days=30)
    assert result["source"] == "ucdp"
    assert result["count"] == 1
    assert result["events"][0]["country"] == "Ukraine"
    assert result["total_fatalities_best"] == 5


# ---------------------------------------------------------------------------
# Hacker News
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_hacker_news(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.hacker_news import fetch_hacker_news

    respx.get("https://hacker-news.firebaseio.com/v0/topstories.json").mock(
        return_value=httpx.Response(200, json=[101, 102])
    )
    respx.get("https://hacker-news.firebaseio.com/v0/item/101.json").mock(
        return_value=httpx.Response(200, json={
            "id": 101, "title": "Show HN: AI Tool", "url": "https://example.com",
            "score": 200, "by": "user1", "time": 1700000000, "descendants": 50,
        })
    )
    respx.get("https://hacker-news.firebaseio.com/v0/item/102.json").mock(
        return_value=httpx.Response(200, json={
            "id": 102, "title": "Rust 2.0", "url": "https://example.com/rust",
            "score": 150, "by": "user2", "time": 1700001000, "descendants": 30,
        })
    )

    result = await fetch_hacker_news(fetcher, limit=2)
    assert result["source"] == "hackernews"
    assert result["count"] == 2
    assert result["stories"][0]["score"] >= result["stories"][1]["score"]


# ---------------------------------------------------------------------------
# GitHub Trending
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_trending_repos(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.github_trending import fetch_trending_repos

    respx.get(url__regex=r".*api\.github\.com/search/repositories.*").mock(
        return_value=httpx.Response(200, json={
            "total_count": 1,
            "items": [{
                "full_name": "user/cool-repo",
                "description": "A cool tool",
                "html_url": "https://github.com/user/cool-repo",
                "stargazers_count": 500,
                "forks_count": 20,
                "language": "Python",
                "created_at": "2026-02-20T00:00:00Z",
                "topics": ["ai", "ml"],
            }],
        })
    )

    result = await fetch_trending_repos(fetcher, limit=5)
    assert result["source"] == "github"
    assert result["count"] == 1
    assert result["repos"][0]["name"] == "user/cool-repo"
    assert result["repos"][0]["stars"] == 500


# ---------------------------------------------------------------------------
# arXiv Papers
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_arxiv_papers(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.arxiv_papers import fetch_arxiv_papers

    arxiv_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <feed xmlns="http://www.w3.org/2005/Atom">
      <entry>
        <id>http://arxiv.org/abs/2602.12345v1</id>
        <title>Attention Is Still All You Need</title>
        <summary>We show transformers continue to dominate.</summary>
        <author><name>Jane Doe</name></author>
        <author><name>John Smith</name></author>
        <published>2026-02-20T00:00:00Z</published>
        <link href="http://arxiv.org/abs/2602.12345v1" rel="alternate"/>
        <link href="http://arxiv.org/pdf/2602.12345v1" title="pdf" rel="related"/>
        <category term="cs.AI"/>
        <category term="cs.LG"/>
      </entry>
    </feed>"""

    respx.get(url__regex=r".*export\.arxiv\.org/api/query.*").mock(
        return_value=httpx.Response(200, text=arxiv_xml)
    )

    result = await fetch_arxiv_papers(fetcher, limit=5)
    assert result["source"] == "arxiv"
    assert result["count"] == 1
    assert "Attention" in result["papers"][0]["title"]
    assert len(result["papers"][0]["authors"]) == 2


# ---------------------------------------------------------------------------
# USA Spending
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_usa_spending(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.usa_spending import fetch_usa_spending

    respx.get(url__regex=r".*api\.usaspending\.gov.*").mock(
        return_value=httpx.Response(200, json={
            "results": [{
                "agency_name": "Department of Defense",
                "abbreviation": "DOD",
                "current_total_budget_authority_amount": 850000000000,
                "obligated_amount": 700000000000,
                "outlay_amount": 650000000000,
                "agency_id": 97,
            }],
            "page_metadata": {"total": 1},
        })
    )

    result = await fetch_usa_spending(fetcher, limit=5)
    assert result["source"] == "usaspending"
    assert result["count"] == 1
    assert result["agencies"][0]["name"] == "Department of Defense"


# ---------------------------------------------------------------------------
# Environmental Events (NASA EONET)
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_environmental_events(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.environmental import fetch_environmental_events

    respx.get(url__regex=r".*eonet\.gsfc\.nasa\.gov.*").mock(
        return_value=httpx.Response(200, json={
            "events": [{
                "id": "EONET_1234",
                "title": "Wildfire in California",
                "categories": [{"id": "wildfires", "title": "Wildfires"}],
                "sources": [{"id": "InciWeb", "url": "https://inciweb.example.com"}],
                "geometry": [{"date": "2026-02-20T00:00:00Z", "coordinates": [-119.5, 34.5]}],
            }],
        })
    )

    result = await fetch_environmental_events(fetcher, days=7)
    assert result["source"] == "eonet"
    assert result["count"] == 1
    assert "Wildfire" in result["events"][0]["title"]


# ---------------------------------------------------------------------------
# Disaster Alerts (GDACS)
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_disaster_alerts(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.environmental import fetch_disaster_alerts

    gdacs_geojson = {
        "type": "FeatureCollection",
        "features": [{
            "type": "Feature",
            "properties": {
                "eventtype": "EQ",
                "eventname": "M6.5 Earthquake",
                "alertlevel": "orange",
                "alertscore": 2.5,
                "severity": {"value": 6.5, "unit": "M"},
                "country": "Turkey",
                "fromdate": "2026-02-20T12:00:00Z",
                "todate": "2026-02-20T12:05:00Z",
                "url": {"report": "https://gdacs.example.com/report"},
                "population": {"value": 500000},
            },
            "geometry": {"type": "Point", "coordinates": [29.0, 38.5]},
        }],
    }

    respx.get(url__regex=r".*gdacs\.org.*").mock(
        return_value=httpx.Response(200, json=gdacs_geojson)
    )

    result = await fetch_disaster_alerts(fetcher)
    assert result["source"] == "gdacs"
    assert result["count"] == 1
    assert result["alerts"][0]["event_type"] == "EQ"
    assert result["alerts"][0]["alert_level"] == "orange"


# ---------------------------------------------------------------------------
# Geospatial — Extended datasets (static, no HTTP mock needed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_undersea_cables() -> None:
    from world_intel_mcp.sources.geospatial import fetch_undersea_cables

    result = await fetch_undersea_cables()
    assert result["count"] > 0
    assert result["source"] == "static-geospatial"
    assert "total_length_km" in result
    assert "total_capacity_tbps" in result


@pytest.mark.asyncio
async def test_fetch_ai_datacenters() -> None:
    from world_intel_mcp.sources.geospatial import fetch_ai_datacenters

    result = await fetch_ai_datacenters(country="USA")
    assert result["count"] > 0
    assert result["source"] == "static-geospatial"
    assert "total_power_mw" in result


@pytest.mark.asyncio
async def test_fetch_spaceports() -> None:
    from world_intel_mcp.sources.geospatial import fetch_spaceports

    result = await fetch_spaceports()
    assert result["count"] > 0
    assert result["source"] == "static-geospatial"


@pytest.mark.asyncio
async def test_fetch_critical_minerals() -> None:
    from world_intel_mcp.sources.geospatial import fetch_critical_minerals

    result = await fetch_critical_minerals(mineral="lithium")
    assert result["count"] > 0
    assert all(d["mineral"] == "lithium" for d in result["deposits"])


@pytest.mark.asyncio
async def test_fetch_stock_exchanges() -> None:
    from world_intel_mcp.sources.geospatial import fetch_stock_exchanges

    result = await fetch_stock_exchanges(tier="mega")
    assert result["count"] > 0
    assert all(e["tier"] == "mega" for e in result["exchanges"])
    assert "total_market_cap_usd_t" in result


# ---------------------------------------------------------------------------
# Country Stocks
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_country_stocks(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.markets import fetch_country_stocks

    chart_response = {
        "chart": {
            "result": [{
                "meta": {
                    "symbol": "^GSPC",
                    "regularMarketPrice": 5200.0,
                    "regularMarketChangePercent": 0.75,
                    "currency": "USD",
                }
            }]
        }
    }

    respx.get(url__regex=r".*query1\.finance\.yahoo\.com.*").mock(
        return_value=httpx.Response(200, json=chart_response)
    )

    result = await fetch_country_stocks(fetcher, country="USA")
    assert result["source"] == "yahoo-finance"
    assert result["country"] == "USA"
    assert "quote" in result


# ---------------------------------------------------------------------------
# Aircraft Batch
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_aircraft_details_batch(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.military import fetch_aircraft_details_batch

    respx.get(url__regex=r".*hexdb\.io/api/v1/aircraft/ae1234.*").mock(
        return_value=httpx.Response(200, json={
            "Registration": "12-3456",
            "Type": "C-17A",
            "Operator": "USAF",
        })
    )
    respx.get(url__regex=r".*hexdb\.io/api/v1/aircraft/ae5678.*").mock(
        return_value=httpx.Response(200, json={
            "Registration": "78-9012",
            "Type": "KC-135R",
            "Operator": "USAF",
        })
    )

    result = await fetch_aircraft_details_batch(fetcher, icao24_list=["ae1234", "ae5678"])
    assert result["source"] == "hexdb"
    assert result["count"] == 2
    assert result["requested"] == 2


# ---------------------------------------------------------------------------
# BTC Technicals (CoinGecko)
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_btc_technicals(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.markets import fetch_btc_technicals

    # Generate 201 daily price points (enough for SMA-200)
    prices = [[1700000000 + i * 86400, 90000 + i * 10] for i in range(201)]

    respx.get("https://api.coingecko.com/api/v3/coins/bitcoin/market_chart").mock(
        return_value=httpx.Response(200, json={"prices": prices})
    )

    result = await fetch_btc_technicals(fetcher)
    assert result["source"] == "coingecko"
    assert result["price"] == prices[-1][1]
    assert result["sma_50"] > 0
    assert result["sma_200"] > 0
    assert result["mayer_multiple"] > 0
    assert result["cross_signal"] in ("golden_cross", "death_cross", "neutral")
    assert result["ath_distance_pct"] <= 0  # Current price <= ATH
    assert result["data_points"] == 201


@respx.mock
@pytest.mark.asyncio
async def test_fetch_btc_technicals_insufficient_data(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.markets import fetch_btc_technicals

    # Only 10 data points — not enough for SMA-50
    prices = [[1700000000 + i * 86400, 90000 + i * 10] for i in range(10)]

    respx.get("https://api.coingecko.com/api/v3/coins/bitcoin/market_chart").mock(
        return_value=httpx.Response(200, json={"prices": prices})
    )

    result = await fetch_btc_technicals(fetcher)
    assert "error" in result
    assert result["source"] == "coingecko"


# ---------------------------------------------------------------------------
# Central Bank Rates
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_central_bank_rates_no_fred(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.central_banks import fetch_central_bank_rates

    import os
    os.environ.pop("FRED_API_KEY", None)

    result = await fetch_central_bank_rates(fetcher)
    assert result["source"] == "multi"
    assert result["fred_available"] is False
    # Should have all 15 banks (12 curated + 3 FRED-fallback curated)
    assert result["count"] == 15
    # Sorted by rate descending — CBRT (45%) should be first
    assert result["rates"][0]["bank"] == "Central Bank of Turkey"
    assert result["rates"][0]["rate"] == 45.00
    # All should be curated source
    assert all(r["source"] == "curated" for r in result["rates"])


@respx.mock
@pytest.mark.asyncio
async def test_fetch_central_bank_rates_with_fred(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.central_banks import fetch_central_bank_rates

    import os
    os.environ["FRED_API_KEY"] = "test_key_123"

    fred_response = {
        "observations": [
            {"date": "2026-02-25", "value": "4.33"}
        ]
    }

    respx.get("https://api.stlouisfed.org/fred/series/observations").mock(
        return_value=httpx.Response(200, json=fred_response)
    )

    try:
        result = await fetch_central_bank_rates(fetcher)
        assert result["source"] == "multi"
        assert result["fred_available"] is True
        assert result["count"] == 15
        # At least some should be from FRED
        fred_sources = [r for r in result["rates"] if r["source"] == "fred"]
        assert len(fred_sources) >= 1
    finally:
        os.environ.pop("FRED_API_KEY", None)


# ---------------------------------------------------------------------------
# USNI Fleet Tracker
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_usni_fleet(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.usni_fleet import fetch_usni_fleet

    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
    <channel>
        <title>USNI News Fleet Tracker</title>
        <item>
            <title>USNI News Fleet and Marine Tracker: Feb. 24, 2026</title>
            <link>https://news.usni.org/2026/02/24/fleet-tracker</link>
            <pubDate>Mon, 24 Feb 2026 14:00:00 GMT</pubDate>
            <description>
            298 ships (237 USS, 61 USNS). 100 deployed (67 USS, 33 USNS). 72 underway (55 deployed, 17 local).
            Carrier Strike Group 3 is currently conducting routine operations in the Western Pacific theater of operations, focused on maintaining freedom of navigation and regional security.
            In the Philippine Sea, USS Abraham Lincoln (CVN-72) is conducting routine flight operations with embarked Carrier Air Wing Nine as part of a scheduled deployment to the Western Pacific region.
            Meanwhile in the Mediterranean Sea near the coast of southern Europe, USS Spruance (DDG-111) is operating independently as part of standing NATO maritime forces conducting presence operations.
            In the Persian Gulf near the Strait of Hormuz, Expeditionary Strike Group 7 continues its deployment supporting maritime security operations in the region.
            USS Bataan (LHD-5) continues operations in the Red Sea supporting regional stability efforts and conducting routine training exercises with coalition partners.
            </description>
        </item>
    </channel>
    </rss>"""

    respx.get("https://news.usni.org/category/fleet-tracker/feed").mock(
        return_value=httpx.Response(200, text=rss_xml)
    )

    result = await fetch_usni_fleet(fetcher)
    assert result["source"] == "usni-fleet-tracker"
    assert result["ship_count"] >= 3  # CVN-72, DDG-111, LHD-5
    assert result["report_title"] == "USNI News Fleet and Marine Tracker: Feb. 24, 2026"

    # Check ships were extracted
    hull_numbers = [s["hull_number"] for s in result["ships"]]
    assert "CVN-72" in hull_numbers
    assert "DDG-111" in hull_numbers
    assert "LHD-5" in hull_numbers

    # Check strike groups
    sg_names = [sg["name"] for sg in result["strike_groups"]]
    assert "CSG-3" in sg_names

    # Check force totals extracted
    assert result["force_totals"]["battle_force"]["total"] == 298
    assert result["force_totals"]["deployed"]["total"] == 100
    assert result["force_totals"]["underway"]["total"] == 72

    # Check region classification (±200 char context windows may overlap in short text,
    # but at least some ships should get classified to a known COCOM region)
    regions = set(s["region"] for s in result["ships"])
    assert len(regions - {"UNKNOWN"}) > 0  # At least one classified


@respx.mock
@pytest.mark.asyncio
async def test_fetch_usni_fleet_empty_feed(fetcher: Fetcher) -> None:
    from world_intel_mcp.sources.usni_fleet import fetch_usni_fleet

    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0"><channel><title>Empty</title></channel></rss>"""

    respx.get("https://news.usni.org/category/fleet-tracker/feed").mock(
        return_value=httpx.Response(200, text=rss_xml)
    )

    result = await fetch_usni_fleet(fetcher)
    assert result["source"] == "usni-fleet-tracker"
    assert "error" in result
    assert result["ship_count"] == 0


# ---------------------------------------------------------------------------
# Trade Routes (static — no HTTP mock needed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_trade_routes() -> None:
    from world_intel_mcp.sources.geospatial import fetch_trade_routes

    result = await fetch_trade_routes()
    assert result["source"] == "static-geospatial"
    assert result["count"] > 0
    assert result["total_oil_flow_mbd"] > 0
    assert "by_type" in result
    assert "chokepoint" in result["by_type"]


@pytest.mark.asyncio
async def test_fetch_trade_routes_filter_type() -> None:
    from world_intel_mcp.sources.geospatial import fetch_trade_routes

    result = await fetch_trade_routes(route_type="canal")
    assert result["source"] == "static-geospatial"
    assert result["count"] > 0
    assert all(r["type"] == "canal" for r in result["routes"])


@pytest.mark.asyncio
async def test_fetch_trade_routes_filter_country() -> None:
    from world_intel_mcp.sources.geospatial import fetch_trade_routes

    result = await fetch_trade_routes(country="EGY")
    assert result["source"] == "static-geospatial"
    assert result["count"] > 0
    assert all("EGY" in r["countries"] for r in result["routes"])


# ---------------------------------------------------------------------------
# Cloud Regions (static — no HTTP mock needed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_cloud_regions() -> None:
    from world_intel_mcp.sources.geospatial import fetch_cloud_regions

    result = await fetch_cloud_regions()
    assert result["source"] == "static-geospatial"
    assert result["count"] > 0
    assert "by_provider" in result
    assert "AWS" in result["by_provider"]


@pytest.mark.asyncio
async def test_fetch_cloud_regions_filter_provider() -> None:
    from world_intel_mcp.sources.geospatial import fetch_cloud_regions

    result = await fetch_cloud_regions(provider="GCP")
    assert result["source"] == "static-geospatial"
    assert result["count"] > 0
    assert all(r["provider"] == "GCP" for r in result["regions"])


# ---------------------------------------------------------------------------
# Financial Centers (static — no HTTP mock needed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_financial_centers() -> None:
    from world_intel_mcp.sources.geospatial import fetch_financial_centers

    result = await fetch_financial_centers()
    assert result["source"] == "static-geospatial"
    assert result["count"] > 0
    assert "by_country" in result


@pytest.mark.asyncio
async def test_fetch_financial_centers_filter_rank() -> None:
    from world_intel_mcp.sources.geospatial import fetch_financial_centers

    result = await fetch_financial_centers(min_rank=5)
    assert result["source"] == "static-geospatial"
    assert result["count"] > 0
    assert result["count"] <= 5
    assert all(fc["gfci_rank"] <= 5 for fc in result["centers"])


@pytest.mark.asyncio
async def test_fetch_financial_centers_filter_country() -> None:
    from world_intel_mcp.sources.geospatial import fetch_financial_centers

    result = await fetch_financial_centers(country="USA")
    assert result["source"] == "static-geospatial"
    assert result["count"] > 0
    assert all(fc["iso3"] == "USA" for fc in result["centers"])
