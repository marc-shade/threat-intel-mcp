"""Tests for the PDF/HTML intelligence report generator."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from world_intel_mcp.reports import (
    _build_html,
    _esc,
    _fmt_num,
    _change_class,
    _render_markets,
    _render_earthquakes,
    _render_conflicts,
    _render_news_clusters,
    _render_alerts,
    _render_posture,
    _render_infrastructure,
    _render_cyber,
    _render_health,
    _render_maritime,
    _render_situation_brief,
    _render_key_value,
    _collect_report_data,
    _safe_fetch,
    pdf_dependencies_available,
    generate_report,
)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


class TestEsc:
    def test_none(self):
        assert _esc(None) == ""

    def test_html_chars(self):
        assert (
            _esc('<script>"alert&"</script>')
            == "&lt;script&gt;&quot;alert&amp;&quot;&lt;/script&gt;"
        )

    def test_plain(self):
        assert _esc("hello world") == "hello world"

    def test_number(self):
        assert _esc(42) == "42"


class TestFmtNum:
    def test_none(self):
        assert _fmt_num(None) == "N/A"

    def test_integer(self):
        assert _fmt_num(1234567, 0) == "1,234,567"

    def test_float(self):
        assert _fmt_num(1234.567, 2) == "1,234.57"

    def test_string(self):
        assert _fmt_num("not a number") == "not a number"


class TestChangeClass:
    def test_positive(self):
        assert _change_class(1.5) == "green"

    def test_negative(self):
        assert _change_class(-0.5) == "red"

    def test_zero(self):
        assert _change_class(0) == ""

    def test_none(self):
        assert _change_class(None) == ""


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------


class TestRenderMarkets:
    def test_no_data(self):
        assert "unavailable" in _render_markets({})

    def test_with_quotes(self):
        data = {
            "quotes": [
                {
                    "shortName": "S&P 500",
                    "regularMarketPrice": 4500.12,
                    "regularMarketChangePercent": 1.23,
                },
                {
                    "symbol": "DJI",
                    "regularMarketPrice": 35000.0,
                    "regularMarketChangePercent": -0.45,
                },
            ]
        }
        html = _render_markets(data)
        assert "S&amp;P 500" in html
        assert "4,500.12" in html
        assert "+1.23%" in html
        assert "green" in html
        assert "red" in html


class TestRenderEarthquakes:
    def test_no_data(self):
        assert "No significant" in _render_earthquakes({})

    def test_with_quakes(self):
        data = {
            "earthquakes": [
                {
                    "properties": {
                        "mag": 5.2,
                        "place": "Near Tokyo",
                        "time": 1700000000000,
                    }
                },
            ]
        }
        html = _render_earthquakes(data)
        assert "5.2" in html
        assert "Near Tokyo" in html


class TestRenderConflicts:
    def test_no_data(self):
        assert "No recent" in _render_conflicts({})

    def test_with_events(self):
        data = {
            "events": [
                {
                    "event_type": "Battle",
                    "country": "Ukraine",
                    "fatalities": 5,
                    "event_date": "2025-01-01",
                    "notes": "Test event",
                },
            ]
        }
        html = _render_conflicts(data)
        assert "Battle" in html
        assert "Ukraine" in html


class TestRenderNewsClusters:
    def test_no_data(self):
        assert "No news clusters" in _render_news_clusters({})

    def test_with_clusters(self):
        data = {"clusters": [{"label": "Climate Summit", "article_count": 42}]}
        html = _render_news_clusters(data)
        assert "Climate Summit" in html
        assert "42" in html


class TestRenderAlerts:
    def test_no_data(self):
        assert "No active alerts" in _render_alerts({})

    def test_with_alerts(self):
        data = {
            "alerts": [
                {
                    "severity": "critical",
                    "title": "Major Quake",
                    "detail": "M7.2 event detected",
                },
                {
                    "severity": "info",
                    "title": "Minor Issue",
                    "description": "Low impact",
                },
            ]
        }
        html = _render_alerts(data)
        assert "critical" in html
        assert "Major Quake" in html


class TestRenderPosture:
    def test_no_data(self):
        assert "unavailable" in _render_posture({})

    def test_with_data(self):
        data = {
            "overall_assessment": "Tensions elevated in multiple regions.",
            "threat_level": "HIGH",
            "regions": {"Europe": "NATO exercises ongoing"},
        }
        html = _render_posture(data)
        assert "HIGH" in html
        assert "red" in html
        assert "Europe" in html


class TestRenderInfrastructure:
    def test_no_data(self):
        assert "No infrastructure" in _render_infrastructure({})

    def test_with_outages(self):
        data = {"outages": [{"entity": "AS12345", "score": 85, "source": "IODA"}]}
        html = _render_infrastructure(data)
        assert "AS12345" in html


class TestRenderCyber:
    def test_no_data(self):
        assert "No recent cyber" in _render_cyber({})

    def test_with_threats(self):
        data = {
            "recent_threats": [
                {"name": "Emotet", "type": "malware", "url": "https://example.com"}
            ]
        }
        html = _render_cyber(data)
        assert "Emotet" in html


class TestRenderHealth:
    def test_no_data(self):
        assert "No active disease" in _render_health({})

    def test_with_outbreaks(self):
        data = {
            "outbreaks": [{"disease": "Mpox", "country": "DRC", "date": "2025-01-15"}]
        }
        html = _render_health(data)
        assert "Mpox" in html


class TestRenderMaritime:
    def test_no_data(self):
        assert "No maritime" in _render_maritime({})

    def test_with_vessels(self):
        data = {"vessels": [{"name": "USS Nimitz", "type": "CVN", "flag": "US"}]}
        html = _render_maritime(data)
        assert "USS Nimitz" in html


class TestRenderSituationBrief:
    def test_no_data(self):
        assert "unavailable" in _render_situation_brief({})

    def test_with_brief(self):
        data = {
            "brief": "Global tensions remain elevated with multiple hotspots active."
        }
        html = _render_situation_brief(data)
        assert "Global tensions" in html


class TestRenderKeyValue:
    def test_no_data(self):
        assert "unavailable" in _render_key_value({})

    def test_with_data(self):
        html = _render_key_value(
            {"metric1": 42, "metric2": "active", "source": "should_skip"}
        )
        assert "metric1" in html
        assert "42" in html
        assert "source" not in html  # filtered out


# ---------------------------------------------------------------------------
# HTML assembly
# ---------------------------------------------------------------------------


class TestBuildHtml:
    def test_basic_structure(self):
        data = {"markets": {"quotes": []}, "world_brief": {"brief": "Test brief"}}
        html = _build_html(data)
        assert "<!DOCTYPE html>" in html
        assert "World Intelligence Report" in html
        assert "Executive Summary" in html
        assert "Financial Markets" in html

    def test_custom_title(self):
        html = _build_html({}, title="Custom Report")
        assert "Custom Report" in html

    def test_all_sections(self):
        data = {
            "world_brief": {"brief": "test"},
            "strategic_posture": {"overall_assessment": "test", "threat_level": "LOW"},
            "alerts": {"alerts": []},
            "markets": {"quotes": []},
            "economic": {"key": "val"},
            "conflicts": {"events": []},
            "military": {"data": "val"},
            "earthquakes": {"earthquakes": []},
            "infrastructure": {"outages": []},
            "cyber": {"recent_threats": []},
            "maritime": {"vessels": []},
            "health": {"outbreaks": []},
            "nuclear": {"sites": []},
            "climate": {"zones": {}},
            "news": {"clusters": []},
            "shipping": {"quotes": []},
            "service_status": {"services": []},
        }
        html = _build_html(data)
        assert "Executive Summary" in html
        assert "Strategic Posture" in html
        assert "Financial Markets" in html
        assert "Cyber Threats" in html


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------


class TestSafeFetch:
    @pytest.mark.asyncio
    async def test_success(self):
        async def good_fn():
            return {"result": "ok"}

        result = await _safe_fetch("test", good_fn)
        assert result == {"result": "ok"}

    @pytest.mark.asyncio
    async def test_failure(self):
        async def bad_fn():
            raise ValueError("boom")

        result = await _safe_fetch("test", bad_fn)
        assert "error" in result
        assert "boom" in result["error"]

    @pytest.mark.asyncio
    async def test_non_dict_result(self):
        async def list_fn():
            return [1, 2, 3]

        result = await _safe_fetch("test", list_fn)
        assert result == {"data": [1, 2, 3]}


class TestCollectReportData:
    @pytest.mark.asyncio
    async def test_section_filter(self):
        with patch("world_intel_mcp.reports.markets") as mock_markets:
            mock_markets.fetch_market_quotes = AsyncMock(return_value={"quotes": []})

            data = await _collect_report_data(
                MagicMock(),
                sections=["markets"],
            )
            assert "markets" in data
            assert "earthquakes" not in data

    @pytest.mark.asyncio
    async def test_handles_failures(self):
        with patch("world_intel_mcp.reports.markets") as mock_markets:
            mock_markets.fetch_market_quotes = AsyncMock(
                side_effect=RuntimeError("api down")
            )

            data = await _collect_report_data(MagicMock(), sections=["markets"])
            assert "error" in data["markets"]


# ---------------------------------------------------------------------------
# PDF dependency check
# ---------------------------------------------------------------------------


class TestPdfDependencies:
    def test_check(self):
        # Just verify it returns a bool without crashing
        result = pdf_dependencies_available()
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# Report generation (HTML mode — no weasyprint needed)
# ---------------------------------------------------------------------------


class TestGenerateReport:
    @pytest.mark.asyncio
    async def test_html_output(self, tmp_path):
        output = tmp_path / "test_report.html"

        with patch("world_intel_mcp.reports._collect_report_data") as mock_collect:
            mock_collect.return_value = {
                "markets": {
                    "quotes": [
                        {
                            "shortName": "SPX",
                            "regularMarketPrice": 4500,
                            "regularMarketChangePercent": 0.5,
                        }
                    ]
                },
            }

            fetcher = MagicMock()
            result = await generate_report(fetcher, output_path=output, fmt="html")

        assert result["format"] == "html"
        assert result["path"] == str(output)
        assert result["size_bytes"] > 0
        assert "markets" in result["sections_included"]
        assert output.exists()

        content = output.read_text()
        assert "<!DOCTYPE html>" in content
        assert "SPX" in content

    @pytest.mark.asyncio
    async def test_default_output_path(self, tmp_path):
        with patch("world_intel_mcp.reports._collect_report_data") as mock_collect:
            mock_collect.return_value = {"markets": {"quotes": []}}

            with patch("world_intel_mcp.reports.Path.home", return_value=tmp_path):
                fetcher = MagicMock()
                result = await generate_report(fetcher, fmt="html")

        assert result["format"] == "html"
        assert "report-" in result["path"]

    @pytest.mark.asyncio
    async def test_sections_tracking(self, tmp_path):
        output = tmp_path / "test.html"

        with patch("world_intel_mcp.reports._collect_report_data") as mock_collect:
            mock_collect.return_value = {
                "markets": {"quotes": []},
                "earthquakes": {"error": "api down"},
            }

            result = await generate_report(MagicMock(), output_path=output, fmt="html")

        assert "markets" in result["sections_included"]
        assert "earthquakes" in result["sections_failed"]

    @pytest.mark.asyncio
    async def test_pdf_without_weasyprint(self, tmp_path):
        output = tmp_path / "test.pdf"

        with patch(
            "world_intel_mcp.reports.pdf_dependencies_available", return_value=False
        ):
            with patch("world_intel_mcp.reports._collect_report_data") as mock_collect:
                mock_collect.return_value = {"markets": {"quotes": []}}

                result = await generate_report(
                    MagicMock(), output_path=output, fmt="pdf"
                )

        assert "error" in result
        assert "WeasyPrint" in result["error"]

    @pytest.mark.asyncio
    async def test_custom_title(self, tmp_path):
        output = tmp_path / "custom.html"

        with patch("world_intel_mcp.reports._collect_report_data") as mock_collect:
            mock_collect.return_value = {}

            result = await generate_report(
                MagicMock(), output_path=output, title="Daily Brief", fmt="html"
            )

        content = output.read_text()
        assert "Daily Brief" in content
