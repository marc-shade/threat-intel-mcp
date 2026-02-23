"""Report orchestrator for world-intel-mcp.

Gathers data from multiple intelligence sources in parallel and renders
HTML or Markdown reports via Jinja2 templates.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from ..cache import Cache
from ..circuit_breaker import CircuitBreaker
from ..fetcher import Fetcher
from ..sources import (
    markets, economic, seismology, wildfire, conflict, military,
    infrastructure, maritime, climate, news, intelligence,
    prediction, displacement, aviation, cyber,
)

logger = logging.getLogger("world-intel-mcp.reports.generator")

# Default output directory
_DEFAULT_OUTPUT_DIR = os.environ.get(
    "INTEL_REPORT_DIR",
    os.path.join(os.environ.get("STORAGE_BASE", "/tmp"), "reports", "intel"),
)


def _ensure_output_dir(path: str | None = None) -> Path:
    """Create output directory if needed and return Path."""
    output_dir = Path(path or _DEFAULT_OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


async def generate_daily_brief(output_dir: str | None = None) -> dict:
    """Generate a daily intelligence brief HTML report.

    Gathers: market quotes, macro signals, conflict events, cyber threats,
    earthquakes, wildfires, prediction markets, trending keywords.
    Renders to HTML and returns the file path + summary.
    """
    cache = Cache()
    breaker = CircuitBreaker()
    fetcher = Fetcher(cache=cache, breaker=breaker)

    try:
        # Gather all data in parallel
        (
            market_data,
            macro_data,
            conflict_data,
            cyber_data,
            quake_data,
            fire_data,
            predict_data,
            keyword_data,
        ) = await asyncio.gather(
            markets.fetch_market_quotes(fetcher),
            markets.fetch_macro_signals(fetcher),
            conflict.fetch_acled_events(fetcher, days=1, limit=50),
            cyber.fetch_cyber_threats(fetcher, limit=30),
            seismology.fetch_earthquakes(fetcher, min_magnitude=4.5, hours=24),
            wildfire.fetch_wildfires(fetcher),
            prediction.fetch_prediction_markets(fetcher, limit=10),
            news.fetch_trending_keywords(fetcher, min_count=3),
        )

        now = datetime.now(timezone.utc)
        context = {
            "title": "Daily Intelligence Brief",
            "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "market_summary": {
                "quotes": market_data.get("quotes", []),
                "macro_signals": macro_data.get("signals", {}),
            },
            "conflict_summary": {
                "events": conflict_data.get("events", []),
                "count": conflict_data.get("count", 0),
            },
            "cyber_summary": {
                "threats": cyber_data.get("threats", []),
                "by_severity": cyber_data.get("by_severity", {}),
            },
            "natural_summary": {
                "earthquakes": quake_data.get("earthquakes", []),
                "fire_count": fire_data.get("total_fires", 0),
            },
            "prediction_highlights": predict_data.get("markets", []),
            "trending_keywords": keyword_data.get("keywords", []),
        }

        # Render HTML
        from .html_report import render_template
        html = render_template("daily_brief.html", context)

        # Write to file
        out_dir = _ensure_output_dir(output_dir)
        filename = f"daily_brief_{now.strftime('%Y%m%d_%H%M%S')}.html"
        filepath = out_dir / filename
        filepath.write_text(html, encoding="utf-8")

        logger.info("Daily brief generated: %s", filepath)

        return {
            "report_type": "daily_brief",
            "file_path": str(filepath),
            "generated_at": context["generated_at"],
            "summary": {
                "market_quotes": len(context["market_summary"]["quotes"]),
                "conflict_events": context["conflict_summary"]["count"],
                "cyber_threats": len(context["cyber_summary"]["threats"]),
                "earthquakes": len(context["natural_summary"]["earthquakes"]),
                "predictions": len(context["prediction_highlights"]),
                "keywords": len(context["trending_keywords"]),
            },
        }
    finally:
        await fetcher.close()


async def generate_country_dossier(
    country_code: str,
    output_dir: str | None = None,
) -> dict:
    """Generate a country dossier HTML report."""
    cache = Cache()
    breaker = CircuitBreaker()
    fetcher = Fetcher(cache=cache, breaker=breaker)

    try:
        (
            brief_data,
            instability_data,
            conflict_data,
            displacement_data,
        ) = await asyncio.gather(
            intelligence.fetch_country_brief(fetcher, country_code=country_code),
            intelligence.fetch_instability_index(fetcher, country_code=country_code),
            conflict.fetch_acled_events(fetcher, country=country_code, days=30, limit=50),
            displacement.fetch_displacement_summary(fetcher),
        )

        now = datetime.now(timezone.utc)
        context = {
            "title": f"Country Dossier: {country_code}",
            "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "country_code": country_code,
            "brief": brief_data.get("brief", ""),
            "instability": {
                "instability_index": instability_data.get("instability_index", 0),
                "components": instability_data.get("components", {}),
                "risk_level": instability_data.get("risk_level", "unknown"),
            },
            "conflict_events": conflict_data.get("events", []),
            "displacement": {
                "by_origin": displacement_data.get("by_origin", []),
                "global_totals": displacement_data.get("global_totals", {}),
            },
            "economic": {
                "gdp": brief_data.get("data", {}).get("gdp", []),
                "inflation": brief_data.get("data", {}).get("inflation", []),
            },
        }

        from .html_report import render_template
        html = render_template("country_dossier.html", context)

        out_dir = _ensure_output_dir(output_dir)
        filename = f"dossier_{country_code}_{now.strftime('%Y%m%d_%H%M%S')}.html"
        filepath = out_dir / filename
        filepath.write_text(html, encoding="utf-8")

        logger.info("Country dossier generated: %s", filepath)

        return {
            "report_type": "country_dossier",
            "country_code": country_code,
            "file_path": str(filepath),
            "generated_at": context["generated_at"],
        }
    finally:
        await fetcher.close()


async def generate_threat_landscape(output_dir: str | None = None) -> dict:
    """Generate a threat landscape HTML report."""
    cache = Cache()
    breaker = CircuitBreaker()
    fetcher = Fetcher(cache=cache, breaker=breaker)

    try:
        (
            cyber_data,
            conflict_data,
            military_data,
            cable_data,
            outage_data,
        ) = await asyncio.gather(
            cyber.fetch_cyber_threats(fetcher, limit=50),
            conflict.fetch_acled_events(fetcher, days=7, limit=100),
            military.fetch_theater_posture(fetcher),
            infrastructure.fetch_cable_health(fetcher),
            infrastructure.fetch_internet_outages(fetcher),
        )

        now = datetime.now(timezone.utc)
        context = {
            "title": "Threat Landscape Report",
            "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cyber_threats": {
                "threats": cyber_data.get("threats", []),
                "by_severity": cyber_data.get("by_severity", {}),
                "by_type": cyber_data.get("by_type", {}),
            },
            "conflict_events": conflict_data.get("events", []),
            "military_activity": {
                "theaters": military_data.get("theaters", {}),
                "total_military_aircraft": military_data.get("total_military_aircraft", 0),
            },
            "cable_health": {
                "corridors": cable_data.get("corridors", {}),
            },
            "outages": {
                "outages": outage_data.get("outages", []),
                "ongoing_count": outage_data.get("ongoing_count", 0),
            },
        }

        from .html_report import render_template
        html = render_template("threat_landscape.html", context)

        out_dir = _ensure_output_dir(output_dir)
        filename = f"threat_landscape_{now.strftime('%Y%m%d_%H%M%S')}.html"
        filepath = out_dir / filename
        filepath.write_text(html, encoding="utf-8")

        logger.info("Threat landscape generated: %s", filepath)

        return {
            "report_type": "threat_landscape",
            "file_path": str(filepath),
            "generated_at": context["generated_at"],
        }
    finally:
        await fetcher.close()


async def generate_market_overview(output_dir: str | None = None) -> dict:
    """Generate a market overview HTML report."""
    cache = Cache()
    breaker = CircuitBreaker()
    fetcher = Fetcher(cache=cache, breaker=breaker)

    try:
        (
            quote_data,
            crypto_data,
            macro_data,
            sector_data,
            etf_data,
        ) = await asyncio.gather(
            markets.fetch_market_quotes(fetcher),
            markets.fetch_crypto_quotes(fetcher, limit=20),
            markets.fetch_macro_signals(fetcher),
            markets.fetch_sector_heatmap(fetcher),
            markets.fetch_etf_flows(fetcher),
        )

        now = datetime.now(timezone.utc)
        context = {
            "title": "Market Overview",
            "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "quotes": quote_data.get("quotes", []),
            "crypto": crypto_data.get("coins", []),
            "macro_signals": macro_data.get("signals", {}),
            "sector_heatmap": sector_data.get("sectors", []),
            "etf_flows": etf_data,
        }

        from .html_report import render_template
        html = render_template("market_overview.html", context)

        out_dir = _ensure_output_dir(output_dir)
        filename = f"market_overview_{now.strftime('%Y%m%d_%H%M%S')}.html"
        filepath = out_dir / filename
        filepath.write_text(html, encoding="utf-8")

        logger.info("Market overview generated: %s", filepath)

        return {
            "report_type": "market_overview",
            "file_path": str(filepath),
            "generated_at": context["generated_at"],
        }
    finally:
        await fetcher.close()
