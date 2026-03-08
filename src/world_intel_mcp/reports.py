"""PDF intelligence report generator.

Renders multi-domain intelligence summaries as styled PDF documents
using WeasyPrint. Data is pulled from the same source modules and
analysis engines used by the MCP server and dashboard.

Optional dependency: ``pip install -e ".[pdf]"`` (weasyprint>=62.0).
Requires native pango/gobject libs (``brew install pango`` on macOS).
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .cache import Cache
from .circuit_breaker import CircuitBreaker
from .fetcher import Fetcher
from .sources import (
    markets,
    seismology,
    military,
    infrastructure,
    intelligence,  # noqa: F401
    wildfire,
    cyber,
    climate,
    conflict,
    health,
    shipping,
    nuclear,
    service_status,
)
from .analysis.alerts import fetch_alert_digest
from .analysis.clustering import fetch_news_clusters  # noqa: F401
from .analysis.posture import fetch_strategic_posture
from .analysis.world_brief import fetch_world_brief  # noqa: F401

logger = logging.getLogger("world-intel-mcp.reports")

# ---------------------------------------------------------------------------
# HTML template for the PDF report
# ---------------------------------------------------------------------------

_CSS = """\
@page {
    size: A4;
    margin: 1.5cm 1.8cm;
    @bottom-center { content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color: #888; }
    @top-right { content: "WORLD INTELLIGENCE REPORT"; font-size: 7pt; color: #aaa; letter-spacing: 1px; }
}
* { box-sizing: border-box; }
body {
    font-family: -apple-system, 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-size: 9pt;
    line-height: 1.45;
    color: #1a1a2e;
    margin: 0;
}
h1 {
    font-size: 22pt;
    margin: 0 0 4pt;
    color: #0f0f23;
    letter-spacing: -0.5px;
}
.subtitle {
    font-size: 10pt;
    color: #555;
    margin-bottom: 14pt;
    border-bottom: 2px solid #0f0f23;
    padding-bottom: 8pt;
}
h2 {
    font-size: 13pt;
    color: #16213e;
    margin: 16pt 0 6pt;
    padding-bottom: 3pt;
    border-bottom: 1px solid #ddd;
    page-break-after: avoid;
}
h3 {
    font-size: 10pt;
    color: #1a1a2e;
    margin: 10pt 0 4pt;
    page-break-after: avoid;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin: 6pt 0 10pt;
    font-size: 8.5pt;
    page-break-inside: avoid;
}
th {
    background: #16213e;
    color: white;
    padding: 4pt 6pt;
    text-align: left;
    font-weight: 600;
    font-size: 8pt;
}
td {
    padding: 3pt 6pt;
    border-bottom: 1px solid #eee;
    vertical-align: top;
}
tr:nth-child(even) td { background: #f8f9fa; }
.alert-box {
    background: #fff3cd;
    border-left: 4px solid #ffc107;
    padding: 6pt 10pt;
    margin: 6pt 0;
    font-size: 8.5pt;
    page-break-inside: avoid;
}
.alert-box.critical {
    background: #f8d7da;
    border-left-color: #dc3545;
}
.metric {
    display: inline-block;
    background: #e8eaf6;
    border-radius: 3pt;
    padding: 2pt 8pt;
    margin: 2pt 4pt 2pt 0;
    font-size: 8pt;
    font-weight: 600;
}
.metric.green { background: #d4edda; color: #155724; }
.metric.red { background: #f8d7da; color: #721c24; }
.metric.amber { background: #fff3cd; color: #856404; }
.section-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 8pt;
}
.section-card {
    flex: 1 1 45%;
    border: 1px solid #dee2e6;
    border-radius: 4pt;
    padding: 6pt 8pt;
    page-break-inside: avoid;
}
.footer {
    margin-top: 20pt;
    padding-top: 8pt;
    border-top: 1px solid #ccc;
    font-size: 7pt;
    color: #999;
    text-align: center;
}
.no-data { color: #999; font-style: italic; font-size: 8pt; }
"""


def _esc(text: Any) -> str:
    """Escape HTML special chars."""
    if text is None:
        return ""
    s = str(text)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _fmt_num(val: Any, decimals: int = 2) -> str:
    """Format a number with commas."""
    if val is None:
        return "N/A"
    try:
        f = float(val)
        if f == int(f) and decimals == 0:
            return f"{int(f):,}"
        return f"{f:,.{decimals}f}"
    except (ValueError, TypeError):
        return str(val)


def _change_class(val: Any) -> str:
    """Return CSS class based on +/- value."""
    try:
        v = float(val)
        if v > 0:
            return "green"
        elif v < 0:
            return "red"
    except (ValueError, TypeError):
        pass
    return ""


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------


def _render_markets(data: dict) -> str:
    """Render market quotes section."""
    quotes = data.get("quotes") or data.get("indices") or []
    if not quotes:
        return '<p class="no-data">Market data unavailable</p>'

    rows = []
    for q in quotes[:15]:
        name = _esc(q.get("shortName") or q.get("symbol", ""))
        price = _fmt_num(q.get("regularMarketPrice"))
        chg = q.get("regularMarketChangePercent")
        chg_str = f"{float(chg):+.2f}%" if chg is not None else "N/A"
        cls = _change_class(chg)
        rows.append(
            f'<tr><td>{name}</td><td>{price}</td><td><span class="metric {cls}">{chg_str}</span></td></tr>'
        )

    return f"""
    <table>
        <tr><th>Index / Symbol</th><th>Price</th><th>Change</th></tr>
        {"".join(rows)}
    </table>"""


def _render_earthquakes(data: dict) -> str:
    """Render seismology section."""
    quakes = data.get("earthquakes", [])
    if not quakes:
        return '<p class="no-data">No significant seismic activity</p>'

    rows = []
    for q in quakes[:10]:
        props = q.get("properties", {})
        mag = _fmt_num(props.get("mag"), 1)
        place = _esc(props.get("place", "Unknown"))
        t = props.get("time")
        time_str = (
            datetime.fromtimestamp(t / 1000, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            )
            if t
            else ""
        )
        rows.append(f"<tr><td>{mag}</td><td>{place}</td><td>{time_str}</td></tr>")

    return f"""
    <table>
        <tr><th>Mag</th><th>Location</th><th>Time</th></tr>
        {"".join(rows)}
    </table>"""


def _render_conflicts(data: dict) -> str:
    """Render conflict events section."""
    events = data.get("events", [])
    if not events:
        return '<p class="no-data">No recent conflict events</p>'

    rows = []
    for e in events[:12]:
        etype = _esc(e.get("event_type", ""))
        country = _esc(e.get("country", ""))
        fatalities = e.get("fatalities", 0)
        date = _esc(e.get("event_date", ""))
        notes = _esc(str(e.get("notes", ""))[:120])
        rows.append(
            f"<tr><td>{etype}</td><td>{country}</td><td>{fatalities}</td><td>{date}</td><td>{notes}</td></tr>"
        )

    return f"""
    <table>
        <tr><th>Type</th><th>Country</th><th>Fatal.</th><th>Date</th><th>Notes</th></tr>
        {"".join(rows)}
    </table>"""


def _render_news_clusters(data: dict) -> str:
    """Render top news clusters."""
    clusters = data.get("clusters", [])
    if not clusters:
        return '<p class="no-data">No news clusters available</p>'

    items = []
    for c in clusters[:8]:
        title = _esc(c.get("label") or c.get("title", ""))
        count = c.get("article_count", c.get("count", ""))
        items.append(f"<li><strong>{title}</strong> ({count} articles)</li>")
    return f"<ul>{''.join(items)}</ul>"


def _render_alerts(data: dict) -> str:
    """Render alert digest."""
    alerts = data.get("alerts", [])
    if not alerts:
        return '<p class="no-data">No active alerts</p>'

    boxes = []
    for a in alerts[:10]:
        severity = a.get("severity", "info")
        css = "critical" if severity in ("critical", "high") else ""
        title = _esc(a.get("title", a.get("type", "")))
        detail = _esc(str(a.get("detail", a.get("description", "")))[:200])
        boxes.append(
            f'<div class="alert-box {css}"><strong>{title}</strong><br>{detail}</div>'
        )
    return "".join(boxes)


def _render_posture(data: dict) -> str:
    """Render strategic posture summary."""
    assessment = data.get("overall_assessment") or data.get("summary", "")
    if not assessment:
        return '<p class="no-data">Posture data unavailable</p>'

    level = _esc(data.get("threat_level", data.get("risk_level", "")))
    cls = (
        "red"
        if "high" in level.lower()
        else "amber"
        if "medium" in level.lower()
        else "green"
    )

    html = f'<span class="metric {cls}">Threat Level: {level}</span>'
    html += f"<p>{_esc(str(assessment)[:500])}</p>"

    regions = data.get("regional_assessments") or data.get("regions", {})
    if regions and isinstance(regions, dict):
        html += "<h3>Regional Breakdown</h3><ul>"
        for region, detail in list(regions.items())[:6]:
            summary = (
                detail
                if isinstance(detail, str)
                else detail.get("summary", str(detail))
            )
            html += (
                f"<li><strong>{_esc(region)}</strong>: {_esc(str(summary)[:150])}</li>"
            )
        html += "</ul>"
    return html


def _render_infrastructure(data: dict) -> str:
    """Render infrastructure status."""
    outages = data.get("outages", data.get("entries", []))
    if not outages:
        return '<p class="no-data">No infrastructure disruptions detected</p>'

    rows = []
    for o in outages[:8]:
        name = _esc(o.get("entity") or o.get("name", ""))
        score = o.get("score") or o.get("severity", "")
        source = _esc(o.get("source", ""))
        rows.append(f"<tr><td>{name}</td><td>{score}</td><td>{source}</td></tr>")

    return f"""
    <table>
        <tr><th>Entity</th><th>Score / Severity</th><th>Source</th></tr>
        {"".join(rows)}
    </table>"""


def _render_cyber(data: dict) -> str:
    """Render cyber threat intelligence."""
    threats = data.get("recent_threats") or data.get("threats", [])
    if not threats:
        return '<p class="no-data">No recent cyber threats</p>'

    rows = []
    for t in threats[:8]:
        name = _esc(t.get("name") or t.get("tag", ""))
        ttype = _esc(t.get("type", ""))
        url = _esc(t.get("url", ""))
        rows.append(f"<tr><td>{name}</td><td>{ttype}</td><td>{url[:60]}</td></tr>")

    return f"""
    <table>
        <tr><th>Threat</th><th>Type</th><th>Reference</th></tr>
        {"".join(rows)}
    </table>"""


def _render_health(data: dict) -> str:
    """Render health/disease outbreak data."""
    outbreaks = data.get("outbreaks") or data.get("events", [])
    if not outbreaks:
        return '<p class="no-data">No active disease outbreaks</p>'

    rows = []
    for o in outbreaks[:8]:
        disease = _esc(o.get("disease") or o.get("title", ""))
        country = _esc(o.get("country", ""))
        date = _esc(o.get("date", ""))
        rows.append(f"<tr><td>{disease}</td><td>{country}</td><td>{date}</td></tr>")

    return f"""
    <table>
        <tr><th>Disease/Event</th><th>Location</th><th>Date</th></tr>
        {"".join(rows)}
    </table>"""


def _render_maritime(data: dict) -> str:
    """Render maritime overview."""
    vessels = data.get("vessels") or data.get("snapshot", [])
    if not vessels:
        return '<p class="no-data">No maritime data</p>'

    rows = []
    items = vessels if isinstance(vessels, list) else [vessels]
    for v in items[:8]:
        name = _esc(v.get("name") or v.get("vessel_name", ""))
        vtype = _esc(v.get("type") or v.get("ship_type", ""))
        flag = _esc(v.get("flag", ""))
        rows.append(f"<tr><td>{name}</td><td>{vtype}</td><td>{flag}</td></tr>")

    return f"""
    <table>
        <tr><th>Vessel</th><th>Type</th><th>Flag</th></tr>
        {"".join(rows)}
    </table>"""


def _render_situation_brief(data: dict) -> str:
    """Render situation brief / world brief."""
    brief = data.get("brief") or data.get("summary", "")
    if not brief:
        return '<p class="no-data">Brief unavailable</p>'
    return f"<p>{_esc(str(brief)[:1000])}</p>"


def _render_key_value(data: dict, keys: list[str] | None = None) -> str:
    """Generic key-value renderer for simple dicts."""
    if not data:
        return '<p class="no-data">Data unavailable</p>'

    items = []
    show_keys = keys or list(data.keys())[:20]
    for k in show_keys:
        v = data.get(k)
        if v is not None and k not in (
            "source",
            "cached",
            "cache_age_seconds",
            "fetched_at",
        ):
            items.append(f"<li><strong>{_esc(k)}</strong>: {_esc(str(v)[:200])}</li>")
    return f"<ul>{''.join(items)}</ul>" if items else '<p class="no-data">No data</p>'


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------


async def _collect_report_data(
    fetcher: Fetcher,
    sections: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch data for all report sections in parallel.

    Args:
        fetcher: Configured Fetcher instance.
        sections: Optional list of section names to include.
                  Default: all sections.
    """
    all_sections = {
        "world_brief": lambda: fetch_world_brief(fetcher),
        "strategic_posture": lambda: fetch_strategic_posture(fetcher),
        "alerts": lambda: fetch_alert_digest(fetcher),
        "markets": lambda: markets.fetch_market_quotes(fetcher),
        "economic": lambda: markets.fetch_macro_signals(fetcher),
        "earthquakes": lambda: seismology.fetch_earthquakes(
            fetcher, min_magnitude=4.5, hours=24
        ),
        "wildfires": lambda: wildfire.fetch_wildfires(fetcher),
        "conflicts": lambda: conflict.fetch_acled_events(fetcher, limit=15),
        "military": lambda: military.fetch_military_flights(fetcher),
        "infrastructure": lambda: infrastructure.fetch_internet_outages(fetcher),
        "maritime": lambda: intelligence.fetch_vessel_snapshot(fetcher),
        "cyber": lambda: cyber.fetch_cyber_threats(fetcher),
        "health": lambda: health.fetch_disease_outbreaks(fetcher),
        "news": lambda: fetch_news_clusters(fetcher),
        "climate": lambda: climate.fetch_climate_anomalies(fetcher),
        "nuclear": lambda: nuclear.fetch_nuclear_monitor(fetcher),
        "shipping": lambda: shipping.fetch_shipping_index(fetcher),
        "service_status": lambda: service_status.fetch_service_status(fetcher),
    }

    if sections:
        all_sections = {k: v for k, v in all_sections.items() if k in sections}

    results: dict[str, Any] = {}
    tasks = {}
    for name, fn in all_sections.items():
        tasks[name] = asyncio.create_task(_safe_fetch(name, fn))

    for name, task in tasks.items():
        results[name] = await task

    return results


async def _safe_fetch(name: str, fn) -> dict:
    """Wrap a fetch call with error handling."""
    try:
        result = await fn()
        return result if isinstance(result, dict) else {"data": result}
    except Exception as exc:
        logger.warning("Report section '%s' failed: %s", name, exc)
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# HTML assembly
# ---------------------------------------------------------------------------


def _build_html(data: dict[str, Any], title: str | None = None) -> str:
    """Assemble the full HTML document from collected data."""
    now = datetime.now(timezone.utc)
    report_title = title or "World Intelligence Report"
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")

    sections_html = []

    # Executive summary (world brief)
    if "world_brief" in data:
        sections_html.append(
            f"<h2>Executive Summary</h2>{_render_situation_brief(data['world_brief'])}"
        )

    # Strategic posture
    if "strategic_posture" in data:
        sections_html.append(
            f"<h2>Strategic Posture</h2>{_render_posture(data['strategic_posture'])}"
        )

    # Alerts
    if "alerts" in data:
        sections_html.append(f"<h2>Active Alerts</h2>{_render_alerts(data['alerts'])}")

    # Markets
    if "markets" in data:
        sections_html.append(
            f"<h2>Financial Markets</h2>{_render_markets(data['markets'])}"
        )

    # Economic
    if "economic" in data:
        sections_html.append(
            f"<h2>Economic Indicators</h2>{_render_key_value(data['economic'])}"
        )

    # Conflicts
    if "conflicts" in data:
        sections_html.append(
            f"<h2>Conflict & Security</h2>{_render_conflicts(data['conflicts'])}"
        )

    # Military
    if "military" in data:
        sections_html.append(
            f"<h2>Military Activity</h2>{_render_key_value(data['military'])}"
        )

    # Earthquakes
    if "earthquakes" in data:
        sections_html.append(
            f"<h2>Seismology</h2>{_render_earthquakes(data['earthquakes'])}"
        )

    # Infrastructure
    if "infrastructure" in data:
        sections_html.append(
            f"<h2>Infrastructure</h2>{_render_infrastructure(data['infrastructure'])}"
        )

    # Cyber
    if "cyber" in data:
        sections_html.append(f"<h2>Cyber Threats</h2>{_render_cyber(data['cyber'])}")

    # Maritime
    if "maritime" in data:
        sections_html.append(f"<h2>Maritime</h2>{_render_maritime(data['maritime'])}")

    # Health
    if "health" in data:
        sections_html.append(
            f"<h2>Health & Disease</h2>{_render_health(data['health'])}"
        )

    # Nuclear
    if "nuclear" in data:
        sections_html.append(
            f"<h2>Nuclear Monitoring</h2>{_render_key_value(data['nuclear'])}"
        )

    # Climate
    if "climate" in data:
        sections_html.append(
            f"<h2>Climate & Environment</h2>{_render_key_value(data['climate'])}"
        )

    # News
    if "news" in data:
        sections_html.append(
            f"<h2>News Clusters</h2>{_render_news_clusters(data['news'])}"
        )

    # Shipping
    if "shipping" in data:
        sections_html.append(f"<h2>Shipping</h2>{_render_key_value(data['shipping'])}")

    # Service status
    if "service_status" in data:
        sections_html.append(
            f"<h2>Cloud & Service Status</h2>{_render_key_value(data['service_status'])}"
        )

    body = "\n".join(sections_html)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <style>{_CSS}</style>
</head>
<body>
    <h1>{_esc(report_title)}</h1>
    <div class="subtitle">Generated {timestamp} &mdash; World Intel MCP &mdash; 109 intelligence sources</div>
    {body}
    <div class="footer">
        World Intelligence MCP Server &mdash; github.com/marc-shade/world-intel-mcp<br>
        Report generated {timestamp}. Data sourced from public APIs.
    </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def pdf_dependencies_available() -> bool:
    """Check if weasyprint is importable."""
    try:
        from importlib.util import find_spec

        return find_spec("weasyprint") is not None
    except Exception:
        return False


async def generate_report(
    fetcher: Fetcher,
    output_path: str | Path | None = None,
    title: str | None = None,
    sections: list[str] | None = None,
    fmt: str = "pdf",
) -> dict[str, Any]:
    """Generate an intelligence report.

    Args:
        fetcher: Configured Fetcher instance.
        output_path: Where to write the file. Default: ``~/.cache/world-intel-mcp/report-<timestamp>.pdf``
        title: Report title.
        sections: List of section names to include (default: all).
        fmt: Output format — ``pdf`` or ``html``.

    Returns:
        Dict with path, format, sections included, generation time.
    """
    t0 = time.time()

    # Collect data
    data = await _collect_report_data(fetcher, sections)

    # Build HTML
    html = _build_html(data, title)

    # Determine output path
    if output_path is None:
        cache_dir = Path.home() / ".cache" / "world-intel-mcp"
        cache_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        ext = "pdf" if fmt == "pdf" else "html"
        output_path = cache_dir / f"report-{ts}.{ext}"
    else:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "pdf":
        if not pdf_dependencies_available():
            return {
                "error": 'WeasyPrint not installed. Install with `pip install -e ".[pdf]"`.',
                "fallback": "Use fmt='html' for HTML output without WeasyPrint.",
            }
        # Import inside the function to avoid import-time failures
        from weasyprint import HTML as WeasyHTML

        pdf_bytes: bytes = await asyncio.to_thread(
            lambda: WeasyHTML(string=html).write_pdf()  # type: ignore[return-value]
        )
        output_path.write_bytes(pdf_bytes)
    else:
        output_path.write_text(html, encoding="utf-8")

    elapsed = time.time() - t0
    sections_included = [k for k, v in data.items() if "error" not in v]
    sections_failed = [k for k, v in data.items() if "error" in v]

    return {
        "path": str(output_path),
        "format": fmt,
        "size_bytes": output_path.stat().st_size,
        "sections_included": sections_included,
        "sections_failed": sections_failed,
        "generation_seconds": round(elapsed, 2),
    }


async def generate_report_standalone(
    output_path: str | Path | None = None,
    title: str | None = None,
    sections: list[str] | None = None,
    fmt: str = "pdf",
) -> dict[str, Any]:
    """Generate a report using a fresh Fetcher (for CLI / standalone use)."""
    cache = Cache()
    breaker = CircuitBreaker(failure_threshold=3, cooldown_seconds=300)
    fetcher = Fetcher(cache=cache, breaker=breaker)
    return await generate_report(fetcher, output_path, title, sections, fmt)
