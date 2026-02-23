"""Markdown report generator for world-intel-mcp.

Generates Markdown reports with optional Mermaid diagrams.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger("world-intel-mcp.reports.markdown_report")


def generate_daily_brief_md(
    market_summary: dict,
    conflict_summary: dict,
    cyber_summary: dict,
    natural_summary: dict,
    prediction_highlights: list,
    trending_keywords: list,
) -> str:
    """Generate a daily intelligence brief in Markdown format."""
    now = datetime.now(timezone.utc)
    lines = [
        f"# Daily Intelligence Brief",
        f"*Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}*",
        "",
        "## Markets",
    ]

    quotes = market_summary.get("quotes", [])
    if quotes:
        lines.append("| Symbol | Price | Change |")
        lines.append("|--------|------:|-------:|")
        for q in quotes[:8]:
            chg = q.get("change_pct") or 0
            lines.append(f"| {q.get('symbol', '?')} | {q.get('price', 0):,.2f} | {chg:+.2f}% |")
    lines.append("")

    # Conflict
    events = conflict_summary.get("events", [])
    lines.append(f"## Conflict ({conflict_summary.get('count', 0)} events)")
    if events:
        lines.append("| Date | Type | Country | Fatalities |")
        lines.append("|------|------|---------|----------:|")
        for e in events[:10]:
            lines.append(
                f"| {(e.get('event_date') or '')[:10]} "
                f"| {e.get('event_type', '')} "
                f"| {e.get('country', '')} "
                f"| {e.get('fatalities', 0)} |"
            )
    lines.append("")

    # Cyber
    by_sev = cyber_summary.get("by_severity", {})
    lines.append(f"## Cyber Threats")
    lines.append(f"Critical: {by_sev.get('critical', 0)} | "
                 f"High: {by_sev.get('high', 0)} | "
                 f"Medium: {by_sev.get('medium', 0)}")
    lines.append("")

    # Natural
    quakes = natural_summary.get("earthquakes", [])
    lines.append(f"## Natural Events")
    lines.append(f"Earthquakes: {len(quakes)} | Fires: {natural_summary.get('fire_count', 0)}")
    if quakes:
        lines.append("")
        lines.append("| Mag | Location | Depth |")
        lines.append("|----:|----------|------:|")
        for q in quakes[:5]:
            lines.append(f"| {q.get('magnitude', 0):.1f} | {(q.get('place') or '')[:40]} | {q.get('depth_km', 0):.0f}km |")
    lines.append("")

    # Predictions
    if prediction_highlights:
        lines.append("## Prediction Markets")
        for p in prediction_highlights[:5]:
            yes = (p.get("yes_probability", 0) or 0) * 100
            lines.append(f"- **{(p.get('question') or '')[:60]}** — YES: {yes:.0f}% ({p.get('sentiment', '')})")
    lines.append("")

    # Trending
    if trending_keywords:
        lines.append("## Trending Keywords")
        kw_str = ", ".join(f"**{k['word']}** ({k['count']})" for k in trending_keywords[:15])
        lines.append(kw_str)
    lines.append("")

    lines.append(f"---\n*Phoenix AGI System — World Intelligence*")
    return "\n".join(lines)


def generate_threat_landscape_md(
    cyber_threats: dict,
    conflict_events: list,
    military_activity: dict,
    cable_health: dict,
    outages: dict,
) -> str:
    """Generate a threat landscape report in Markdown with Mermaid diagram."""
    now = datetime.now(timezone.utc)
    lines = [
        "# Threat Landscape Report",
        f"*Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}*",
        "",
    ]

    # Mermaid threat overview
    by_sev = cyber_threats.get("by_severity", {})
    lines.append("## Threat Overview")
    lines.append("```mermaid")
    lines.append("pie title Threat Severity Distribution")
    for level in ["critical", "high", "medium", "low"]:
        count = by_sev.get(level, 0)
        if count > 0:
            lines.append(f'    "{level.title()}" : {count}')
    lines.append("```")
    lines.append("")

    # Cyber section
    lines.append(f"## Cyber Threats ({len(cyber_threats.get('threats', []))})")
    for t in cyber_threats.get("threats", [])[:10]:
        lines.append(f"- [{t.get('severity', '').upper()}] **{(t.get('indicator') or '')[:40]}** — {t.get('threat', '')} (via {t.get('source_feed', '')})")
    lines.append("")

    # Military
    theaters = military_activity.get("theaters", {})
    total = military_activity.get("total_military_aircraft", 0)
    lines.append(f"## Military Activity ({total} aircraft)")
    for name, info in theaters.items():
        count = info.get("count", 0)
        lines.append(f"- **{name.replace('_', ' ').title()}**: {count} aircraft")
    lines.append("")

    # Conflict events count
    conflict_count = len(conflict_events)
    if conflict_count:
        lines.append(f"## Active Conflicts ({conflict_count} events, 7 days)")
        for e in conflict_events[:10]:
            lines.append(
                f"- [{(e.get('event_date') or '')[:10]}] **{e.get('country', '')}** — "
                f"{e.get('event_type', '')} ({e.get('fatalities', 0)} fatalities)"
            )
        lines.append("")

    # Infrastructure
    corridors = cable_health.get("corridors", {})
    if corridors:
        lines.append("## Cable Health")
        status_map = {0: "Clear", 1: "Advisory", 2: "At Risk", 3: "Disrupted"}
        for name, info in corridors.items():
            score = info.get("status_score", 0)
            lines.append(f"- **{name.replace('_', ' ').title()}**: {status_map.get(score, '?')}")
    lines.append("")

    # Outages
    ongoing = outages.get("ongoing_count", 0)
    lines.append(f"## Internet Outages ({ongoing} ongoing)")
    lines.append("")

    lines.append(f"---\n*Phoenix AGI System — Threat Intelligence*")
    return "\n".join(lines)
