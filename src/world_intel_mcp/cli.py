#!/usr/bin/env python3
"""
intel — CLI for World Intelligence MCP.

Calls source functions directly (no MCP protocol overhead).
"""

import asyncio
import json
from typing import Any

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from .cache import Cache
from .circuit_breaker import CircuitBreaker
from .fetcher import Fetcher
from .sources import (
    markets,
    economic,
    seismology,
    wildfire,
    conflict,
    military,
    infrastructure,
    maritime,
    climate,
    news,
    intelligence,
    prediction,
    displacement,
    aviation,
    cyber,
    shipping,
    social,
    nuclear,
    space_weather,
    ai_watch,
    elections,
    health,
    sanctions,
)
from .sources.central_banks import fetch_central_bank_rates
from .sources.usni_fleet import fetch_usni_fleet
from .sources.hacker_news import fetch_hacker_news
from .sources.github_trending import fetch_trending_repos
from .sources.arxiv_papers import fetch_arxiv_papers
from .sources.usa_spending import fetch_usa_spending
from .sources import geospatial

console = Console()

# Shared infrastructure — lazily initialized
_fetcher: Fetcher | None = None


def _get_fetcher() -> Fetcher:
    global _fetcher
    if _fetcher is None:
        cache = Cache()
        breaker = CircuitBreaker()
        _fetcher = Fetcher(cache=cache, breaker=breaker)
    return _fetcher


def _run(coro: Any) -> Any:
    """Run an async coroutine from sync CLI context."""
    return asyncio.run(coro)


def _print_json(data: dict) -> None:
    """Print raw JSON if --json flag, otherwise formatted."""
    console.print_json(json.dumps(data, default=str))


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@click.group()
@click.option("--json-output", is_flag=True, help="Output raw JSON")
@click.pass_context
def main(ctx: click.Context, json_output: bool) -> None:
    """World Intelligence CLI — real-time global intelligence."""
    ctx.ensure_object(dict)
    ctx.obj["json"] = json_output


# ---------------------------------------------------------------------------
# Markets
# ---------------------------------------------------------------------------


@main.command(name="markets")
@click.option("--symbols", "-s", multiple=True, help="Ticker symbols")
@click.pass_context
def markets_cmd(ctx: click.Context, symbols: tuple[str, ...]) -> None:
    """Stock market index quotes."""
    f = _get_fetcher()
    sym_list = list(symbols) if symbols else None
    data = _run(markets.fetch_market_quotes(f, symbols=sym_list))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    quotes = data.get("quotes", [])
    if not quotes:
        console.print("[yellow]No market data available[/yellow]")
        return

    table = Table(title="Market Indices", box=box.SIMPLE_HEAVY)
    table.add_column("Symbol", style="bold")
    table.add_column("Price", justify="right")
    table.add_column("Change %", justify="right")
    table.add_column("Currency")

    for q in quotes:
        chg = q.get("change_pct") or 0
        price = q.get("price") or 0
        style = "green" if chg >= 0 else "red"
        table.add_row(
            q.get("symbol", "?"),
            f"{price:,.2f}",
            f"[{style}]{chg:+.2f}%[/{style}]",
            q.get("currency", ""),
        )
    console.print(table)


@main.command()
@click.option("--limit", "-n", default=20, help="Number of coins")
@click.pass_context
def crypto(ctx: click.Context, limit: int) -> None:
    """Top cryptocurrency prices."""
    f = _get_fetcher()
    data = _run(markets.fetch_crypto_quotes(f, limit=limit))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    coins = data.get("coins", [])
    if not coins:
        console.print("[yellow]No crypto data available[/yellow]")
        return

    table = Table(title=f"Top {limit} Cryptocurrencies", box=box.SIMPLE_HEAVY)
    table.add_column("#", justify="right")
    table.add_column("Symbol", style="bold")
    table.add_column("Price", justify="right")
    table.add_column("24h %", justify="right")
    table.add_column("Market Cap", justify="right")

    for i, c in enumerate(coins[:limit], 1):
        chg = c.get("price_change_percentage_24h", 0) or 0
        style = "green" if chg >= 0 else "red"
        mcap = c.get("market_cap", 0) or 0
        table.add_row(
            str(i),
            c.get("symbol", "?").upper(),
            f"${c.get('current_price', 0):,.2f}",
            f"[{style}]{chg:+.2f}%[/{style}]",
            f"${mcap:,.0f}",
        )
    console.print(table)


@main.command()
@click.pass_context
def macro(ctx: click.Context) -> None:
    """7-signal macro dashboard."""
    f = _get_fetcher()
    data = _run(markets.fetch_macro_signals(f))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    signals = data.get("signals", {})
    table = Table(title="Macro Signals", box=box.SIMPLE_HEAVY)
    table.add_column("Signal", style="bold")
    table.add_column("Value", justify="right")
    table.add_column("Detail")

    for name, info in signals.items():
        if info is None:
            table.add_row(name, "[dim]unavailable[/dim]", "")
        elif isinstance(info, dict):
            val = info.get("value", info.get("price", "?"))
            detail = info.get("classification", info.get("label", ""))
            table.add_row(name, str(val), str(detail))
        else:
            table.add_row(name, str(info), "")
    console.print(table)


# ---------------------------------------------------------------------------
# Economic
# ---------------------------------------------------------------------------


@main.command()
@click.pass_context
def energy(ctx: click.Context) -> None:
    """Oil and natural gas prices (EIA)."""
    f = _get_fetcher()
    data = _run(economic.fetch_energy_prices(f))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    oil = data.get("oil", {})
    gas = data.get("natural_gas", {})
    table = Table(title="Energy Prices", box=box.SIMPLE_HEAVY)
    table.add_column("Commodity", style="bold")
    table.add_column("Price", justify="right")
    table.add_column("Date")

    for name, info in [
        ("Brent Crude", oil.get("brent")),
        ("WTI Crude", oil.get("wti")),
        ("Natural Gas", gas),
    ]:
        if info and isinstance(info, dict):
            table.add_row(name, f"${info.get('price', '?')}", str(info.get("date", "")))
    console.print(table)


@main.command("gas-prices")
@click.pass_context
def gas_prices(ctx: click.Context) -> None:
    """US retail gasoline & diesel prices (AAA, daily)."""
    f = _get_fetcher()
    data = _run(economic.fetch_gas_prices(f))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    prices = data.get("prices", {})
    table = Table(title="US Gas Prices — Today (AAA)", box=box.SIMPLE_HEAVY)
    table.add_column("Grade", style="bold")
    table.add_column("$/gallon", justify="right")
    table.add_column("DoD", justify="right")
    table.add_column("WoW", justify="right")

    grade_labels = {
        "regular": "Regular",
        "mid_grade": "Mid-Grade",
        "premium": "Premium",
        "diesel": "Diesel",
    }
    for grade, label in grade_labels.items():
        info = prices.get(grade)
        if info and isinstance(info, dict):
            price = info.get("price_per_gallon", 0)
            dod = info.get("change_pct")
            wow = info.get("week_ago_pct")
            dod_str = (
                f"[{'green' if dod >= 0 else 'red'}]{dod:+.2f}%[/]"
                if dod is not None
                else "—"
            )
            wow_str = (
                f"[{'green' if wow >= 0 else 'red'}]{wow:+.2f}%[/]"
                if wow is not None
                else "—"
            )
            table.add_row(label, f"${price:.3f}", dod_str, wow_str)
    console.print(table)


@main.command("natgas")
@click.pass_context
def natgas(ctx: click.Context) -> None:
    """US residential natural gas prices (EIA)."""
    f = _get_fetcher()
    data = _run(economic.fetch_residential_natgas_prices(f))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    prices = data.get("prices", [])
    table = Table(title="US Residential Natural Gas Prices", box=box.SIMPLE_HEAVY)
    table.add_column("Period", style="bold")
    table.add_column("$/MCF", justify="right")

    for entry in prices:
        table.add_row(str(entry.get("period", "")), f"${entry.get('price', '?'):.2f}")
    console.print(table)


@main.command("electricity")
@click.option("--state", "-s", default=None, help="2-letter state code (e.g., CA, TX)")
@click.pass_context
def electricity(ctx: click.Context, state: str | None) -> None:
    """US electricity retail rates (EIA)."""
    f = _get_fetcher()
    data = _run(economic.fetch_electricity_rates(f, state=state))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    rates = data.get("rates", {})
    label = data.get("state", "US")
    table = Table(title=f"Electricity Rates — {label}", box=box.SIMPLE_HEAVY)
    table.add_column("Sector", style="bold")
    table.add_column("cents/kWh", justify="right")
    table.add_column("Period")

    for sector in ("residential", "commercial", "industrial", "all_sectors"):
        info = rates.get(sector)
        if info and isinstance(info, dict):
            table.add_row(
                sector.replace("_", " ").title(),
                f"{info.get('price_cents_kwh', '?'):.2f}",
                str(info.get("period", "")),
            )
    console.print(table)


@main.command()
@click.argument("series_id")
@click.option("--limit", "-n", default=30, help="Number of observations")
@click.pass_context
def fred(ctx: click.Context, series_id: str, limit: int) -> None:
    """FRED economic data series (e.g., UNRATE, GDP, CPIAUCSL)."""
    f = _get_fetcher()
    data = _run(economic.fetch_fred_series(f, series_id=series_id, limit=limit))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    obs = data.get("observations", [])
    title = data.get("title", series_id)
    table = Table(title=f"FRED: {title}", box=box.SIMPLE_HEAVY)
    table.add_column("Date", style="bold")
    table.add_column("Value", justify="right")

    for o in obs[:20]:
        table.add_row(o.get("date", ""), str(o.get("value", "")))
    console.print(table)


# ---------------------------------------------------------------------------
# Natural
# ---------------------------------------------------------------------------


@main.command()
@click.option("--min-mag", "-m", default=4.5, help="Minimum magnitude")
@click.option("--hours", "-h", default=24, help="Lookback hours")
@click.pass_context
def earthquakes(ctx: click.Context, min_mag: float, hours: int) -> None:
    """Recent earthquakes (USGS)."""
    f = _get_fetcher()
    data = _run(seismology.fetch_earthquakes(f, min_magnitude=min_mag, hours=hours))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    quakes = data.get("earthquakes", [])
    console.print(
        f"[bold]{data.get('count', 0)} earthquakes[/bold] (M{min_mag}+ in last {hours}h)\n"
    )

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Mag", justify="right", style="bold")
    table.add_column("Location")
    table.add_column("Depth (km)", justify="right")
    table.add_column("Time")
    table.add_column("Alert")

    for q in quakes[:25]:
        mag = q.get("magnitude", 0)
        style = "red bold" if mag >= 6.0 else "yellow" if mag >= 5.0 else ""
        alert = q.get("alert_level") or ""
        table.add_row(
            f"[{style}]{mag:.1f}[/{style}]" if style else f"{mag:.1f}",
            q.get("place", "Unknown"),
            f"{q.get('depth_km', 0):.1f}",
            q.get("time", "")[:19],
            alert,
        )
    console.print(table)


@main.command()
@click.option("--region", "-r", default=None, help="Region name (e.g., north_america)")
@click.pass_context
def fires(ctx: click.Context, region: str | None) -> None:
    """Active wildfires (NASA FIRMS)."""
    f = _get_fetcher()
    data = _run(wildfire.fetch_wildfires(f, region=region))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    console.print(
        f"[bold]{data.get('total_fires', 0)} high-confidence fires detected[/bold]\n"
    )

    for reg_name, reg_data in data.get("fires_by_region", {}).items():
        count = reg_data.get("count", 0)
        if count == 0:
            continue
        console.print(f"  [bold]{reg_name}[/bold]: {count} fires")
        for cluster in reg_data.get("top_clusters", [])[:5]:
            console.print(
                f"    ({cluster.get('lat', 0):.1f}, {cluster.get('lon', 0):.1f}) "
                f"— {cluster.get('fire_count', 0)} fires, FRP max {cluster.get('max_frp', 0):.0f}"
            )


# ---------------------------------------------------------------------------
# Conflict
# ---------------------------------------------------------------------------


@main.command()
@click.option("--country", "-c", default=None, help="Country name")
@click.option("--days", "-d", default=7, help="Lookback days")
@click.pass_context
def conflicts(ctx: click.Context, country: str | None, days: int) -> None:
    """Armed conflict events (ACLED)."""
    f = _get_fetcher()
    data = _run(conflict.fetch_acled_events(f, country=country, days=days))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    events = data.get("events", [])
    console.print(
        f"[bold]{data.get('count', 0)} conflict events[/bold] (last {days}d)\n"
    )

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Date", style="bold")
    table.add_column("Type")
    table.add_column("Country")
    table.add_column("Location")
    table.add_column("Fatalities", justify="right")

    for e in events[:25]:
        fat = e.get("fatalities", 0) or 0
        style = "red bold" if fat >= 10 else "yellow" if fat > 0 else ""
        fat_str = f"[{style}]{fat}[/{style}]" if style else str(fat)
        table.add_row(
            str(e.get("event_date", ""))[:10],
            e.get("event_type", ""),
            e.get("country", ""),
            e.get("location", ""),
            fat_str,
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Military
# ---------------------------------------------------------------------------


@main.command()
@click.option(
    "--bbox", "-b", default=None, help="Bounding box: lamin,lomin,lamax,lomax"
)
@click.pass_context
def flights(ctx: click.Context, bbox: str | None) -> None:
    """Military aircraft tracking (OpenSky)."""
    f = _get_fetcher()
    data = _run(military.fetch_military_flights(f, bbox=bbox))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    aircraft = data.get("aircraft", [])
    console.print(f"[bold]{data.get('count', 0)} military aircraft detected[/bold]\n")

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Callsign", style="bold")
    table.add_column("ICAO24")
    table.add_column("Country")
    table.add_column("Alt (m)", justify="right")
    table.add_column("Speed (m/s)", justify="right")

    for a in aircraft[:30]:
        table.add_row(
            a.get("callsign", "?"),
            a.get("icao24", ""),
            a.get("origin_country", ""),
            f"{a.get('altitude_m') or 0:,.0f}",
            f"{a.get('velocity_ms') or 0:.0f}",
        )
    console.print(table)


@main.command()
@click.pass_context
def posture(ctx: click.Context) -> None:
    """Military theater posture (5 theaters)."""
    f = _get_fetcher()
    data = _run(military.fetch_theater_posture(f))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    console.print(
        f"[bold]{data.get('total_military_aircraft', 0)} total military aircraft[/bold]\n"
    )
    theaters = data.get("theaters", {})

    table = Table(title="Theater Posture", box=box.SIMPLE_HEAVY)
    table.add_column("Theater", style="bold")
    table.add_column("Aircraft", justify="right")
    table.add_column("Countries")
    table.add_column("Sample Callsigns")

    for name, info in theaters.items():
        count = info.get("count", 0)
        style = "red bold" if count >= 20 else "yellow" if count >= 5 else ""
        count_str = f"[{style}]{count}[/{style}]" if style else str(count)
        table.add_row(
            name.replace("_", " ").title(),
            count_str,
            ", ".join(info.get("countries", [])[:5]),
            ", ".join(info.get("sample_callsigns", [])[:3]),
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------


@main.command()
@click.pass_context
def outages(ctx: click.Context) -> None:
    """Internet outages (Cloudflare Radar)."""
    f = _get_fetcher()
    data = _run(infrastructure.fetch_internet_outages(f))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    console.print(
        f"[bold]{data.get('ongoing_count', 0)} ongoing outages[/bold], "
        f"{data.get('total_7d', 0)} in last 7 days\n"
    )

    for o in data.get("outages", [])[:15]:
        ongoing = "[red]ONGOING[/red]" if o.get("is_ongoing") else ""
        countries = ", ".join(o.get("countries", [])[:5]) if o.get("countries") else ""
        console.print(
            f"  {o.get('start', '')[:16]}  {countries}  {o.get('description', '')[:80]}  {ongoing}"
        )


@main.command()
@click.pass_context
def cables(ctx: click.Context) -> None:
    """Undersea cable corridor health (NGA)."""
    f = _get_fetcher()
    data = _run(infrastructure.fetch_cable_health(f))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    status_labels = {
        0: "[green]Clear[/green]",
        1: "[yellow]Advisory[/yellow]",
        2: "[red]At Risk[/red]",
        3: "[red bold]Disrupted[/red bold]",
    }

    table = Table(title="Undersea Cable Health", box=box.SIMPLE_HEAVY)
    table.add_column("Corridor", style="bold")
    table.add_column("Status")
    table.add_column("Cables")
    table.add_column("Warnings", justify="right")

    for name, info in data.get("corridors", {}).items():
        score = info.get("status_score", 0)
        table.add_row(
            name.replace("_", " ").title(),
            status_labels.get(score, str(score)),
            ", ".join(info.get("cables", [])[:3]),
            str(len(info.get("relevant_warnings", []))),
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Maritime
# ---------------------------------------------------------------------------


@main.command()
@click.option("--navarea", "-n", default=None, help="NAVAREA number (e.g., IV)")
@click.pass_context
def warnings(ctx: click.Context, navarea: str | None) -> None:
    """Navigational warnings (NGA Maritime Safety)."""
    f = _get_fetcher()
    data = _run(maritime.fetch_nav_warnings(f, navarea=navarea))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    console.print(f"[bold]{data.get('count', 0)} active warnings[/bold]\n")

    by_area = data.get("by_navarea", {})
    if by_area:
        console.print(
            "  By NAVAREA: " + ", ".join(f"{k}:{v}" for k, v in sorted(by_area.items()))
        )
        console.print()

    for w in data.get("warnings", [])[:20]:
        console.print(
            f"  [{w.get('navarea', '?')}] {w.get('id', '')}  {w.get('text', '')[:100]}"
        )


# ---------------------------------------------------------------------------
# Climate
# ---------------------------------------------------------------------------


@main.command(name="climate")
@click.pass_context
def climate_cmd(ctx: click.Context) -> None:
    """Climate anomalies (15 global zones vs. prior year)."""
    f = _get_fetcher()
    data = _run(climate.fetch_climate_anomalies(f))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    zones = data.get("zones", {})
    sig = data.get("significant_anomalies", [])

    table = Table(title="Climate Anomalies", box=box.SIMPLE_HEAVY)
    table.add_column("Zone", style="bold")
    table.add_column("Temp Anomaly", justify="right")
    table.add_column("Precip Anomaly", justify="right")
    table.add_column("Flag")

    for key, z in zones.items():
        temp_a = z.get("temp_anomaly_c", 0)
        prec_a = z.get("precip_anomaly_pct", 0)
        t_style = "red" if temp_a > 3 else "blue" if temp_a < -3 else ""
        flag = "[red bold]SIG[/red bold]" if key in sig else ""
        t_str = (
            f"[{t_style}]{temp_a:+.1f}C[/{t_style}]" if t_style else f"{temp_a:+.1f}C"
        )
        table.add_row(z.get("name", key), t_str, f"{prec_a:+.0f}%", flag)
    console.print(table)


# ---------------------------------------------------------------------------
# News
# ---------------------------------------------------------------------------


@main.command(name="news")
@click.option(
    "--category",
    "-c",
    default=None,
    type=click.Choice(
        [
            "geopolitics",
            "security",
            "technology",
            "finance",
            "military",
            "science",
            "think_tanks",
            "middle_east",
            "asia_pacific",
            "africa",
            "latin_america",
            "multilingual",
            "energy",
            "government",
            "crisis",
            "europe",
            "south_asia",
            "health",
            "central_asia",
            "arctic",
            "maritime",
            "space",
            "nuclear",
            "climate",
        ]
    ),
    help="Category filter",
)
@click.option("--limit", "-n", default=30, help="Max items")
@click.pass_context
def news_cmd(ctx: click.Context, category: str | None, limit: int) -> None:
    """Intelligence news from 119 RSS feeds across 24 categories."""
    f = _get_fetcher()
    data = _run(news.fetch_news_feed(f, category=category, limit=limit))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    items = data.get("items", [])
    if not items:
        console.print("[yellow]No news items available[/yellow]")
        return

    console.print(
        f"[bold]{data.get('count', 0)} items[/bold] from {', '.join(data.get('categories_fetched', []))}\n"
    )

    for item in items:
        cat = item.get("category", "")
        title = item.get("title", "")
        feed = item.get("feed_name", "")
        pub = (item.get("published") or "")[:16]
        console.print(f"  [{cat}] [bold]{title}[/bold]")
        console.print(f"         {feed} — {pub}")


@main.command()
@click.option("--min-count", "-m", default=3, help="Minimum keyword occurrences")
@click.pass_context
def trending(ctx: click.Context, min_count: int) -> None:
    """Trending keywords from recent news."""
    f = _get_fetcher()
    data = _run(news.fetch_trending_keywords(f, min_count=min_count))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    keywords = data.get("keywords", [])
    console.print(
        f"[bold]Trending keywords[/bold] (from {data.get('total_items_analyzed', 0)} items)\n"
    )

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("#", justify="right")
    table.add_column("Keyword", style="bold")
    table.add_column("Count", justify="right")

    for i, kw in enumerate(keywords[:30], 1):
        table.add_row(str(i), kw["word"], str(kw["count"]))
    console.print(table)


@main.command()
@click.argument("query", default="conflict")
@click.option(
    "--mode", "-m", default="artlist", type=click.Choice(["artlist", "timelinevol"])
)
@click.option("--limit", "-n", default=20, help="Max records")
@click.pass_context
def gdelt(ctx: click.Context, query: str, mode: str, limit: int) -> None:
    """Search GDELT 2.0 global news database."""
    f = _get_fetcher()
    data = _run(news.fetch_gdelt_search(f, query=query, mode=mode, limit=limit))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    if mode == "artlist":
        articles = data.get("articles", [])
        console.print(f"[bold]{len(articles)} articles[/bold] for '{query}'\n")
        for a in articles[:20]:
            title = a.get("title", "")[:80]
            domain = a.get("domain", "")
            console.print(f"  [bold]{title}[/bold]  ({domain})")
    else:
        console.print(f"[bold]Timeline volume for '{query}'[/bold]")
        _print_json(data)


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------


@main.command()
@click.option("--limit", "-n", default=20, help="Number of markets")
@click.pass_context
def predictions(ctx: click.Context, limit: int) -> None:
    """Prediction market movers (Polymarket)."""
    f = _get_fetcher()
    data = _run(prediction.fetch_prediction_markets(f, limit=limit))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    mkts = data.get("markets", [])
    if not mkts:
        console.print("[yellow]No prediction market data available[/yellow]")
        return

    table = Table(title="Prediction Markets", box=box.SIMPLE_HEAVY)
    table.add_column("Question", max_width=50)
    table.add_column("YES %", justify="right")
    table.add_column("Sentiment")
    table.add_column("24h Vol", justify="right")

    for m in mkts:
        yes_pct = (m.get("yes_probability", 0) or 0) * 100
        sentiment = m.get("sentiment", "")
        vol = m.get("volume_24h", 0) or 0
        s_style = (
            "green" if "yes" in sentiment else "red" if "no" in sentiment else "yellow"
        )
        table.add_row(
            (m.get("question", "")[:50]),
            f"{yes_pct:.0f}%",
            f"[{s_style}]{sentiment}[/{s_style}]",
            f"${vol:,.0f}",
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Displacement
# ---------------------------------------------------------------------------


@main.command(name="displacement")
@click.option("--year", "-y", default=None, type=int, help="Reporting year")
@click.pass_context
def displacement_cmd(ctx: click.Context, year: int | None) -> None:
    """UNHCR displacement statistics."""
    f = _get_fetcher()
    data = _run(displacement.fetch_displacement_summary(f, year=year))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    totals = data.get("global_totals", {})
    console.print(f"[bold]Global Displacement ({data.get('year', '?')})[/bold]")
    console.print(f"  Grand total: {totals.get('grand_total', 0):,}\n")

    by_origin = data.get("by_origin", [])
    table = Table(title="Top Countries of Origin", box=box.SIMPLE_HEAVY)
    table.add_column("Country", style="bold")
    table.add_column("Total Displaced", justify="right")
    table.add_column("Refugees", justify="right")
    table.add_column("IDPs", justify="right")

    for c in by_origin[:15]:
        table.add_row(
            c.get("country", ""),
            f"{c.get('total_displaced', 0):,}",
            f"{c.get('refugees', 0):,}",
            f"{c.get('internally_displaced', 0):,}",
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Aviation
# ---------------------------------------------------------------------------


@main.command()
@click.pass_context
def delays(ctx: click.Context) -> None:
    """US airport delays (FAA)."""
    f = _get_fetcher()
    data = _run(aviation.fetch_airport_delays(f))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    delayed = data.get("delayed", [])
    console.print(
        f"[bold]{data.get('delayed_count', 0)} airports with delays[/bold] "
        f"(checked {data.get('total_checked', 0)})\n"
    )

    if not delayed:
        console.print("[green]No major airport delays![/green]")
        return

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Airport", style="bold")
    table.add_column("Name")
    table.add_column("Delay Info")

    for d in delayed:
        statuses = d.get("status", [])
        info = (
            "; ".join(
                f"{s.get('type', '')} - {s.get('reason', '')} ({s.get('avg_delay', '')})"
                for s in statuses
            )
            if statuses
            else "Details unavailable"
        )
        table.add_row(d.get("code", ""), d.get("name", ""), info[:80])
    console.print(table)


# ---------------------------------------------------------------------------
# Cyber
# ---------------------------------------------------------------------------


@main.command()
@click.option("--limit", "-n", default=30, help="Max threats")
@click.pass_context
def threats(ctx: click.Context, limit: int) -> None:
    """Cyber threat intelligence (4 feeds)."""
    f = _get_fetcher()
    data = _run(cyber.fetch_cyber_threats(f, limit=limit))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    by_sev = data.get("by_severity", {})
    console.print(
        f"[bold]{data.get('count', 0)} threats[/bold] "
        f"({data.get('feeds_successful', 0)}/{data.get('feeds_attempted', 0)} feeds)"
    )
    console.print(
        f"  [red]Critical: {by_sev.get('critical', 0)}[/red]  "
        f"[yellow]High: {by_sev.get('high', 0)}[/yellow]  "
        f"Medium: {by_sev.get('medium', 0)}  "
        f"[dim]Low: {by_sev.get('low', 0)}[/dim]\n"
    )

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Severity")
    table.add_column("Type")
    table.add_column("Indicator", max_width=40)
    table.add_column("Threat")
    table.add_column("Feed")

    for t in data.get("threats", [])[:limit]:
        sev = t.get("severity", "")
        sev_style = {
            "critical": "red bold",
            "high": "yellow",
            "medium": "",
            "low": "dim",
        }.get(sev, "")
        sev_str = f"[{sev_style}]{sev}[/{sev_style}]" if sev_style else sev
        table.add_row(
            sev_str,
            t.get("type", ""),
            (t.get("indicator", ""))[:40],
            (t.get("threat", ""))[:30],
            t.get("source_feed", ""),
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Intelligence
# ---------------------------------------------------------------------------


@main.command()
@click.argument("country_code", default="US")
@click.pass_context
def brief(ctx: click.Context, country_code: str) -> None:
    """Country intelligence brief (LLM + data)."""
    f = _get_fetcher()
    data = _run(intelligence.fetch_country_brief(f, country_code=country_code))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    llm_tag = (
        "[green]LLM[/green]"
        if data.get("llm_available")
        else "[yellow]data-only[/yellow]"
    )
    console.print(f"[bold]Intelligence Brief: {country_code}[/bold] ({llm_tag})\n")
    console.print(data.get("brief", "No brief available."))

    d = data.get("data", {})
    if d.get("gdp") or d.get("recent_events"):
        console.print(
            f"\n[dim]GDP data points: {len(d.get('gdp', []))} | "
            f"Recent conflict events: {d.get('recent_events', 0)}[/dim]"
        )


@main.command()
@click.option("--country", "-c", default="US", help="ISO-2 or ISO-3 country code")
@click.pass_context
def dossier(ctx: click.Context, country: str) -> None:
    """Comprehensive country intelligence dossier."""
    from .analysis.dossier import fetch_country_dossier

    f = _get_fetcher()
    data = _run(fetch_country_dossier(f, country=country))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    overview = data.get("overview", {})
    console.print(
        f"[bold]Country Dossier: {overview.get('country', country)}[/bold] "
        f"({overview.get('iso2')}/{overview.get('iso3')})\n"
    )

    # Economy
    econ = data.get("economy", {})
    if "_error" not in econ:
        gdp = econ.get("gdp", [])
        if gdp:
            latest = gdp[0]
            console.print(
                f"[cyan]Economy:[/cyan] GDP {latest.get('year')}: ${latest.get('value', 0) / 1e9:,.1f}B"
            )
        if econ.get("conflict_events_30d"):
            console.print(f"  Conflict events (30d): {econ['conflict_events_30d']}")

    # Markets
    mkt = data.get("markets", {})
    if "ticker" in mkt:
        q = mkt.get("quote", {})
        console.print(
            f"[green]Markets:[/green] {mkt['ticker']} = {q.get('price', 'N/A')} ({q.get('change_pct', 'N/A')}%)"
        )

    # Elections
    elec = data.get("elections", {})
    upcoming = elec.get("upcoming", [])
    if upcoming:
        next_e = upcoming[0]
        console.print(
            f"[yellow]Elections:[/yellow] {next_e.get('election_type')} on {next_e.get('date')} "
            f"(risk: {next_e.get('risk_score', 0):.0f})"
        )

    # Sanctions
    sanc = data.get("sanctions", {})
    if sanc.get("match_count", 0) > 0:
        console.print(f"[red]Sanctions:[/red] {sanc['match_count']} OFAC matches")

    # News
    news = data.get("news", {})
    console.print(f"[blue]News:[/blue] {news.get('mention_count', 0)} recent mentions")
    for art in news.get("mentions", [])[:3]:
        console.print(f"  - {art.get('title', 'N/A')[:80]}")

    # Security
    sec = data.get("security", {})
    if sec.get("hotspot_count", 0):
        console.print(f"[red]Hotspots:[/red] {sec['hotspot_count']} associated")
    if sec.get("conflict_count", 0):
        console.print(f"[red]Conflicts:[/red] {sec['conflict_count']} active")

    br = overview.get("baseline_risk")
    if br is not None:
        console.print(f"\n[dim]Baseline risk: {br}/100[/dim]")


@main.command()
@click.option("--limit", "-n", default=20, help="Top N countries")
@click.pass_context
def risk(ctx: click.Context, limit: int) -> None:
    """Country risk scores (ACLED-based)."""
    f = _get_fetcher()
    data = _run(intelligence.fetch_risk_scores(f, limit=limit))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    table = Table(title="Country Risk Scores", box=box.SIMPLE_HEAVY)
    table.add_column("#", justify="right")
    table.add_column("Country", style="bold")
    table.add_column("Events (30d)", justify="right")
    table.add_column("Risk Score", justify="right")
    table.add_column("Level")

    for i, c in enumerate(data.get("countries", []), 1):
        level = c.get("risk_level", "")
        l_style = {
            "critical": "red bold",
            "elevated": "yellow",
            "moderate": "",
            "low": "dim",
        }.get(level, "")
        l_str = f"[{l_style}]{level}[/{l_style}]" if l_style else level
        table.add_row(
            str(i),
            c.get("country", ""),
            str(c.get("events_30d", 0)),
            f"{c.get('risk_score', 0):.0f}",
            l_str,
        )
    console.print(table)


@main.command()
@click.argument("country_code", required=False, default=None)
@click.pass_context
def instability(ctx: click.Context, country_code: str | None) -> None:
    """Country Instability Index (0-100)."""
    f = _get_fetcher()
    data = _run(intelligence.fetch_instability_index(f, country_code=country_code))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    if country_code:
        idx = data.get("instability_index", 0)
        level = data.get("risk_level", "")
        console.print(
            f"[bold]{country_code} Instability Index: {idx}/100 ({level})[/bold]\n"
        )
        components = data.get("components", {})
        for name, score in components.items():
            bar = "█" * int(score) + "░" * (20 - int(score))
            console.print(f"  {name:30s} {bar} {score:.1f}/20")
    else:
        table = Table(title="Instability Index (Focus Countries)", box=box.SIMPLE_HEAVY)
        table.add_column("Country", style="bold")
        table.add_column("Index", justify="right")
        table.add_column("Events (30d)", justify="right")
        table.add_column("Risk Level")

        for c in data.get("countries", []):
            level = c.get("risk_level", "")
            l_style = {
                "critical": "red bold",
                "high": "yellow",
                "medium": "",
                "low": "dim",
            }.get(level, "")
            l_str = f"[{l_style}]{level}[/{l_style}]" if l_style else level
            table.add_row(
                f"{c.get('country_name', '')} ({c.get('country_code', '')})",
                f"{c.get('instability_index', 0):.0f}",
                str(c.get("events_30d", 0)),
                l_str,
            )
        console.print(table)


# ---------------------------------------------------------------------------
# Finance (additional)
# ---------------------------------------------------------------------------


@main.command()
@click.pass_context
def btc(ctx: click.Context) -> None:
    """Bitcoin technical indicators (SMA, Mayer, cross signals)."""
    f = _get_fetcher()
    data = _run(markets.fetch_btc_technicals(f))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    console.print(f"[bold]BTC Technicals[/bold]  price: ${data.get('price', 0):,.2f}\n")
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Indicator", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("SMA-50", f"${data.get('sma_50', 0):,.2f}")
    table.add_row(
        "SMA-200", f"${data.get('sma_200', 0):,.2f}" if data.get("sma_200") else "N/A"
    )
    table.add_row(
        "Mayer Multiple",
        f"{data.get('mayer_multiple', 0):.4f}" if data.get("mayer_multiple") else "N/A",
    )
    cross = data.get("cross_signal", "neutral")
    c_style = (
        "green" if cross == "golden_cross" else "red" if cross == "death_cross" else ""
    )
    table.add_row(
        "Cross Signal", f"[{c_style}]{cross}[/{c_style}]" if c_style else cross
    )
    table.add_row("ATH Distance", f"{data.get('ath_distance_pct', 0):.1f}%")
    table.add_row(
        "7d Change",
        f"{data.get('change_7d_pct', 0):+.2f}%"
        if data.get("change_7d_pct") is not None
        else "N/A",
    )
    table.add_row(
        "30d Change",
        f"{data.get('change_30d_pct', 0):+.2f}%"
        if data.get("change_30d_pct") is not None
        else "N/A",
    )
    console.print(table)


@main.command(name="central-banks")
@click.pass_context
def central_banks_cmd(ctx: click.Context) -> None:
    """Central bank policy rates (15 banks)."""
    f = _get_fetcher()
    data = _run(fetch_central_bank_rates(f))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    fred_tag = (
        "[green]FRED[/green]"
        if data.get("fred_available")
        else "[yellow]curated[/yellow]"
    )
    console.print(f"[bold]{data.get('count', 0)} Central Banks[/bold] ({fred_tag})\n")

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Bank", style="bold")
    table.add_column("Country")
    table.add_column("Rate %", justify="right")
    table.add_column("As Of")

    for r in data.get("rates", []):
        rate = r.get("rate", 0)
        style = (
            "red bold"
            if rate >= 10
            else "yellow"
            if rate >= 5
            else "green"
            if rate < 1
            else ""
        )
        rate_str = f"[{style}]{rate:.2f}[/{style}]" if style else f"{rate:.2f}"
        table.add_row(
            r.get("bank", ""), r.get("country", ""), rate_str, r.get("as_of", "")
        )
    console.print(table)


@main.command(name="shipping")
@click.pass_context
def shipping_cmd(ctx: click.Context) -> None:
    """Shipping index (BDI, tanker, container ETFs)."""
    f = _get_fetcher()
    data = _run(shipping.fetch_shipping_index(f))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    console.print(
        f"[bold]Shipping Stress: {data.get('assessment', '?')}[/bold] "
        f"(score: {data.get('stress_score', 0):.0f}/100)\n"
    )

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Symbol", style="bold")
    table.add_column("Price", justify="right")
    table.add_column("Change %", justify="right")

    for q in data.get("quotes", []):
        chg = q.get("change_pct") or 0
        style = "green" if chg >= 0 else "red"
        table.add_row(
            q.get("symbol", ""),
            f"${q.get('price', 0):,.2f}",
            f"[{style}]{chg:+.2f}%[/{style}]",
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Social & Health
# ---------------------------------------------------------------------------


@main.command(name="social")
@click.pass_context
def social_cmd(ctx: click.Context) -> None:
    """Reddit social signals (worldnews, geopolitics)."""
    f = _get_fetcher()
    data = _run(social.fetch_social_signals(f))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    metrics = data.get("velocity_metrics", {})
    console.print(
        f"[bold]Social Signals[/bold] — {metrics.get('total_posts', 0)} posts, "
        f"{metrics.get('high_engagement_count', 0)} high engagement\n"
    )

    for post in data.get("top_posts", [])[:15]:
        score = post.get("score", 0)
        style = "bold" if score >= 1000 else ""
        title = post.get("title", "")[:80]
        console.print(
            f"  [{style}]{score:>5}[/{style}]  {title}"
            if style
            else f"  {score:>5}  {title}"
        )


@main.command(name="disease")
@click.pass_context
def disease_cmd(ctx: click.Context) -> None:
    """Disease outbreaks (WHO/ProMED/CIDRAP)."""
    f = _get_fetcher()
    data = _run(health.fetch_disease_outbreaks(f))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    console.print(
        f"[bold]{data.get('count', 0)} outbreak reports[/bold] "
        f"([red]{data.get('high_concern_count', 0)} high concern[/red])\n"
    )

    for item in data.get("items", [])[:20]:
        hc = "[red]HC[/red] " if item.get("is_high_concern") else "    "
        title = item.get("title", "")[:80]
        feed = item.get("feed_name", "")
        console.print(f"  {hc}{title}  [dim]({feed})[/dim]")


@main.command(name="elections")
@click.option("--country", "-c", default=None, help="Country filter (ISO-3)")
@click.pass_context
def elections_cmd(ctx: click.Context, country: str | None) -> None:
    """Election calendar with risk scoring."""
    f = _get_fetcher()
    data = _run(elections.fetch_election_calendar(f, country=country))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    table = Table(title="Election Calendar", box=box.SIMPLE_HEAVY)
    table.add_column("Date", style="bold")
    table.add_column("Country")
    table.add_column("Type")
    table.add_column("Days", justify="right")
    table.add_column("Risk", justify="right")

    for e in data.get("elections", []):
        risk = e.get("risk_score", 0)
        r_style = "red bold" if risk >= 4 else "yellow" if risk >= 2 else ""
        r_str = f"[{r_style}]{risk:.1f}[/{r_style}]" if r_style else f"{risk:.1f}"
        table.add_row(
            e.get("date", ""),
            e.get("country", ""),
            e.get("type", ""),
            str(e.get("days_until", "")),
            r_str,
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Specialist
# ---------------------------------------------------------------------------


@main.command(name="nuclear")
@click.option("--hours", "-h", default=72, help="Lookback hours")
@click.pass_context
def nuclear_cmd(ctx: click.Context, hours: int) -> None:
    """Nuclear test site seismic monitor."""
    f = _get_fetcher()
    data = _run(nuclear.fetch_nuclear_monitor(f, hours=hours))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    console.print(
        f"[bold]{data.get('total_flagged_events', 0)} flagged events[/bold] "
        f"([red]{data.get('critical_flags', 0)} critical[/red]) in last {hours}h\n"
    )

    for site in data.get("sites", []):
        n = site.get("name", "")
        events = site.get("events", [])
        count = len(events)
        style = "red bold" if count > 0 else "dim"
        console.print(f"  [{style}]{n}: {count} events[/{style}]")


@main.command(name="space")
@click.pass_context
def space_cmd(ctx: click.Context) -> None:
    """Space weather (NOAA/SWPC)."""
    f = _get_fetcher()
    data = _run(space_weather.fetch_space_weather(f))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    table = Table(title="Space Weather", box=box.SIMPLE_HEAVY)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    for key in (
        "k_index",
        "solar_wind_speed_km_s",
        "solar_wind_density",
        "bz_gsm_nt",
        "flux_10_7",
    ):
        val = data.get(key)
        if val is not None:
            table.add_row(key.replace("_", " ").title(), str(val))
    console.print(table)


@main.command(name="sanctions")
@click.argument("query")
@click.option("--country", "-c", default=None, help="Country filter")
@click.pass_context
def sanctions_cmd(ctx: click.Context, query: str, country: str | None) -> None:
    """Search OFAC SDN sanctions list."""
    f = _get_fetcher()
    data = _run(sanctions.fetch_sanctions_search(f, query=query, country=country))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    console.print(
        f"[bold]{data.get('count', 0)} matches[/bold] for '{query}' "
        f"(from {data.get('total_entities', 0)} total)\n"
    )

    for m in data.get("matches", [])[:20]:
        etype = m.get("entity_type", "")
        name = m.get("name", "")
        programs = ", ".join(m.get("programs", [])[:3])
        console.print(f"  [{etype}] [bold]{name}[/bold]  ({programs})")


@main.command(name="ai-watch")
@click.pass_context
def ai_watch_cmd(ctx: click.Context) -> None:
    """AI model and paper releases tracker."""
    f = _get_fetcher()
    data = _run(ai_watch.fetch_ai_watch(f))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    console.print(f"[bold]AI Watch[/bold] — {data.get('total_items', 0)} items\n")
    for item in data.get("items", [])[:20]:
        title = item.get("title", "")[:80]
        src = item.get("source", "")
        console.print(f"  [{src}] {title}")


# ---------------------------------------------------------------------------
# Navy
# ---------------------------------------------------------------------------


@main.command(name="fleet")
@click.pass_context
def fleet_cmd(ctx: click.Context) -> None:
    """USNI Fleet Tracker (Navy disposition)."""
    f = _get_fetcher()
    data = _run(fetch_usni_fleet(f))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    console.print(f"[bold]{data.get('report_title', 'Fleet Report')}[/bold]\n")

    totals = data.get("force_totals", {})
    if totals.get("battle_force"):
        bf = totals["battle_force"]
        console.print(
            f"  Battle Force: {bf.get('total', 0)} ships ({bf.get('uss', 0)} USS, {bf.get('usns', 0)} USNS)"
        )
    if totals.get("deployed"):
        dp = totals["deployed"]
        console.print(
            f"  Deployed: {dp.get('total', 0)} ({dp.get('uss', 0)} USS, {dp.get('usns', 0)} USNS)"
        )

    ships = data.get("ships", [])
    if ships:
        console.print(f"\n  [bold]{len(ships)} ships identified[/bold]")
        table = Table(box=box.SIMPLE_HEAVY)
        table.add_column("Ship", style="bold")
        table.add_column("Hull")
        table.add_column("Type")
        table.add_column("Region")
        for s in ships[:20]:
            table.add_row(
                s.get("name", ""),
                s.get("hull_number", ""),
                s.get("type", ""),
                s.get("region", ""),
            )
        console.print(table)


# ---------------------------------------------------------------------------
# Tech & Science
# ---------------------------------------------------------------------------


@main.command(name="hn")
@click.option("--limit", "-n", default=20, help="Number of stories")
@click.pass_context
def hn_cmd(ctx: click.Context, limit: int) -> None:
    """Top Hacker News stories."""
    f = _get_fetcher()
    data = _run(fetch_hacker_news(f, limit=limit))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    for s in data.get("stories", []):
        score = s.get("score", 0)
        title = s.get("title", "")[:80]
        console.print(f"  {score:>5}  {title}")


@main.command(name="gh-trending")
@click.option("--limit", "-n", default=15, help="Number of repos")
@click.pass_context
def gh_trending_cmd(ctx: click.Context, limit: int) -> None:
    """Trending GitHub repositories."""
    f = _get_fetcher()
    data = _run(fetch_trending_repos(f, limit=limit))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    for r in data.get("repos", []):
        stars = r.get("stars", 0)
        name = r.get("name", "")
        lang = r.get("language") or ""
        desc = (r.get("description") or "")[:60]
        console.print(f"  {stars:>6} [bold]{name}[/bold] [{lang}]  {desc}")


@main.command(name="arxiv")
@click.option("--query", "-q", default="cs.AI", help="arXiv category or query")
@click.option("--limit", "-n", default=10, help="Number of papers")
@click.pass_context
def arxiv_cmd(ctx: click.Context, query: str, limit: int) -> None:
    """Recent arXiv papers."""
    f = _get_fetcher()
    data = _run(fetch_arxiv_papers(f, query=query, limit=limit))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    for p in data.get("papers", []):
        title = p.get("title", "")[:80]
        authors = ", ".join(p.get("authors", [])[:3])
        console.print(f"  [bold]{title}[/bold]")
        console.print(f"    {authors}")


@main.command(name="spending")
@click.option("--limit", "-n", default=15, help="Top N agencies")
@click.pass_context
def spending_cmd(ctx: click.Context, limit: int) -> None:
    """US federal spending (USAspending.gov)."""
    f = _get_fetcher()
    data = _run(fetch_usa_spending(f, limit=limit))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    table = Table(title="Federal Agencies by Budget", box=box.SIMPLE_HEAVY)
    table.add_column("Agency", style="bold")
    table.add_column("Budget Auth", justify="right")
    table.add_column("Obligated", justify="right")

    for a in data.get("agencies", []):
        budget = a.get("budget_authority", 0) or 0
        obligated = a.get("obligated", 0) or 0
        table.add_row(
            a.get("name", ""), f"${budget / 1e9:,.1f}B", f"${obligated / 1e9:,.1f}B"
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Geospatial (static datasets)
# ---------------------------------------------------------------------------


@main.command(name="bases")
@click.option("--operator", "-o", default=None, help="Operator country (USA, RUS, CHN)")
@click.option("--country", "-c", default=None, help="Host country")
@click.pass_context
def bases_cmd(ctx: click.Context, operator: str | None, country: str | None) -> None:
    """Military bases worldwide (70 bases)."""
    data = _run(geospatial.fetch_military_bases(operator=operator, country=country))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    console.print(
        f"[bold]{data.get('count', 0)} bases[/bold] (of {data.get('total_in_database', 0)})\n"
    )
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Name", style="bold")
    table.add_column("Operator")
    table.add_column("Country")
    table.add_column("Type")
    table.add_column("Branch")

    for b in data.get("bases", [])[:30]:
        table.add_row(
            b.get("name", ""),
            b.get("operator", ""),
            b.get("country", ""),
            b.get("type", ""),
            b.get("branch", ""),
        )
    console.print(table)


@main.command(name="exchanges")
@click.option(
    "--tier", "-t", default=None, type=click.Choice(["mega", "major", "mid", "small"])
)
@click.option("--country", "-c", default=None, help="Country filter")
@click.pass_context
def exchanges_cmd(ctx: click.Context, tier: str | None, country: str | None) -> None:
    """Global stock exchanges (82 exchanges)."""
    data = _run(geospatial.fetch_stock_exchanges(tier=tier, country=country))

    if ctx.obj.get("json"):
        _print_json(data)
        return

    console.print(
        f"[bold]{data.get('count', 0)} exchanges[/bold] "
        f"(${data.get('total_market_cap_usd_t', 0):.1f}T total market cap)\n"
    )

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Exchange", style="bold")
    table.add_column("Country")
    table.add_column("Tier")
    table.add_column("Market Cap ($T)", justify="right")

    for e in data.get("exchanges", [])[:30]:
        table.add_row(
            e.get("name", ""),
            e.get("country", ""),
            e.get("tier", ""),
            f"{e.get('market_cap_usd_t', 0):.2f}",
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Traffic, Aviation, Webcams
# ---------------------------------------------------------------------------


@main.command()
@click.pass_context
def traffic(ctx: click.Context) -> None:
    """Real-time traffic congestion for 20 major cities (TomTom)."""
    from .sources.traffic import fetch_traffic_flow

    f = _get_fetcher()
    data = _run(fetch_traffic_flow(f))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    console.print(
        f"[bold]Global Traffic[/bold] — {data.get('count', 0)} cities, "
        f"avg congestion {data.get('global_avg_congestion', 0):.0f}%\n"
    )

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("City", style="bold")
    table.add_column("Country")
    table.add_column("Congestion %", justify="right")
    table.add_column("Speed (km/h)", justify="right")

    for c in data.get("cities", [])[:20]:
        cong = c.get("congestion_pct", 0)
        style = "red" if cong > 60 else "yellow" if cong > 30 else "green"
        table.add_row(
            c.get("name", ""),
            c.get("country", ""),
            f"[{style}]{cong}%[/{style}]",
            str(c.get("current_speed_kmh", "")),
        )
    console.print(table)


@main.command()
@click.pass_context
def incidents(ctx: click.Context) -> None:
    """Major traffic incidents across strategic regions (TomTom)."""
    from .sources.traffic import fetch_traffic_incidents

    f = _get_fetcher()
    data = _run(fetch_traffic_incidents(f))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    console.print(
        f"[bold]Traffic Incidents[/bold] — {data.get('total_count', 0)} across "
        f"{data.get('regions_checked', 0)} regions\n"
    )

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Region")
    table.add_column("Description", max_width=40)
    table.add_column("Delay (min)", justify="right")
    table.add_column("Road")

    for inc in data.get("incidents", [])[:20]:
        delay_min = round(inc.get("delay_seconds", 0) / 60)
        table.add_row(
            inc.get("region", ""),
            inc.get("description", "")[:40],
            str(delay_min) if delay_min else "-",
            inc.get("from_road", "")[:30],
        )
    console.print(table)


@main.command(name="air-traffic")
@click.pass_context
def air_traffic_cmd(ctx: click.Context) -> None:
    """Global air traffic snapshot (OpenSky)."""
    f = _get_fetcher()
    data = _run(aviation.fetch_domestic_flights(f))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    console.print(
        f"[bold]Air Traffic[/bold] — {data.get('total_aircraft', 0)} airborne\n"
    )

    table = Table(box=box.SIMPLE_HEAVY, title="By Region")
    table.add_column("Region", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Commercial", justify="right")
    table.add_column("General", justify="right")

    for region, stats in sorted(
        data.get("by_region", {}).items(), key=lambda x: -x[1]["count"]
    ):
        table.add_row(
            region, str(stats["count"]), str(stats["commercial"]), str(stats["general"])
        )
    console.print(table)

    if data.get("busiest_origins"):
        console.print("\n[bold]Busiest Origins:[/bold]")
        for o in data["busiest_origins"][:10]:
            console.print(f"  {o['country']}: {o['count']}")


@main.command()
@click.option("--category", "-c", default="traffic", help="Webcam category")
@click.option("--limit", "-n", default=20, help="Max cameras")
@click.pass_context
def webcams_cmd(ctx: click.Context, category: str, limit: int) -> None:
    """Public webcam locations worldwide (Windy)."""
    from .sources.webcams import fetch_webcams

    f = _get_fetcher()
    data = _run(fetch_webcams(f, category=category, limit=limit))

    if ctx.obj.get("json") or "error" in data:
        _print_json(data)
        return

    console.print(
        f"[bold]Webcams[/bold] — {data.get('count', 0)} cameras ({category})\n"
    )

    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Title", style="bold", max_width=30)
    table.add_column("City")
    table.add_column("Country")
    table.add_column("Status")

    for cam in data.get("cameras", []):
        table.add_row(
            cam.get("title", "")[:30],
            cam.get("city", ""),
            cam.get("country", ""),
            cam.get("status", ""),
        )
    console.print(table)


# ---------------------------------------------------------------------------
# System
# ---------------------------------------------------------------------------


@main.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Data source health and cache stats."""
    f = _get_fetcher()
    breaker_status = f.breaker.status()
    cache_stats = f.cache.stats()

    if ctx.obj.get("json"):
        _print_json({"circuit_breakers": breaker_status, "cache": cache_stats})
        return

    console.print(Panel("[bold]World Intelligence Status[/bold]"))

    # Cache
    console.print(
        f"\n[bold]Cache:[/bold] {cache_stats.get('active_entries', 0)} active, "
        f"{cache_stats.get('expired_entries', 0)} expired"
    )

    # Circuit breakers
    if breaker_status:
        table = Table(title="Circuit Breakers", box=box.SIMPLE_HEAVY)
        table.add_column("Source", style="bold")
        table.add_column("Status")
        table.add_column("Failures", justify="right")
        table.add_column("Cooldown", justify="right")

        for source, info in sorted(breaker_status.items()):
            s = info.get("status", "closed")
            style = (
                "green" if s == "closed" else "yellow" if s == "half-open" else "red"
            )
            table.add_row(
                source,
                f"[{style}]{s}[/{style}]",
                str(info.get("failures", 0)),
                f"{info.get('cooldown_remaining_s', 0):.0f}s"
                if info.get("cooldown_remaining_s")
                else "",
            )
        console.print(table)
    else:
        console.print("\n[dim]No circuit breaker data yet (no requests made)[/dim]")


@main.command(name="sync")
@click.argument("source", required=False)
def sync_cmd(source: str | None) -> None:
    """Force refresh a data source cache."""
    f = _get_fetcher()
    if source:
        # Delete all cache entries matching this source prefix
        # Simple approach: evict expired, then note we can't selectively clear yet
        console.print(
            f"[yellow]Force sync not yet implemented for specific source '{source}'[/yellow]"
        )
        console.print(
            "[dim]Workaround: cache entries expire naturally based on TTL[/dim]"
        )
    else:
        removed = f.cache.evict_expired()
        console.print(f"Evicted {removed} expired cache entries")


@main.command()
@click.option("--port", default=8501, type=int, help="Port to listen on")
@click.option("--host", default="127.0.0.1", help="Host to bind to")
def dashboard(port: int, host: str) -> None:
    """Launch the live intelligence dashboard."""
    from .dashboard.app import run as run_dashboard

    console.print(
        f"[bold]Starting Intelligence Dashboard[/bold] on http://{host}:{port}"
    )
    run_dashboard(host=host, port=port)


@main.command()
@click.option(
    "--output", "-o", type=click.Path(), default=None, help="Output file path"
)
@click.option("--title", "-t", default=None, help="Report title")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["pdf", "html"]),
    default="pdf",
    help="Output format",
)
@click.option(
    "--sections", "-s", default=None, help="Comma-separated section names to include"
)
def report(
    output: str | None, title: str | None, fmt: str, sections: str | None
) -> None:
    """Generate a PDF or HTML intelligence report."""
    from .reports import generate_report

    f = _get_fetcher()
    section_list = [s.strip() for s in sections.split(",")] if sections else None

    with console.status("[bold]Generating report..."):
        result = asyncio.run(
            generate_report(
                f, output_path=output, title=title, sections=section_list, fmt=fmt
            )
        )

    if "error" in result:
        console.print(f"[red]Error:[/red] {result['error']}")
        if "fallback" in result:
            console.print(f"[yellow]{result['fallback']}[/yellow]")
        return

    console.print(
        Panel(
            f"[bold green]Report generated[/bold green]\n\n"
            f"Path: {result['path']}\n"
            f"Format: {result['format']}\n"
            f"Size: {result['size_bytes']:,} bytes\n"
            f"Sections: {', '.join(result['sections_included'])}\n"
            f"Time: {result['generation_seconds']}s"
            + (
                f"\n[yellow]Failed: {', '.join(result['sections_failed'])}[/yellow]"
                if result["sections_failed"]
                else ""
            ),
            title="Intelligence Report",
            border_style="green",
        )
    )


if __name__ == "__main__":
    main()
