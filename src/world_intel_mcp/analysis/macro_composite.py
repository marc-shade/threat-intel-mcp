"""Macro signal composite — synthesize market signals into an actionable verdict.

Aggregates Fear & Greed, VIX, sector breadth, DXY, BTC technicals, and
10Y yield into a single weighted score with a market stance verdict.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.analysis.macro_composite")

# Signal weights (sum to 1.0)
SIGNAL_WEIGHTS: dict[str, float] = {
    "fear_greed": 0.25,
    "vix": 0.20,
    "sector_breadth": 0.20,
    "dxy": 0.15,
    "btc": 0.10,
    "yield_10y": 0.10,
}

_VERDICT_BANDS: list[tuple[float, str]] = [
    (80, "RISK_ON"),
    (60, "CONSTRUCTIVE"),
    (40, "NEUTRAL"),
    (20, "CAUTIOUS"),
    (0, "STRONG_CAUTION"),
]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _classify_vix(value: float | None) -> tuple[str, float]:
    """Classify VIX into a label and a 0-100 score (inverted: low VIX = high score)."""
    if value is None:
        return "unavailable", 50.0
    if value < 15:
        return "complacent", 90.0
    elif value < 20:
        return "calm", 70.0
    elif value < 30:
        return "cautious", 40.0
    else:
        return "fear", 10.0


def _classify_dxy(value: float | None) -> tuple[str, float]:
    """Classify DXY and produce a 0-100 risk-on score.

    Weak dollar is generally risk-on for equities/crypto.
    """
    if value is None:
        return "unavailable", 50.0
    if value < 100:
        return "weak dollar", 75.0
    elif value <= 105:
        return "neutral", 50.0
    else:
        return "strong dollar", 25.0


def _classify_yield(value: float | None) -> tuple[str, float]:
    """Classify 10Y yield (in percentage points from Yahoo ^TNX format)."""
    if value is None:
        return "unavailable", 50.0
    if value < 3.0:
        return "accommodative", 80.0
    elif value < 4.0:
        return "moderate", 60.0
    elif value < 5.0:
        return "elevated", 35.0
    else:
        return "restrictive", 15.0


def _classify_btc(technicals: dict) -> tuple[str, float, float | None]:
    """Classify BTC technicals into a signal and a 0-100 score."""
    cross = technicals.get("cross_signal", "neutral")
    mayer = technicals.get("mayer_multiple")

    if cross == "golden_cross":
        label = "bullish"
        score = 75.0
    elif cross == "death_cross":
        label = "bearish"
        score = 25.0
    else:
        label = "neutral"
        score = 50.0

    # Mayer multiple adjustment: >2.4 = overheated, <0.8 = undervalued
    if mayer is not None:
        if mayer > 2.4:
            score = max(score - 20, 0)
            label = "overheated"
        elif mayer < 0.8:
            score = min(score + 20, 100)
            label = "undervalued"

    return label, score, mayer


def _compute_sector_breadth(heatmap: dict) -> tuple[int, int, float]:
    """Count positive vs negative sectors and produce a 0-100 score."""
    sectors = heatmap.get("sectors", [])
    positive = sum(1 for s in sectors if (s.get("change_pct") or 0) > 0)
    negative = sum(1 for s in sectors if (s.get("change_pct") or 0) < 0)
    total = positive + negative
    if total == 0:
        return 0, 0, 50.0
    score = (positive / total) * 100
    return positive, negative, score


def _verdict(score: float) -> str:
    """Map composite score to verdict string."""
    for threshold, label in _VERDICT_BANDS:
        if score >= threshold:
            return label
    return "STRONG_CAUTION"


async def _safe(coro, label: str):
    """Run a coroutine, swallowing exceptions."""
    try:
        return await coro
    except Exception as exc:
        logger.warning("MacroComposite: %s failed: %s", label, exc)
        return {}


async def fetch_macro_composite(fetcher: Fetcher) -> dict:
    """Compute a weighted macro market composite from existing signal sources.

    Fetches macro signals, sector heatmap, and BTC technicals in parallel,
    then scores each dimension and produces an overall market verdict.

    Returns:
        Dict with verdict, score, individual signals, top/bottom sectors.
    """
    from ..sources.markets import (
        fetch_btc_technicals,
        fetch_macro_signals,
        fetch_sector_heatmap,
    )

    (
        macro_data,
        heatmap_data,
        btc_data,
    ) = await asyncio.gather(
        _safe(fetch_macro_signals(fetcher), "macro_signals"),
        _safe(fetch_sector_heatmap(fetcher), "sector_heatmap"),
        _safe(fetch_btc_technicals(fetcher), "btc_technicals"),
    )

    signals_raw = macro_data.get("signals", {}) if macro_data else {}

    # --- Fear & Greed ---
    fg_data = signals_raw.get("fear_greed") or {}
    fg_value = fg_data.get("value")
    fg_label = fg_data.get("classification", "unavailable")
    fg_score = float(fg_value) if fg_value is not None else 50.0

    # --- VIX ---
    vix_data = signals_raw.get("vix") or {}
    vix_value = vix_data.get("price")
    vix_label, vix_score = _classify_vix(vix_value)

    # --- DXY ---
    dxy_data = signals_raw.get("dxy") or {}
    dxy_value = dxy_data.get("price")
    dxy_label, dxy_score = _classify_dxy(dxy_value)

    # --- 10Y Yield ---
    yield_data = signals_raw.get("treasury_10y") or {}
    yield_value = yield_data.get("price")
    yield_label, yield_score = _classify_yield(yield_value)

    # --- Sector breadth ---
    heatmap = heatmap_data if heatmap_data else {}
    positive, negative, breadth_score = _compute_sector_breadth(heatmap)

    # --- BTC ---
    btc = btc_data if btc_data else {}
    btc_label, btc_score, btc_mayer = _classify_btc(btc)

    # --- Weighted composite ---
    component_scores = {
        "fear_greed": fg_score,
        "vix": vix_score,
        "sector_breadth": breadth_score,
        "dxy": dxy_score,
        "btc": btc_score,
        "yield_10y": yield_score,
    }

    composite = sum(
        component_scores[name] * weight for name, weight in SIGNAL_WEIGHTS.items()
    )
    composite = min(100.0, max(0.0, composite))

    # --- Top / bottom sectors ---
    sectors = heatmap.get("sectors", [])
    sorted_sectors = sorted(
        sectors, key=lambda s: s.get("change_pct") or 0, reverse=True
    )
    top_sectors = [
        {"name": s.get("name"), "change_pct": s.get("change_pct")}
        for s in sorted_sectors[:3]
    ]
    bottom_sectors = [
        {"name": s.get("name"), "change_pct": s.get("change_pct")}
        for s in sorted_sectors[-3:]
    ]

    return {
        "verdict": _verdict(composite),
        "score": round(composite, 1),
        "signals": {
            "fear_greed": {
                "value": fg_value,
                "label": fg_label,
                "weight": SIGNAL_WEIGHTS["fear_greed"],
            },
            "vix": {
                "value": vix_value,
                "label": vix_label,
                "weight": SIGNAL_WEIGHTS["vix"],
            },
            "sector_breadth": {
                "positive": positive,
                "negative": negative,
                "weight": SIGNAL_WEIGHTS["sector_breadth"],
            },
            "dxy": {
                "value": dxy_value,
                "label": dxy_label,
                "weight": SIGNAL_WEIGHTS["dxy"],
            },
            "btc": {
                "signal": btc_label,
                "mayer": btc_mayer,
                "weight": SIGNAL_WEIGHTS["btc"],
            },
            "yield_10y": {
                "value": yield_value,
                "label": yield_label,
                "weight": SIGNAL_WEIGHTS["yield_10y"],
            },
        },
        "top_sectors": top_sectors,
        "bottom_sectors": bottom_sectors,
        "fetched_at": _utc_now_iso(),
        "source": "composite",
    }
