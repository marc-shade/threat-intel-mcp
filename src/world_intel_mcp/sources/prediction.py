"""Prediction market data sources for world-intel-mcp.

Fetches active prediction markets from Polymarket via their public
Gamma API.  Every function takes a Fetcher instance as its first
argument and returns a dict (or empty results when upstream calls fail).
"""

import json
import logging
from datetime import datetime, timezone

from ..fetcher import Fetcher

logger = logging.getLogger("world-intel-mcp.sources.prediction")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GAMMA_MARKETS_URL = "https://gamma-api.polymarket.com/markets"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_outcome_prices(raw: str | None) -> float | None:
    """Parse the outcomePrices JSON string and return YES probability.

    ``outcomePrices`` is a JSON-encoded list like ``"[0.85, 0.15]"``
    where the first element represents the YES probability.
    Returns None if the value is missing or unparseable.
    """
    if raw is None:
        return None
    try:
        prices = json.loads(raw)
        if isinstance(prices, list) and len(prices) > 0:
            return float(prices[0])
    except (json.JSONDecodeError, ValueError, TypeError, IndexError):
        logger.debug("Failed to parse outcomePrices: %r", raw)
    return None


def _classify_sentiment(yes_probability: float) -> str:
    """Classify a YES probability into a human-readable sentiment label."""
    if yes_probability > 0.85:
        return "strong_yes"
    if yes_probability > 0.65:
        return "leaning_yes"
    if yes_probability < 0.15:
        return "strong_no"
    if yes_probability < 0.35:
        return "leaning_no"
    return "uncertain"


def _safe_float(value) -> float:
    """Convert a value to float, returning 0.0 on failure."""
    if value is None:
        return 0.0
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def fetch_prediction_markets(fetcher: Fetcher, limit: int = 20) -> dict:
    """Fetch active prediction markets from Polymarket sorted by 24h volume.

    Uses the Polymarket Gamma API to retrieve currently active (non-closed)
    markets ordered by trading volume.

    Returns::

        {"markets": [...], "count": N, "source": "polymarket",
         "timestamp": "<iso>"}
    """
    params = {
        "limit": str(limit),
        "active": "true",
        "closed": "false",
        "order": "volume24hr",
        "ascending": "false",
    }

    data = await fetcher.get_json(
        _GAMMA_MARKETS_URL,
        source="polymarket",
        cache_key=f"prediction:polymarket:{limit}",
        cache_ttl=300,
        params=params,
    )

    if data is None:
        return {
            "markets": [],
            "count": 0,
            "source": "polymarket",
            "timestamp": _utc_now_iso(),
        }

    if not isinstance(data, list):
        logger.warning("Unexpected Polymarket response type: %s", type(data).__name__)
        return {
            "markets": [],
            "count": 0,
            "source": "polymarket",
            "timestamp": _utc_now_iso(),
        }

    markets: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue

        yes_probability = _parse_outcome_prices(item.get("outcomePrices"))
        if yes_probability is None:
            # Skip markets with unparseable outcome data
            continue

        volume_24h = _safe_float(item.get("volume24hr"))
        total_volume = _safe_float(item.get("volume"))
        liquidity = _safe_float(item.get("liquidity"))
        slug = item.get("slug", "")

        markets.append({
            "question": item.get("question", ""),
            "yes_probability": round(yes_probability, 4),
            "sentiment": _classify_sentiment(yes_probability),
            "volume_24h": volume_24h,
            "total_volume": total_volume,
            "liquidity": liquidity,
            "category": item.get("category", ""),
            "url": f"https://polymarket.com/event/{slug}" if slug else "",
        })

    # Ensure descending sort by 24h volume (API should already return
    # sorted, but enforce it defensively)
    markets.sort(key=lambda m: m["volume_24h"], reverse=True)

    return {
        "markets": markets,
        "count": len(markets),
        "source": "polymarket",
        "timestamp": _utc_now_iso(),
    }
