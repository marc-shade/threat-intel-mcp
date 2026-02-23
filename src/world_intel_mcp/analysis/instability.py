"""Country Instability Index (CII) computation.

Pure scoring functions that transform raw data into instability scores.

CII v1 scorers (score_conflict_intensity, score_economic_stress, etc.) are
kept for backward compatibility. CII v2 uses weighted component scoring via
compute_cii() with new domain scorers (score_unrest, score_conflict_v2,
score_security, score_information).
"""

import logging

logger = logging.getLogger("world-intel-mcp.analysis.instability")


# ---------------------------------------------------------------------------
# CII v2 weights
# ---------------------------------------------------------------------------

CII_WEIGHTS: dict[str, float] = {
    "unrest": 0.25,
    "conflict": 0.30,
    "security": 0.20,
    "information": 0.25,
}


# ---------------------------------------------------------------------------
# CII v1 scorers (kept for backward compatibility)
# ---------------------------------------------------------------------------

def score_conflict_intensity(event_count: int, days: int = 30) -> float:
    """Score conflict intensity 0-20 based on event count per period."""
    daily_rate = event_count / max(days, 1)
    # 0 events = 0, 10+/day = 20
    return min(20.0, daily_rate * 2.0)


def score_economic_stress(inflation_rate: float | None, gdp_growth: float | None) -> float:
    """Score economic stress 0-20 from inflation and GDP growth."""
    score = 0.0
    if inflation_rate is not None:
        # High inflation (>20%) = 10, moderate (>10%) = 5
        if inflation_rate > 20:
            score += 10.0
        elif inflation_rate > 10:
            score += 5.0
        elif inflation_rate > 5:
            score += 2.0
    if gdp_growth is not None:
        # Negative GDP = 10, stagnant = 5
        if gdp_growth < -5:
            score += 10.0
        elif gdp_growth < 0:
            score += 7.0
        elif gdp_growth < 1:
            score += 3.0
    return min(20.0, score)


def score_humanitarian_crisis(dataset_count: int, displacement_total: int = 0) -> float:
    """Score humanitarian crisis 0-20 based on HDX datasets and displacement."""
    score = 0.0
    # Many crisis datasets = high concern
    score += min(10.0, dataset_count * 0.5)
    # Displacement
    if displacement_total > 1_000_000:
        score += 10.0
    elif displacement_total > 100_000:
        score += 5.0
    return min(20.0, score)


def score_infrastructure_disruption(outage_count: int, cable_warnings: int = 0) -> float:
    """Score infrastructure disruption 0-20."""
    score = 0.0
    score += min(10.0, outage_count * 2.0)
    score += min(10.0, cable_warnings * 2.5)
    return min(20.0, score)


def score_military_activity(aircraft_count: int, flight_density: float = 0.0) -> float:
    """Score military activity 0-20 based on aircraft presence."""
    score = 0.0
    if aircraft_count > 50:
        score = 20.0
    elif aircraft_count > 20:
        score = 15.0
    elif aircraft_count > 10:
        score = 10.0
    elif aircraft_count > 5:
        score = 5.0
    elif aircraft_count > 0:
        score = 2.0
    return score


# ---------------------------------------------------------------------------
# CII v2 component scorers (0-25 each)
# ---------------------------------------------------------------------------

def score_unrest(protest_count: int = 0, riot_count: int = 0) -> float:
    """Score unrest 0-25 from protests and riots."""
    # Protests: 0=0, 50+=15
    protest_score = min(15.0, protest_count * 0.3)
    # Riots: 0=0, 20+=10
    riot_score = min(10.0, riot_count * 0.5)
    return min(25.0, protest_score + riot_score)


def score_conflict_v2(
    event_count: int = 0,
    fatalities: int = 0,
    days: int = 30,
) -> float:
    """Score conflict 0-25 from armed conflict events and fatalities."""
    daily_rate = event_count / max(days, 1)
    # 0 events/day = 0, 15+/day = 15
    event_score = min(15.0, daily_rate * 1.0)
    # Fatalities: 0=0, 1000+=10
    fat_score = min(10.0, fatalities / 100.0)
    return min(25.0, event_score + fat_score)


def score_security(
    military_count: int = 0,
    outage_count: int = 0,
    cable_warnings: int = 0,
) -> float:
    """Score security 0-25 from military activity and infrastructure disruption."""
    # Military: 0=0, 50+=12
    mil_score = min(12.0, military_count * 0.24)
    # Outages: 0=0, 5+=8
    outage_score = min(8.0, outage_count * 1.6)
    # Cable warnings: 0=0, 3+=5
    cable_score = min(5.0, cable_warnings * 1.67)
    return min(25.0, mil_score + outage_score + cable_score)


def score_information(
    news_velocity: int = 0,
    trending_count: int = 0,
) -> float:
    """Score information environment 0-25 from news velocity and trending keywords."""
    # News velocity (articles mentioning country in last 24h): 0=0, 100+=15
    news_score = min(15.0, news_velocity * 0.15)
    # Trending keyword mentions: 0=0, 20+=10
    trend_score = min(10.0, trending_count * 0.5)
    return min(25.0, news_score + trend_score)


# ---------------------------------------------------------------------------
# CII v2 computation
# ---------------------------------------------------------------------------

def compute_cii(
    unrest: float = 0.0,
    conflict: float = 0.0,
    security: float = 0.0,
    information: float = 0.0,
    event_multiplier: float = 1.0,
    ucdp_floor: float | None = None,
    focal_boost: float = 0.0,
    displacement_boost: float = 0.0,
    # v1 compat: if these are passed, use v1 mode
    economic: float | None = None,
    humanitarian: float | None = None,
    infrastructure: float | None = None,
    military: float | None = None,
) -> dict:
    """Compute Country Instability Index (0-100).

    CII v2: Weighted multi-signal instability index using 4 domains
    (unrest, conflict, security, information) scaled 0-25 each.

    Falls back to v1 simple sum if legacy component names are passed.
    """
    # Detect v1 call pattern (old callers pass economic/humanitarian/etc.)
    if economic is not None or humanitarian is not None or infrastructure is not None or military is not None:
        total = (
            conflict
            + (economic or 0.0)
            + (humanitarian or 0.0)
            + (infrastructure or 0.0)
            + (military or 0.0)
        )
        total = min(100.0, max(0.0, total))

        if total >= 75:
            risk_level = "critical"
        elif total >= 50:
            risk_level = "high"
        elif total >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "instability_index": round(total, 1),
            "components": {
                "conflict_intensity": round(conflict, 1),
                "economic_stress": round(economic or 0.0, 1),
                "humanitarian_crisis": round(humanitarian or 0.0, 1),
                "infrastructure_disruption": round(infrastructure or 0.0, 1),
                "military_activity": round(military or 0.0, 1),
            },
            "risk_level": risk_level,
        }

    # CII v2: weighted scoring
    raw = (
        unrest * CII_WEIGHTS["unrest"]
        + conflict * CII_WEIGHTS["conflict"]
        + security * CII_WEIGHTS["security"]
        + information * CII_WEIGHTS["information"]
    )
    # Components are 0-25 each, weights sum to 1.0, raw max = 25
    # Normalize to 0-100
    scaled = raw * 4.0

    # Apply country-specific multiplier
    adjusted = scaled * event_multiplier

    # Apply boosts
    adjusted += focal_boost + displacement_boost

    # Apply UCDP floor (wars can't score below a threshold)
    if ucdp_floor is not None:
        adjusted = max(adjusted, ucdp_floor)

    total = min(100.0, max(0.0, adjusted))

    if total >= 75:
        risk_level = "critical"
    elif total >= 50:
        risk_level = "high"
    elif total >= 25:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "instability_index": round(total, 1),
        "components": {
            "unrest": round(unrest, 1),
            "conflict": round(conflict, 1),
            "security": round(security, 1),
            "information": round(information, 1),
        },
        "weights": dict(CII_WEIGHTS),
        "event_multiplier": event_multiplier,
        "focal_boost": round(focal_boost, 1),
        "displacement_boost": round(displacement_boost, 1),
        "ucdp_floor": ucdp_floor,
        "risk_level": risk_level,
    }
