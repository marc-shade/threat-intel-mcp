"""Country Instability Index (CII) computation.

Pure scoring functions that transform raw data into instability scores.
"""

import logging

logger = logging.getLogger("world-intel-mcp.analysis.instability")


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


def compute_cii(
    conflict: float = 0.0,
    economic: float = 0.0,
    humanitarian: float = 0.0,
    infrastructure: float = 0.0,
    military: float = 0.0,
) -> dict:
    """Compute Country Instability Index (0-100) from component scores.

    Returns dict with index, components, and risk_level.
    """
    total = conflict + economic + humanitarian + infrastructure + military
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
            "economic_stress": round(economic, 1),
            "humanitarian_crisis": round(humanitarian, 1),
            "infrastructure_disruption": round(infrastructure, 1),
            "military_activity": round(military, 1),
        },
        "risk_level": risk_level,
    }
