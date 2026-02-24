"""Keyword-based event threat classification.

Fast classifier with 14 categories and severity scoring. No ML deps.
Designed as the first pass; an LLM can refine confidence later.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Category keyword patterns (ordered by specificity)
# ---------------------------------------------------------------------------

CATEGORIES: dict[str, dict] = {
    "nuclear": {
        "keywords": [
            "nuclear", "atomic", "uranium", "plutonium", "warhead",
            "icbm", "ballistic missile", "nuclear test", "radiation",
            "enrichment", "nonproliferation", "iaea", "dirty bomb",
        ],
        "severity_base": 9,
    },
    "terrorism": {
        "keywords": [
            "terrorist", "terrorism", "suicide bomb", "car bomb", "ied",
            "hostage", "kidnapping", "beheading", "mass shooting",
            "lone wolf", "radicalization", "jihad", "extremist",
        ],
        "severity_base": 9,
    },
    "military": {
        "keywords": [
            "military", "troops", "soldier", "artillery", "airstrike",
            "bombing", "invasion", "offensive", "deployed", "nato",
            "warship", "submarine", "fighter jet", "drone strike",
            "mobilization", "ceasefire", "frontline", "casualties",
        ],
        "severity_base": 8,
    },
    "cyber": {
        "keywords": [
            "cyber", "hack", "ransomware", "malware", "phishing",
            "data breach", "ddos", "vulnerability", "exploit", "cve-",
            "zero-day", "apt", "botnet", "credential", "encryption",
        ],
        "severity_base": 7,
    },
    "political": {
        "keywords": [
            "election", "coup", "protest", "demonstration", "sanctions",
            "embargo", "diplomatic", "parliament", "congress",
            "impeachment", "referendum", "regime", "martial law",
            "authoritarian", "democracy", "opposition",
        ],
        "severity_base": 6,
    },
    "economic": {
        "keywords": [
            "recession", "inflation", "default", "debt crisis",
            "currency collapse", "bank run", "stock crash", "layoffs",
            "trade war", "tariff", "supply chain", "shortage",
        ],
        "severity_base": 6,
    },
    "health": {
        "keywords": [
            "pandemic", "epidemic", "outbreak", "virus", "pathogen",
            "vaccine", "quarantine", "who emergency", "mortality",
            "infection", "ebola", "bird flu", "h5n1", "mpox",
        ],
        "severity_base": 7,
    },
    "climate": {
        "keywords": [
            "hurricane", "typhoon", "cyclone", "earthquake", "tsunami",
            "flood", "drought", "wildfire", "heatwave", "glacier",
            "sea level", "emission", "carbon", "climate change",
        ],
        "severity_base": 6,
    },
    "infrastructure": {
        "keywords": [
            "power outage", "blackout", "pipeline", "cable cut",
            "internet outage", "grid failure", "dam collapse",
            "bridge collapse", "port blockade", "supply disruption",
        ],
        "severity_base": 7,
    },
    "maritime": {
        "keywords": [
            "shipping", "strait", "piracy", "naval blockade", "vessel",
            "cargo ship", "tanker", "port", "chokepoint", "seafarer",
            "coast guard", "maritime security",
        ],
        "severity_base": 5,
    },
    "aviation": {
        "keywords": [
            "airspace", "no-fly zone", "intercept", "air defense",
            "airline", "crash", "hijack", "flight ban",
        ],
        "severity_base": 6,
    },
    "energy": {
        "keywords": [
            "oil price", "opec", "gas pipeline", "lng", "refinery",
            "energy crisis", "power grid", "renewable", "solar",
            "wind farm", "battery", "hydrogen",
        ],
        "severity_base": 5,
    },
    "social_unrest": {
        "keywords": [
            "riot", "looting", "tear gas", "water cannon", "curfew",
            "state of emergency", "civil disobedience", "strike",
            "labor dispute", "food riot", "uprising",
        ],
        "severity_base": 7,
    },
    "space": {
        "keywords": [
            "satellite", "space debris", "solar flare", "geomagnetic",
            "space weather", "orbit", "launch", "rocket", "asteroid",
        ],
        "severity_base": 4,
    },
}

# Severity modifiers — keywords that bump severity up
_HIGH_SEVERITY: list[str] = [
    "killed", "dead", "death toll", "massacre", "war crime", "genocide",
    "nuclear", "catastrophic", "critical", "emergency", "mass casualty",
    "destroyed", "collapse", "unprecedented", "worst",
]

_MODERATE_SEVERITY: list[str] = [
    "injured", "wounded", "escalation", "crisis", "threat", "warning",
    "attack", "strike", "explosion", "breach", "violation",
]


def classify_event(text: str) -> dict:
    """Classify text into threat categories with severity scoring.

    Returns dict with primary category, severity (1-10), confidence,
    all matched categories, and matched keywords.
    """
    text_lower = text.lower()
    matches: list[dict] = []

    for cat_name, cat_info in CATEGORIES.items():
        matched_kw = [kw for kw in cat_info["keywords"] if kw in text_lower]
        if matched_kw:
            # Confidence scales with number of keyword hits
            confidence = min(1.0, len(matched_kw) * 0.2 + 0.3)
            matches.append({
                "category": cat_name,
                "keywords_matched": matched_kw,
                "keyword_count": len(matched_kw),
                "severity_base": cat_info["severity_base"],
                "confidence": round(confidence, 2),
            })

    # Sort by keyword count (most specific match first)
    matches.sort(key=lambda m: m["keyword_count"], reverse=True)

    # Compute severity modifier
    severity_mod = 0
    high_hits = [kw for kw in _HIGH_SEVERITY if kw in text_lower]
    mod_hits = [kw for kw in _MODERATE_SEVERITY if kw in text_lower]
    if high_hits:
        severity_mod = 2
    elif mod_hits:
        severity_mod = 1

    primary = matches[0] if matches else None
    severity = min(10, (primary["severity_base"] + severity_mod)) if primary else 0

    return {
        "primary_category": primary["category"] if primary else "unclassified",
        "severity": severity,
        "confidence": primary["confidence"] if primary else 0.0,
        "all_categories": [
            {"category": m["category"], "confidence": m["confidence"], "keywords": m["keywords_matched"]}
            for m in matches
        ],
        "category_count": len(matches),
        "severity_modifiers": high_hits + mod_hits,
        "source": "keyword-classifier",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def fetch_classify_event(fetcher, text: str) -> dict:
    """Classify a text event. Thin async wrapper for MCP dispatch."""
    return classify_event(text)
