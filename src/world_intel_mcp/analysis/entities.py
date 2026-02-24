"""Named entity extraction from text.

Regex-based NER for countries, leaders, organizations, companies, CVEs,
and APT groups. No ML dependencies — uses reference data from config/.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ..config.countries import TIER1_COUNTRIES
from ..config.entities import LEADERS, ORGANIZATIONS, COMPANIES, APT_GROUPS


# Pre-compile patterns
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_APT_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(a) for a in sorted(APT_GROUPS, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)

# Build country keyword → iso3 lookup (lowercase)
_COUNTRY_KW: dict[str, str] = {}
for _iso3, _info in TIER1_COUNTRIES.items():
    for _kw in _info["keywords"]:
        _COUNTRY_KW[_kw.lower()] = _iso3
    _COUNTRY_KW[_info["name"].lower()] = _iso3
    _COUNTRY_KW[_iso3.lower()] = _iso3

# Build leader name lookup (lowercase)
_LEADER_KW: dict[str, dict] = {k.lower(): v for k, v in LEADERS.items()}

# Build org lookup (lowercase)
_ORG_KW: dict[str, dict] = {k.lower(): v for k, v in ORGANIZATIONS.items()}

# Build company lookup (lowercase)
_COMPANY_KW: dict[str, dict] = {k.lower(): v for k, v in COMPANIES.items()}


def extract_entities(text: str) -> dict:
    """Extract named entities from text.

    Returns dict with entities grouped by type, plus counts and metadata.
    """
    text_lower = text.lower()
    words_set = set(text_lower.split())

    countries: list[dict] = []
    leaders: list[dict] = []
    organizations: list[dict] = []
    companies: list[dict] = []
    cves: list[str] = []
    apts: list[str] = []

    seen_countries: set[str] = set()
    seen_leaders: set[str] = set()
    seen_orgs: set[str] = set()
    seen_companies: set[str] = set()

    # Countries (keyword search in text)
    for kw, iso3 in _COUNTRY_KW.items():
        if iso3 in seen_countries:
            continue
        if kw in text_lower:
            seen_countries.add(iso3)
            info = TIER1_COUNTRIES[iso3]
            countries.append({
                "iso3": iso3,
                "name": info["name"],
                "baseline_risk": info["baseline_risk"],
            })

    # Leaders (match longest first to avoid partial matches)
    for kw in sorted(_LEADER_KW.keys(), key=len, reverse=True):
        info = _LEADER_KW[kw]
        if info["name"] in seen_leaders:
            continue
        if kw in text_lower:
            seen_leaders.add(info["name"])
            leaders.append({
                "name": info["name"],
                "title": info["title"],
                "country": info["country"],
            })

    # Organizations
    for kw in sorted(_ORG_KW.keys(), key=len, reverse=True):
        info = _ORG_KW[kw]
        if info["abbrev"] in seen_orgs:
            continue
        # For short abbreviations (2-4 chars), require word boundary
        if len(kw) <= 4:
            if kw in words_set:
                seen_orgs.add(info["abbrev"])
                organizations.append({
                    "name": info["abbrev"],
                    "type": info["type"],
                })
        elif kw in text_lower:
            seen_orgs.add(info["abbrev"])
            organizations.append({
                "name": info["abbrev"],
                "type": info["type"],
            })

    # Companies
    for kw in sorted(_COMPANY_KW.keys(), key=len, reverse=True):
        info = _COMPANY_KW[kw]
        if kw in seen_companies:
            continue
        if kw in text_lower:
            seen_companies.add(kw)
            companies.append({
                "name": kw.title(),
                "ticker": info["ticker"],
                "sector": info["sector"],
            })

    # CVEs
    cves = list(set(_CVE_RE.findall(text)))

    # APTs
    apt_matches = _APT_RE.findall(text)
    apts = list(set(m.lower() for m in apt_matches))

    total = len(countries) + len(leaders) + len(organizations) + len(companies) + len(cves) + len(apts)

    return {
        "entities": {
            "countries": countries,
            "leaders": leaders,
            "organizations": organizations,
            "companies": companies,
            "cves": cves,
            "apt_groups": apts,
        },
        "by_type": {
            "countries": len(countries),
            "leaders": len(leaders),
            "organizations": len(organizations),
            "companies": len(companies),
            "cves": len(cves),
            "apt_groups": len(apts),
        },
        "total_entities": total,
        "source": "regex-ner",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def fetch_entity_extraction(fetcher, text: str | None = None, use_news: bool = True) -> dict:
    """Extract entities from provided text or recent news headlines.

    If text is provided, extract from that. Otherwise fetch recent news
    headlines and extract entities from the combined text.
    """
    if text:
        return extract_entities(text)

    if use_news:
        from ..sources import news
        feed_data = await news.fetch_news_feed(fetcher, limit=100)
        items = feed_data.get("items", [])
        combined = " ".join(
            (item.get("title", "") + " " + item.get("summary", ""))
            for item in items
        )
        result = extract_entities(combined)
        result["input_source"] = "news_feed"
        result["items_analyzed"] = len(items)
        return result

    return extract_entities("")
