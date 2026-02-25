"""Launch facilities and spaceports worldwide.

Pure data module — no I/O, no external dependencies.
Sources: FAA, ESA, CSIS Aerospace, press reporting.
"""

from __future__ import annotations

SPACEPORTS: list[dict] = [
    # United States
    {"name": "Cape Canaveral SFS / KSC", "country": "USA", "iso3": "USA", "lat": 28.56, "lon": -80.58, "operator": "USSF / NASA", "type": "orbital", "status": "active", "pads": 7, "notes": "Primary US orbital launch site, SpaceX LC-40, NASA LC-39A/B"},
    {"name": "Vandenberg SFB", "country": "USA", "iso3": "USA", "lat": 34.73, "lon": -120.57, "operator": "USSF", "type": "orbital", "status": "active", "pads": 4, "notes": "Polar/SSO launches, SpaceX SLC-4E"},
    {"name": "SpaceX Starbase (Boca Chica)", "country": "USA", "iso3": "USA", "lat": 25.99, "lon": -97.16, "operator": "SpaceX", "type": "orbital", "status": "active", "pads": 2, "notes": "Starship development and launch facility"},
    {"name": "Wallops Flight Facility", "country": "USA", "iso3": "USA", "lat": 37.83, "lon": -75.49, "operator": "NASA", "type": "orbital", "status": "active", "pads": 2, "notes": "Antares/Minotaur, ISS cargo"},
    {"name": "Kodiak Launch Complex", "country": "USA", "iso3": "USA", "lat": 57.44, "lon": -152.34, "operator": "Alaska Aerospace", "type": "orbital", "status": "active", "pads": 2, "notes": "Polar orbits, Astra launches"},
    {"name": "Mojave Air and Space Port", "country": "USA", "iso3": "USA", "lat": 35.06, "lon": -118.15, "operator": "Mojave Air & Space Port", "type": "suborbital", "status": "active", "pads": 0, "notes": "Horizontal launch, Virgin Orbit (defunct), test facility"},
    {"name": "Spaceport America", "country": "USA", "iso3": "USA", "lat": 32.99, "lon": -106.97, "operator": "New Mexico SAA", "type": "suborbital", "status": "active", "pads": 1, "notes": "Virgin Galactic SpaceShipTwo"},
    # Russia
    {"name": "Baikonur Cosmodrome", "country": "Kazakhstan", "iso3": "KAZ", "lat": 45.96, "lon": 63.31, "operator": "Roscosmos (leased)", "type": "orbital", "status": "active", "pads": 6, "notes": "World's first spaceport, Soyuz, Proton"},
    {"name": "Plesetsk Cosmodrome", "country": "Russia", "iso3": "RUS", "lat": 62.93, "lon": 40.58, "operator": "Russian MoD", "type": "orbital", "status": "active", "pads": 4, "notes": "Military launches, Angara, ICBM tests"},
    {"name": "Vostochny Cosmodrome", "country": "Russia", "iso3": "RUS", "lat": 51.88, "lon": 128.33, "operator": "Roscosmos", "type": "orbital", "status": "active", "pads": 2, "notes": "New Russian civilian spaceport, Amur region"},
    # China
    {"name": "Jiuquan Satellite Launch Center", "country": "China", "iso3": "CHN", "lat": 40.96, "lon": 100.30, "operator": "PLA SSF", "type": "orbital", "status": "active", "pads": 4, "notes": "First Chinese crewed launches, Shenzhou"},
    {"name": "Xichang Satellite Launch Center", "country": "China", "iso3": "CHN", "lat": 28.25, "lon": 102.03, "operator": "PLA SSF", "type": "orbital", "status": "active", "pads": 3, "notes": "GEO launches, BeiDou, Long March 3B"},
    {"name": "Taiyuan Satellite Launch Center", "country": "China", "iso3": "CHN", "lat": 38.85, "lon": 111.61, "operator": "PLA SSF", "type": "orbital", "status": "active", "pads": 2, "notes": "SSO/polar orbits"},
    {"name": "Wenchang Space Launch Site", "country": "China", "iso3": "CHN", "lat": 19.61, "lon": 110.95, "operator": "PLA SSF", "type": "orbital", "status": "active", "pads": 3, "notes": "Newest, largest Chinese vehicles, Long March 5/7"},
    {"name": "Haiyang Commercial Launch Site", "country": "China", "iso3": "CHN", "lat": 36.73, "lon": 121.13, "operator": "Commercial (CAS Space)", "type": "orbital", "status": "active", "pads": 2, "notes": "First Chinese commercial launch site, 2024"},
    # Europe
    {"name": "Guiana Space Centre (Kourou)", "country": "French Guiana", "iso3": "GUF", "lat": 5.24, "lon": -52.77, "operator": "ESA / CNES / Arianespace", "type": "orbital", "status": "active", "pads": 4, "notes": "Ariane 6, Vega-C, Soyuz (suspended), equatorial advantage"},
    {"name": "SaxaVord Spaceport", "country": "UK", "iso3": "GBR", "lat": 60.82, "lon": -0.86, "operator": "SaxaVord UK", "type": "orbital", "status": "construction", "pads": 3, "notes": "UK's first vertical launch site, Shetland Islands"},
    {"name": "Andøya Spaceport", "country": "Norway", "iso3": "NOR", "lat": 69.29, "lon": 16.02, "operator": "Andøya Space", "type": "orbital", "status": "active", "pads": 2, "notes": "Northernmost orbital-class spaceport, polar orbits"},
    # India
    {"name": "Satish Dhawan Space Centre (Sriharikota)", "country": "India", "iso3": "IND", "lat": 13.72, "lon": 80.23, "operator": "ISRO", "type": "orbital", "status": "active", "pads": 3, "notes": "Primary Indian launch site, GSLV, PSLV, LVM3, Gaganyaan"},
    {"name": "Kulasekarapattinam (Tamil Nadu)", "country": "India", "iso3": "IND", "lat": 8.56, "lon": 78.08, "operator": "ISRO", "type": "orbital", "status": "construction", "pads": 1, "notes": "Small satellite launch complex"},
    # Japan
    {"name": "Tanegashima Space Center", "country": "Japan", "iso3": "JPN", "lat": 30.40, "lon": 131.00, "operator": "JAXA", "type": "orbital", "status": "active", "pads": 2, "notes": "H-IIA/H3, southernmost Japanese island"},
    {"name": "Uchinoura Space Center", "country": "Japan", "iso3": "JPN", "lat": 31.25, "lon": 131.08, "operator": "JAXA", "type": "orbital", "status": "active", "pads": 2, "notes": "Epsilon rocket, sounding rockets"},
    # Others
    {"name": "Rocket Lab Launch Complex 1", "country": "New Zealand", "iso3": "NZL", "lat": -39.26, "lon": 177.86, "operator": "Rocket Lab", "type": "orbital", "status": "active", "pads": 2, "notes": "Electron launches, Mahia Peninsula"},
    {"name": "Semnan Space Center", "country": "Iran", "iso3": "IRN", "lat": 35.23, "lon": 53.92, "operator": "ISA / IRGC", "type": "orbital", "status": "active", "pads": 2, "notes": "Simorgh, Qased, dual-use ICBM concern"},
    {"name": "Sohae Satellite Launching Station", "country": "North Korea", "iso3": "PRK", "lat": 39.66, "lon": 124.71, "operator": "NADA", "type": "orbital", "status": "active", "pads": 1, "notes": "Unha/Chollima launches, ICBM test concern"},
    {"name": "Palmachim Airbase", "country": "Israel", "iso3": "ISR", "lat": 31.88, "lon": 34.69, "operator": "IAI / IMoD", "type": "orbital", "status": "active", "pads": 1, "notes": "Shavit launches (westward retrograde orbit)"},
    {"name": "Alcântara Launch Center", "country": "Brazil", "iso3": "BRA", "lat": -2.37, "lon": -44.40, "operator": "FAB / AEB", "type": "orbital", "status": "active", "pads": 2, "notes": "Near equator, US technology safeguards agreement"},
]


def query_spaceports(
    country: str | None = None,
    status: str | None = None,
    spaceport_type: str | None = None,
    operator: str | None = None,
) -> list[dict]:
    """Filter spaceports by country, status, type, or operator."""
    results = []
    for sp in SPACEPORTS:
        if country:
            c = country.lower()
            if c not in (sp["country"].lower(), sp["iso3"].lower()):
                continue
        if status and sp["status"] != status.lower():
            continue
        if spaceport_type and sp["type"] != spaceport_type.lower():
            continue
        if operator:
            if operator.lower() not in sp["operator"].lower():
                continue
        results.append(sp)
    return results
