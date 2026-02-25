"""AI datacenter clusters worldwide.

Pure data module — no I/O, no external dependencies.
Sources: Data Center Map, Cloudscene, company announcements, press reports.
"""

from __future__ import annotations

AI_DATACENTERS: list[dict] = [
    # United States — Top clusters
    {"name": "Ashburn / Loudoun County", "country": "USA", "iso3": "USA", "lat": 39.04, "lon": -77.49, "region": "Virginia", "power_mw": 4500, "operators": ["AWS", "Microsoft", "Google", "Meta", "Equinix", "Digital Realty"], "notes": "Data Center Alley — largest concentration globally, ~70% of world internet traffic"},
    {"name": "Dallas / Fort Worth", "country": "USA", "iso3": "USA", "lat": 32.90, "lon": -97.04, "region": "Texas", "power_mw": 2200, "operators": ["AWS", "Meta", "Google", "CyrusOne", "QTS"], "notes": "Second largest US cluster, low power costs"},
    {"name": "Phoenix / Mesa", "country": "USA", "iso3": "USA", "lat": 33.44, "lon": -111.94, "region": "Arizona", "power_mw": 1800, "operators": ["Microsoft", "Google", "Meta", "Apple"], "notes": "Rapid expansion, solar power access"},
    {"name": "Council Bluffs", "country": "USA", "iso3": "USA", "lat": 41.26, "lon": -95.86, "region": "Iowa", "power_mw": 1200, "operators": ["Google", "Meta"], "notes": "Google mega-campus, cheap wind power"},
    {"name": "The Dalles", "country": "USA", "iso3": "USA", "lat": 45.60, "lon": -121.18, "region": "Oregon", "power_mw": 900, "operators": ["Google"], "notes": "Google flagship, hydroelectric cooling"},
    {"name": "Quincy", "country": "USA", "iso3": "USA", "lat": 47.23, "lon": -119.85, "region": "Washington", "power_mw": 800, "operators": ["Microsoft", "Yahoo", "Dell"], "notes": "Columbia River hydro power"},
    {"name": "Prineville", "country": "USA", "iso3": "USA", "lat": 44.30, "lon": -120.73, "region": "Oregon", "power_mw": 600, "operators": ["Meta", "Apple"], "notes": "Meta's first custom DC"},
    {"name": "San Jose / Santa Clara", "country": "USA", "iso3": "USA", "lat": 37.35, "lon": -121.95, "region": "California", "power_mw": 1500, "operators": ["Equinix", "CoreSite", "NVIDIA", "Google"], "notes": "Silicon Valley interconnection hub"},
    {"name": "Chicago / Aurora", "country": "USA", "iso3": "USA", "lat": 41.76, "lon": -88.32, "region": "Illinois", "power_mw": 1100, "operators": ["AWS", "Microsoft", "Google", "Digital Realty"], "notes": "Midwest hub, CME/CBOE proximity"},
    {"name": "Atlanta / Douglas County", "country": "USA", "iso3": "USA", "lat": 33.70, "lon": -84.75, "region": "Georgia", "power_mw": 900, "operators": ["Google", "Microsoft", "QTS", "Switch"], "notes": "Southeast US hub"},
    {"name": "Salt Lake City / West Jordan", "country": "USA", "iso3": "USA", "lat": 40.61, "lon": -111.94, "region": "Utah", "power_mw": 600, "operators": ["Meta", "AWS", "C7"], "notes": "NSA Utah Data Center nearby"},
    {"name": "Reno / Sparks", "country": "USA", "iso3": "USA", "lat": 39.53, "lon": -119.81, "region": "Nevada", "power_mw": 500, "operators": ["Apple", "Switch", "Microsoft"], "notes": "Switch SuperNAP campus"},
    {"name": "New Albany", "country": "USA", "iso3": "USA", "lat": 40.08, "lon": -82.81, "region": "Ohio", "power_mw": 1400, "operators": ["Google", "AWS", "Meta", "Microsoft"], "notes": "Ohio Intel fab synergy, massive expansion"},
    {"name": "Papillion / Omaha", "country": "USA", "iso3": "USA", "lat": 41.15, "lon": -96.04, "region": "Nebraska", "power_mw": 500, "operators": ["Meta", "Google"], "notes": "Central US, wind/solar access"},
    # Europe
    {"name": "Amsterdam / Schiphol", "country": "Netherlands", "iso3": "NLD", "lat": 52.30, "lon": 4.76, "region": "North Holland", "power_mw": 800, "operators": ["Equinix", "Digital Realty", "Microsoft"], "notes": "AMS-IX — world's largest IXP, moratorium on new DCs"},
    {"name": "Dublin", "country": "Ireland", "iso3": "IRL", "lat": 53.35, "lon": -6.26, "region": "Leinster", "power_mw": 900, "operators": ["AWS", "Microsoft", "Google", "Meta"], "notes": "EU data sovereignty hub, tax advantages"},
    {"name": "Frankfurt", "country": "Germany", "iso3": "DEU", "lat": 50.11, "lon": 8.68, "region": "Hesse", "power_mw": 700, "operators": ["Equinix", "Digital Realty", "AWS", "Google"], "notes": "DE-CIX — largest IXP by members"},
    {"name": "London / Slough", "country": "UK", "iso3": "GBR", "lat": 51.51, "lon": -0.59, "region": "Berkshire", "power_mw": 900, "operators": ["Equinix", "Digital Realty", "AWS", "Google"], "notes": "LINX, financial sector hub"},
    {"name": "Paris / Île-de-France", "country": "France", "iso3": "FRA", "lat": 48.95, "lon": 2.40, "region": "Île-de-France", "power_mw": 500, "operators": ["Equinix", "Digital Realty", "OVHcloud"], "notes": "France-IX hub"},
    {"name": "Stockholm / Rosersberg", "country": "Sweden", "iso3": "SWE", "lat": 59.60, "lon": 17.88, "region": "Stockholm", "power_mw": 400, "operators": ["AWS", "Microsoft", "Ericsson"], "notes": "Nordic hub, cold climate cooling"},
    {"name": "Milan", "country": "Italy", "iso3": "ITA", "lat": 45.46, "lon": 9.19, "region": "Lombardy", "power_mw": 300, "operators": ["Equinix", "AWS", "Google"], "notes": "Southern Europe hub"},
    {"name": "Madrid", "country": "Spain", "iso3": "ESP", "lat": 40.42, "lon": -3.70, "region": "Community of Madrid", "power_mw": 350, "operators": ["AWS", "Microsoft", "Google"], "notes": "Iberian expansion"},
    {"name": "Luleå", "country": "Sweden", "iso3": "SWE", "lat": 65.58, "lon": 22.15, "region": "Norrbotten", "power_mw": 200, "operators": ["Meta"], "notes": "Arctic cooling, hydro power, first Meta EU DC"},
    {"name": "Hamina", "country": "Finland", "iso3": "FIN", "lat": 60.57, "lon": 27.20, "region": "Kymenlaakso", "power_mw": 200, "operators": ["Google"], "notes": "Seawater cooling from Baltic"},
    # Asia-Pacific
    {"name": "Singapore / Jurong", "country": "Singapore", "iso3": "SGP", "lat": 1.33, "lon": 103.74, "region": "West Region", "power_mw": 700, "operators": ["Equinix", "Digital Realty", "AWS", "Google"], "notes": "APAC hub, moratorium lifted 2022 with green requirements"},
    {"name": "Tokyo / Inzai", "country": "Japan", "iso3": "JPN", "lat": 35.83, "lon": 140.14, "region": "Chiba", "power_mw": 900, "operators": ["Equinix", "AWS", "Google", "NTT"], "notes": "Asia's largest market"},
    {"name": "Seoul / Gasan", "country": "South Korea", "iso3": "KOR", "lat": 37.48, "lon": 126.88, "region": "Seoul", "power_mw": 400, "operators": ["AWS", "Google", "Samsung SDS", "KT"], "notes": "Korean DC cluster, 5G synergy"},
    {"name": "Mumbai / Navi Mumbai", "country": "India", "iso3": "IND", "lat": 19.06, "lon": 73.01, "region": "Maharashtra", "power_mw": 600, "operators": ["AWS", "Microsoft", "Google", "Reliance Jio", "Adani"], "notes": "India's primary DC hub, submarine cable landing"},
    {"name": "Chennai / Ambattur", "country": "India", "iso3": "IND", "lat": 13.11, "lon": 80.15, "region": "Tamil Nadu", "power_mw": 350, "operators": ["AWS", "Microsoft", "NTT"], "notes": "Second India hub, cable landing site"},
    {"name": "Sydney / Western Sydney", "country": "Australia", "iso3": "AUS", "lat": -33.80, "lon": 150.90, "region": "NSW", "power_mw": 500, "operators": ["Equinix", "AWS", "Microsoft", "Google"], "notes": "Australia's primary hub"},
    {"name": "Hong Kong / Tseung Kwan O", "country": "China", "iso3": "HKG", "lat": 22.31, "lon": 114.26, "region": "New Territories", "power_mw": 400, "operators": ["Equinix", "SUNeVision", "NTT"], "notes": "Asia financial connectivity hub"},
    {"name": "Beijing / Zhongguancun", "country": "China", "iso3": "CHN", "lat": 39.98, "lon": 116.30, "region": "Beijing", "power_mw": 800, "operators": ["Alibaba", "Tencent", "Baidu", "ByteDance"], "notes": "China's AI research center"},
    {"name": "Shanghai / Lingang", "country": "China", "iso3": "CHN", "lat": 30.89, "lon": 121.93, "region": "Shanghai", "power_mw": 700, "operators": ["Alibaba", "Tencent", "AWS (via partners)"], "notes": "East China financial hub"},
    {"name": "Guizhou / Guiyang", "country": "China", "iso3": "CHN", "lat": 26.65, "lon": 106.63, "region": "Guizhou", "power_mw": 500, "operators": ["Alibaba", "Huawei", "Tencent", "Apple"], "notes": "Mountain cooling, Apple iCloud China"},
    {"name": "Zhangbei / Hebei", "country": "China", "iso3": "CHN", "lat": 41.15, "lon": 114.70, "region": "Hebei", "power_mw": 600, "operators": ["Alibaba"], "notes": "Cold climate DC cluster, near Beijing"},
    {"name": "Ulanqab / Inner Mongolia", "country": "China", "iso3": "CHN", "lat": 41.00, "lon": 113.13, "region": "Inner Mongolia", "power_mw": 500, "operators": ["Alibaba", "Huawei"], "notes": "Cold climate, wind/solar power"},
    {"name": "Jakarta / Cibitung", "country": "Indonesia", "iso3": "IDN", "lat": -6.27, "lon": 107.09, "region": "West Java", "power_mw": 300, "operators": ["AWS", "Google", "Telkom"], "notes": "Indonesia hub, fast growth"},
    {"name": "Johor Bahru", "country": "Malaysia", "iso3": "MYS", "lat": 1.49, "lon": 103.74, "region": "Johor", "power_mw": 500, "operators": ["Microsoft", "Google", "Amazon", "ByteDance"], "notes": "Singapore spillover, massive 2024-25 expansion"},
    # Middle East
    {"name": "Dubai / Jebel Ali", "country": "UAE", "iso3": "ARE", "lat": 24.99, "lon": 55.06, "region": "Dubai", "power_mw": 300, "operators": ["AWS", "Microsoft", "Oracle", "Equinix"], "notes": "MENA hub"},
    {"name": "Riyadh", "country": "Saudi Arabia", "iso3": "SAU", "lat": 24.71, "lon": 46.67, "region": "Riyadh Province", "power_mw": 300, "operators": ["AWS", "Google", "Oracle", "STC"], "notes": "Vision 2030 DC investment"},
    {"name": "Tel Aviv / Haifa", "country": "Israel", "iso3": "ISR", "lat": 32.07, "lon": 34.77, "region": "Tel Aviv", "power_mw": 200, "operators": ["AWS", "Google", "Microsoft", "Equinix"], "notes": "Israel tech hub, Blue/Raman cable landing"},
    # South America
    {"name": "São Paulo / Barueri", "country": "Brazil", "iso3": "BRA", "lat": -23.51, "lon": -46.88, "region": "São Paulo", "power_mw": 500, "operators": ["Equinix", "Digital Realty", "AWS", "Google"], "notes": "Latin America's largest DC market"},
    {"name": "Santiago", "country": "Chile", "iso3": "CHL", "lat": -33.45, "lon": -70.65, "region": "Metropolitana", "power_mw": 150, "operators": ["Google", "AWS", "Huawei"], "notes": "Pacific cable landing, Curie cable"},
    {"name": "Querétaro", "country": "Mexico", "iso3": "MEX", "lat": 20.59, "lon": -100.39, "region": "Querétaro", "power_mw": 200, "operators": ["Google", "AWS", "Equinix", "KIO Networks"], "notes": "Mexico DC hub"},
    # Africa
    {"name": "Johannesburg / Isando", "country": "South Africa", "iso3": "ZAF", "lat": -26.14, "lon": 28.20, "region": "Gauteng", "power_mw": 200, "operators": ["Teraco", "AWS", "Microsoft"], "notes": "Africa's primary DC hub, NAPAfrica IXP"},
    {"name": "Nairobi", "country": "Kenya", "iso3": "KEN", "lat": -1.29, "lon": 36.82, "region": "Nairobi", "power_mw": 80, "operators": ["AWS", "Microsoft", "Liquid Intelligent"], "notes": "East Africa hub"},
    {"name": "Lagos / Lekki", "country": "Nigeria", "iso3": "NGA", "lat": 6.43, "lon": 3.43, "region": "Lagos", "power_mw": 70, "operators": ["Rack Centre", "Africa Data Centres"], "notes": "West Africa's largest, 2Africa cable landing"},
    # Nordics / Specialty
    {"name": "Reykjavik / Fitjar", "country": "Iceland", "iso3": "ISL", "lat": 64.05, "lon": -21.95, "region": "Capital Region", "power_mw": 100, "operators": ["Verne Global", "atNorth"], "notes": "100% geothermal/hydro, natural cooling"},
]


def query_datacenters(
    country: str | None = None,
    operator: str | None = None,
    min_power_mw: int | None = None,
    region: str | None = None,
) -> list[dict]:
    """Filter AI datacenters by country, operator, minimum power, or region."""
    results = []
    for dc in AI_DATACENTERS:
        if country:
            c = country.lower()
            if c not in (dc["country"].lower(), dc["iso3"].lower()):
                continue
        if min_power_mw and dc["power_mw"] < min_power_mw:
            continue
        if operator:
            op_lower = operator.lower()
            if not any(op_lower in o.lower() for o in dc["operators"]):
                continue
        if region:
            if region.lower() not in dc["region"].lower():
                continue
        results.append(dc)
    return results
