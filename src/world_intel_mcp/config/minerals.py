"""Critical mineral deposits and strategic mineral locations.

Pure data module — no I/O, no external dependencies.
Sources: USGS Mineral Commodity Summaries, IEA Critical Minerals,
EU Critical Raw Materials Act, Australian Geoscience.
"""

from __future__ import annotations

CRITICAL_MINERALS: list[dict] = [
    # Lithium
    {"name": "Salar de Atacama", "country": "Chile", "iso3": "CHL", "lat": -23.50, "lon": -68.20, "mineral": "lithium", "type": "brine", "operator": "SQM / Albemarle", "annual_tonnes": 100000, "pct_global": 26, "notes": "World's largest lithium brine operation"},
    {"name": "Greenbushes", "country": "Australia", "iso3": "AUS", "lat": -33.85, "lon": 116.06, "mineral": "lithium", "type": "hard_rock", "operator": "Talison (Tianqi/Albemarle)", "annual_tonnes": 75000, "pct_global": 20, "notes": "Largest hard-rock lithium mine"},
    {"name": "Salar de Uyuni", "country": "Bolivia", "iso3": "BOL", "lat": -20.13, "lon": -67.49, "mineral": "lithium", "type": "brine", "operator": "YLB (state)", "annual_tonnes": 5000, "pct_global": 1, "notes": "Largest reserves globally (~21M tonnes), low extraction"},
    {"name": "Pilgangoora", "country": "Australia", "iso3": "AUS", "lat": -21.30, "lon": 119.04, "mineral": "lithium", "type": "hard_rock", "operator": "Pilbara Minerals", "annual_tonnes": 40000, "pct_global": 10, "notes": "Major spodumene producer, Pilbara region"},
    {"name": "Thacker Pass", "country": "USA", "iso3": "USA", "lat": 41.32, "lon": -117.65, "mineral": "lithium", "type": "clay", "operator": "Lithium Americas", "annual_tonnes": 0, "pct_global": 0, "notes": "Largest US lithium project, under construction"},
    # Cobalt
    {"name": "Katanga Province Mines", "country": "DR Congo", "iso3": "COD", "lat": -10.98, "lon": 26.02, "mineral": "cobalt", "type": "copper_cobalt", "operator": "Glencore / CMOC / Artisanal", "annual_tonnes": 130000, "pct_global": 73, "notes": "~73% of global cobalt, artisanal mining concerns"},
    {"name": "Murrin Murrin", "country": "Australia", "iso3": "AUS", "lat": -28.72, "lon": 121.87, "mineral": "cobalt", "type": "nickel_cobalt", "operator": "Glencore", "annual_tonnes": 3000, "pct_global": 2, "notes": "Nickel-cobalt laterite"},
    # Rare Earth Elements
    {"name": "Bayan Obo", "country": "China", "iso3": "CHN", "lat": 41.78, "lon": 109.97, "mineral": "rare_earths", "type": "open_pit", "operator": "China Northern Rare Earth", "annual_tonnes": 45000, "pct_global": 38, "notes": "World's largest REE deposit, Inner Mongolia"},
    {"name": "Mount Weld", "country": "Australia", "iso3": "AUS", "lat": -28.77, "lon": 122.55, "mineral": "rare_earths", "type": "open_pit", "operator": "Lynas Rare Earths", "annual_tonnes": 12000, "pct_global": 10, "notes": "Largest non-Chinese REE mine, processed in Malaysia"},
    {"name": "Mountain Pass", "country": "USA", "iso3": "USA", "lat": 35.48, "lon": -115.53, "mineral": "rare_earths", "type": "open_pit", "operator": "MP Materials", "annual_tonnes": 43000, "pct_global": 14, "notes": "Only US rare earth mine, processing expansion underway"},
    {"name": "Xunwu / Ganzhou", "country": "China", "iso3": "CHN", "lat": 24.95, "lon": 115.65, "mineral": "rare_earths", "type": "ion_adsorption", "operator": "Various Chinese SOEs", "annual_tonnes": 30000, "pct_global": 25, "notes": "Heavy rare earths (Dy, Tb), Jiangxi province"},
    # Nickel
    {"name": "Sorowako / Morowali", "country": "Indonesia", "iso3": "IDN", "lat": -2.54, "lon": 121.36, "mineral": "nickel", "type": "laterite", "operator": "Vale / Chinese consortia", "annual_tonnes": 1600000, "pct_global": 48, "notes": "Indonesia is #1 producer, massive HPAL expansion"},
    {"name": "Norilsk", "country": "Russia", "iso3": "RUS", "lat": 69.35, "lon": 88.20, "mineral": "nickel", "type": "sulfide", "operator": "Nornickel", "annual_tonnes": 200000, "pct_global": 6, "notes": "Major PGM co-product, Arctic"},
    # Copper
    {"name": "Escondida", "country": "Chile", "iso3": "CHL", "lat": -24.27, "lon": -69.07, "mineral": "copper", "type": "open_pit", "operator": "BHP / Rio Tinto / JECO", "annual_tonnes": 1100000, "pct_global": 5, "notes": "World's largest copper mine by output"},
    {"name": "Grasberg", "country": "Indonesia", "iso3": "IDN", "lat": -4.06, "lon": 137.11, "mineral": "copper", "type": "underground", "operator": "Freeport-McMoRan / INALUM", "annual_tonnes": 700000, "pct_global": 3, "notes": "Largest gold reserve, deep block cave"},
    {"name": "Kamoa-Kakula", "country": "DR Congo", "iso3": "COD", "lat": -10.77, "lon": 25.33, "mineral": "copper", "type": "underground", "operator": "Ivanhoe Mines / Zijin", "annual_tonnes": 400000, "pct_global": 2, "notes": "Newest mega-mine, highest grade discovered copper"},
    # Graphite
    {"name": "Heilongjiang Province", "country": "China", "iso3": "CHN", "lat": 47.35, "lon": 127.96, "mineral": "graphite", "type": "flake", "operator": "Various Chinese", "annual_tonnes": 900000, "pct_global": 65, "notes": "China dominates natural graphite production"},
    {"name": "Balama", "country": "Mozambique", "iso3": "MOZ", "lat": -13.35, "lon": 38.58, "mineral": "graphite", "type": "flake", "operator": "Syrah Resources", "annual_tonnes": 50000, "pct_global": 4, "notes": "Largest known graphite reserve, feeds Vidalia (US)"},
    # Manganese
    {"name": "Kalahari Manganese Field", "country": "South Africa", "iso3": "ZAF", "lat": -27.18, "lon": 22.98, "mineral": "manganese", "type": "open_pit", "operator": "South32 / Samancor", "annual_tonnes": 7200000, "pct_global": 37, "notes": "~80% of global reserves in Kalahari"},
    # Platinum Group Metals
    {"name": "Bushveld Complex", "country": "South Africa", "iso3": "ZAF", "lat": -25.00, "lon": 29.50, "mineral": "pgm", "type": "underground", "operator": "Anglo American / Impala / Sibanye", "annual_tonnes": 130, "pct_global": 72, "notes": "~72% of global platinum, major PGM source"},
    # Titanium
    {"name": "Richards Bay", "country": "South Africa", "iso3": "ZAF", "lat": -28.78, "lon": 32.04, "mineral": "titanium", "type": "mineral_sands", "operator": "Rio Tinto (RBM)", "annual_tonnes": 1000000, "pct_global": 11, "notes": "Ilmenite and rutile sands"},
    # Tungsten
    {"name": "Jiangxi Province Mines", "country": "China", "iso3": "CHN", "lat": 27.63, "lon": 115.97, "mineral": "tungsten", "type": "underground", "operator": "Various Chinese SOEs", "annual_tonnes": 60000, "pct_global": 82, "notes": "China produces >80% of global tungsten"},
    # Uranium
    {"name": "Cigar Lake", "country": "Canada", "iso3": "CAN", "lat": 58.01, "lon": -104.56, "mineral": "uranium", "type": "underground", "operator": "Cameco / Orano", "annual_tonnes": 6900, "pct_global": 13, "notes": "Highest grade uranium mine in world"},
    {"name": "Inkai", "country": "Kazakhstan", "iso3": "KAZ", "lat": 44.49, "lon": 66.09, "mineral": "uranium", "type": "isl", "operator": "Kazatomprom / Cameco", "annual_tonnes": 4000, "pct_global": 8, "notes": "Kazakhstan is #1 uranium producer (~43% global)"},
    # Tin
    {"name": "Bangka-Belitung Islands", "country": "Indonesia", "iso3": "IDN", "lat": -2.13, "lon": 106.11, "mineral": "tin", "type": "alluvial", "operator": "PT Timah / Artisanal", "annual_tonnes": 52000, "pct_global": 24, "notes": "Major tin source, environmental concerns"},
    # Gallium / Germanium (strategic, China-controlled)
    {"name": "Shanxi / Henan Alumina Refineries", "country": "China", "iso3": "CHN", "lat": 37.87, "lon": 112.55, "mineral": "gallium", "type": "byproduct", "operator": "Chalco / various", "annual_tonnes": 340, "pct_global": 98, "notes": "China controls ~98% of gallium, export restrictions 2023"},
    {"name": "Yunnan Germanium Refineries", "country": "China", "iso3": "CHN", "lat": 25.04, "lon": 102.68, "mineral": "germanium", "type": "byproduct", "operator": "Yunnan Germanium", "annual_tonnes": 100, "pct_global": 60, "notes": "China ~60% of germanium, export restrictions 2023"},
]


def query_minerals(
    mineral: str | None = None,
    country: str | None = None,
    mineral_type: str | None = None,
    operator: str | None = None,
) -> list[dict]:
    """Filter critical mineral deposits."""
    results = []
    for m in CRITICAL_MINERALS:
        if mineral and m["mineral"] != mineral.lower():
            continue
        if country:
            c = country.lower()
            if c not in (m["country"].lower(), m["iso3"].lower()):
                continue
        if mineral_type and m["type"] != mineral_type.lower():
            continue
        if operator:
            if operator.lower() not in m["operator"].lower():
                continue
        results.append(m)
    return results
