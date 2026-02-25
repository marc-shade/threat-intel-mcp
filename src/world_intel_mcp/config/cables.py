"""Undersea cable routes with landing points.

Pure data module — no I/O, no external dependencies.
Sources: TeleGeography Submarine Cable Map, ITU cable database.
"""

from __future__ import annotations

UNDERSEA_CABLES: list[dict] = [
    # Transatlantic
    {"name": "TAT-14", "status": "decommissioned", "rfs_year": 2001, "length_km": 15428, "capacity_tbps": 3.2,
     "owners": ["Deutsche Telekom", "AT&T", "Orange"], "landing_points": [
         {"name": "Tuckerton", "country": "USA", "lat": 39.60, "lon": -74.34},
         {"name": "Manasquan", "country": "USA", "lat": 40.12, "lon": -74.04},
         {"name": "Blaabjerg", "country": "Denmark", "lat": 55.60, "lon": 8.12},
         {"name": "Norden", "country": "Germany", "lat": 53.60, "lon": 7.20},
         {"name": "Saint-Valery-en-Caux", "country": "France", "lat": 49.87, "lon": 0.72},
         {"name": "Bude", "country": "UK", "lat": 50.83, "lon": -4.55},
     ]},
    {"name": "MAREA", "status": "active", "rfs_year": 2018, "length_km": 6600, "capacity_tbps": 200,
     "owners": ["Microsoft", "Meta", "Telxius"], "landing_points": [
         {"name": "Virginia Beach", "country": "USA", "lat": 36.85, "lon": -75.98},
         {"name": "Bilbao", "country": "Spain", "lat": 43.26, "lon": -2.93},
     ]},
    {"name": "Dunant", "status": "active", "rfs_year": 2021, "length_km": 6600, "capacity_tbps": 250,
     "owners": ["Google"], "landing_points": [
         {"name": "Virginia Beach", "country": "USA", "lat": 36.85, "lon": -75.98},
         {"name": "Saint-Hilaire-de-Riez", "country": "France", "lat": 46.72, "lon": -1.95},
     ]},
    {"name": "Amitié", "status": "active", "rfs_year": 2022, "length_km": 6800, "capacity_tbps": 400,
     "owners": ["Google", "Meta", "Lumen"], "landing_points": [
         {"name": "Lynn", "country": "USA", "lat": 42.47, "lon": -70.95},
         {"name": "Bude", "country": "UK", "lat": 50.83, "lon": -4.55},
         {"name": "Le Porge", "country": "France", "lat": 44.87, "lon": -1.16},
     ]},
    {"name": "AEC-1 (Anjana/East)", "status": "active", "rfs_year": 2002, "length_km": 7200, "capacity_tbps": 5.1,
     "owners": ["Telia", "Aqua Comms"], "landing_points": [
         {"name": "Shirley", "country": "USA", "lat": 40.80, "lon": -72.87},
         {"name": "Killala", "country": "Ireland", "lat": 54.21, "lon": -9.22},
         {"name": "Blaabjerg", "country": "Denmark", "lat": 55.60, "lon": 8.12},
     ]},
    {"name": "HAVFRUE/AEC-2", "status": "active", "rfs_year": 2020, "length_km": 7860, "capacity_tbps": 108,
     "owners": ["Google", "Aqua Comms", "Bulk"], "landing_points": [
         {"name": "Wall Township", "country": "USA", "lat": 40.16, "lon": -74.07},
         {"name": "Blaabjerg", "country": "Denmark", "lat": 55.60, "lon": 8.12},
         {"name": "Kristiansand", "country": "Norway", "lat": 58.15, "lon": 8.00},
         {"name": "Killala", "country": "Ireland", "lat": 54.21, "lon": -9.22},
     ]},
    {"name": "Grace Hopper", "status": "active", "rfs_year": 2022, "length_km": 6300, "capacity_tbps": 340,
     "owners": ["Google"], "landing_points": [
         {"name": "New York", "country": "USA", "lat": 40.57, "lon": -73.97},
         {"name": "Bude", "country": "UK", "lat": 50.83, "lon": -4.55},
         {"name": "Bilbao", "country": "Spain", "lat": 43.26, "lon": -2.93},
     ]},
    # Transpacific
    {"name": "JUPITER", "status": "active", "rfs_year": 2020, "length_km": 14000, "capacity_tbps": 60,
     "owners": ["Google", "Meta", "PLDT", "SoftBank"], "landing_points": [
         {"name": "Virginia Beach", "country": "USA", "lat": 36.85, "lon": -75.98},
         {"name": "Daet", "country": "Philippines", "lat": 14.11, "lon": 122.96},
         {"name": "Maruyama", "country": "Japan", "lat": 33.48, "lon": 135.76},
     ]},
    {"name": "FASTER", "status": "active", "rfs_year": 2016, "length_km": 11629, "capacity_tbps": 60,
     "owners": ["Google", "China Mobile", "KDDI", "SingTel"], "landing_points": [
         {"name": "Bandon", "country": "USA", "lat": 43.12, "lon": -124.41},
         {"name": "Chikura", "country": "Japan", "lat": 34.93, "lon": 139.95},
         {"name": "Shima", "country": "Japan", "lat": 34.33, "lon": 136.83},
     ]},
    {"name": "Curie", "status": "active", "rfs_year": 2019, "length_km": 10476, "capacity_tbps": 72,
     "owners": ["Google"], "landing_points": [
         {"name": "Los Angeles", "country": "USA", "lat": 33.94, "lon": -118.45},
         {"name": "Valparaiso", "country": "Chile", "lat": -33.04, "lon": -71.63},
     ]},
    {"name": "Firmina", "status": "active", "rfs_year": 2023, "length_km": 14000, "capacity_tbps": 340,
     "owners": ["Google"], "landing_points": [
         {"name": "Myrtle Beach", "country": "USA", "lat": 33.69, "lon": -78.89},
         {"name": "Praia Grande", "country": "Brazil", "lat": -24.01, "lon": -46.41},
         {"name": "Las Toninas", "country": "Argentina", "lat": -36.48, "lon": -56.70},
     ]},
    {"name": "PLCN (Pacific Light Cable Network)", "status": "active", "rfs_year": 2023, "length_km": 12800, "capacity_tbps": 144,
     "owners": ["Google", "Meta"], "landing_points": [
         {"name": "El Segundo", "country": "USA", "lat": 33.92, "lon": -118.42},
         {"name": "Changi", "country": "Singapore", "lat": 1.35, "lon": 104.00},
         {"name": "Tanah Merah", "country": "Indonesia", "lat": -6.17, "lon": 106.97},
     ]},
    # Asia-Europe (SEA-ME-WE family)
    {"name": "SEA-ME-WE 3", "status": "active", "rfs_year": 1999, "length_km": 39000, "capacity_tbps": 0.96,
     "owners": ["Consortium (76 telcos)"], "landing_points": [
         {"name": "Norden", "country": "Germany", "lat": 53.60, "lon": 7.20},
         {"name": "Penmarc'h", "country": "France", "lat": 47.80, "lon": -4.37},
         {"name": "Tetney", "country": "UK", "lat": 53.50, "lon": 0.02},
         {"name": "Suez", "country": "Egypt", "lat": 29.97, "lon": 32.55},
         {"name": "Mumbai", "country": "India", "lat": 18.93, "lon": 72.83},
         {"name": "Singapore", "country": "Singapore", "lat": 1.26, "lon": 103.82},
         {"name": "Shanghai", "country": "China", "lat": 31.05, "lon": 121.72},
         {"name": "Keoje", "country": "South Korea", "lat": 34.88, "lon": 128.70},
         {"name": "Okinawa", "country": "Japan", "lat": 26.34, "lon": 127.77},
     ]},
    {"name": "SEA-ME-WE 5", "status": "active", "rfs_year": 2017, "length_km": 20000, "capacity_tbps": 24,
     "owners": ["Consortium (17 telcos)"], "landing_points": [
         {"name": "Marseille", "country": "France", "lat": 43.30, "lon": 5.37},
         {"name": "Catania", "country": "Italy", "lat": 37.50, "lon": 15.09},
         {"name": "Alexandria", "country": "Egypt", "lat": 31.20, "lon": 29.92},
         {"name": "Jeddah", "country": "Saudi Arabia", "lat": 21.49, "lon": 39.19},
         {"name": "Mumbai", "country": "India", "lat": 18.93, "lon": 72.83},
         {"name": "Singapore", "country": "Singapore", "lat": 1.26, "lon": 103.82},
     ]},
    {"name": "SEA-ME-WE 6", "status": "construction", "rfs_year": 2025, "length_km": 19200, "capacity_tbps": 100,
     "owners": ["Consortium (12 telcos)"], "landing_points": [
         {"name": "Marseille", "country": "France", "lat": 43.30, "lon": 5.37},
         {"name": "Genoa", "country": "Italy", "lat": 44.41, "lon": 8.93},
         {"name": "Alexandria", "country": "Egypt", "lat": 31.20, "lon": 29.92},
         {"name": "Singapore", "country": "Singapore", "lat": 1.26, "lon": 103.82},
     ]},
    # Africa
    {"name": "2Africa", "status": "active", "rfs_year": 2024, "length_km": 45000, "capacity_tbps": 180,
     "owners": ["Meta", "MTN", "Orange", "Vodafone", "China Mobile"], "landing_points": [
         {"name": "Genoa", "country": "Italy", "lat": 44.41, "lon": 8.93},
         {"name": "Barcelona", "country": "Spain", "lat": 41.39, "lon": 2.16},
         {"name": "Marseille", "country": "France", "lat": 43.30, "lon": 5.37},
         {"name": "Bude", "country": "UK", "lat": 50.83, "lon": -4.55},
         {"name": "Dakar", "country": "Senegal", "lat": 14.69, "lon": -17.47},
         {"name": "Lagos", "country": "Nigeria", "lat": 6.45, "lon": 3.39},
         {"name": "Cape Town", "country": "South Africa", "lat": -33.92, "lon": 18.42},
         {"name": "Maputo", "country": "Mozambique", "lat": -25.97, "lon": 32.57},
         {"name": "Mombasa", "country": "Kenya", "lat": -4.04, "lon": 39.67},
         {"name": "Djibouti", "country": "Djibouti", "lat": 11.55, "lon": 43.15},
         {"name": "Jeddah", "country": "Saudi Arabia", "lat": 21.49, "lon": 39.19},
         {"name": "Mumbai", "country": "India", "lat": 18.93, "lon": 72.83},
     ]},
    {"name": "Equiano", "status": "active", "rfs_year": 2023, "length_km": 15000, "capacity_tbps": 144,
     "owners": ["Google"], "landing_points": [
         {"name": "Sesimbra", "country": "Portugal", "lat": 38.44, "lon": -9.10},
         {"name": "Lagos", "country": "Nigeria", "lat": 6.45, "lon": 3.39},
         {"name": "Lomé", "country": "Togo", "lat": 6.13, "lon": 1.22},
         {"name": "Swakopmund", "country": "Namibia", "lat": -22.68, "lon": 14.53},
         {"name": "Melkbosstrand", "country": "South Africa", "lat": -33.72, "lon": 18.44},
     ]},
    # PEACE Cable
    {"name": "PEACE", "status": "active", "rfs_year": 2022, "length_km": 15000, "capacity_tbps": 96,
     "owners": ["PEACE Cable International"], "landing_points": [
         {"name": "Marseille", "country": "France", "lat": 43.30, "lon": 5.37},
         {"name": "Karachi", "country": "Pakistan", "lat": 24.86, "lon": 67.01},
         {"name": "Mombasa", "country": "Kenya", "lat": -4.04, "lon": 39.67},
         {"name": "Seychelles", "country": "Seychelles", "lat": -4.68, "lon": 55.49},
         {"name": "Singapore", "country": "Singapore", "lat": 1.26, "lon": 103.82},
     ]},
    # Asia-Pacific
    {"name": "APG (Asia-Pacific Gateway)", "status": "active", "rfs_year": 2016, "length_km": 10400, "capacity_tbps": 54.8,
     "owners": ["Consortium (12 telcos)"], "landing_points": [
         {"name": "Chongming", "country": "China", "lat": 31.62, "lon": 121.73},
         {"name": "Hong Kong", "country": "China", "lat": 22.25, "lon": 114.17},
         {"name": "Taipei", "country": "Taiwan", "lat": 25.16, "lon": 121.74},
         {"name": "Maruyama", "country": "Japan", "lat": 33.48, "lon": 135.76},
         {"name": "Changi", "country": "Singapore", "lat": 1.35, "lon": 104.00},
         {"name": "Da Nang", "country": "Vietnam", "lat": 16.07, "lon": 108.22},
         {"name": "Kuantan", "country": "Malaysia", "lat": 3.80, "lon": 103.33},
     ]},
    {"name": "SJC (Southeast Asia-Japan Cable)", "status": "active", "rfs_year": 2013, "length_km": 8900, "capacity_tbps": 28,
     "owners": ["Google", "Meta", "KDDI", "SingTel", "PLDT"], "landing_points": [
         {"name": "Maruyama", "country": "Japan", "lat": 33.48, "lon": 135.76},
         {"name": "Shantou", "country": "China", "lat": 23.35, "lon": 116.68},
         {"name": "Hong Kong", "country": "China", "lat": 22.25, "lon": 114.17},
         {"name": "Changi", "country": "Singapore", "lat": 1.35, "lon": 104.00},
     ]},
    {"name": "SJC2", "status": "active", "rfs_year": 2022, "length_km": 10500, "capacity_tbps": 144,
     "owners": ["Meta", "Google", "SingTel", "PLDT", "Telin"], "landing_points": [
         {"name": "Shima", "country": "Japan", "lat": 34.33, "lon": 136.83},
         {"name": "Chikura", "country": "Japan", "lat": 34.93, "lon": 139.95},
         {"name": "Taiwan", "country": "Taiwan", "lat": 25.16, "lon": 121.74},
         {"name": "Changi", "country": "Singapore", "lat": 1.35, "lon": 104.00},
         {"name": "Manado", "country": "Indonesia", "lat": 1.49, "lon": 124.84},
     ]},
    # Middle East
    {"name": "FLAG Europe-Asia (FEA)", "status": "active", "rfs_year": 1997, "length_km": 28000, "capacity_tbps": 10,
     "owners": ["Reliance Globalcom"], "landing_points": [
         {"name": "Porthcurno", "country": "UK", "lat": 50.04, "lon": -5.66},
         {"name": "Estepona", "country": "Spain", "lat": 36.43, "lon": -5.15},
         {"name": "Palermo", "country": "Italy", "lat": 38.12, "lon": 13.36},
         {"name": "Port Said", "country": "Egypt", "lat": 31.26, "lon": 32.30},
         {"name": "Mumbai", "country": "India", "lat": 18.93, "lon": 72.83},
         {"name": "Busan", "country": "South Korea", "lat": 35.10, "lon": 129.04},
         {"name": "Miura", "country": "Japan", "lat": 35.14, "lon": 139.62},
     ]},
    {"name": "AAE-1", "status": "active", "rfs_year": 2017, "length_km": 25000, "capacity_tbps": 40,
     "owners": ["Consortium (19 telcos)"], "landing_points": [
         {"name": "Marseille", "country": "France", "lat": 43.30, "lon": 5.37},
         {"name": "Bari", "country": "Italy", "lat": 41.13, "lon": 16.87},
         {"name": "Alexandria", "country": "Egypt", "lat": 31.20, "lon": 29.92},
         {"name": "Djibouti", "country": "Djibouti", "lat": 11.55, "lon": 43.15},
         {"name": "Mumbai", "country": "India", "lat": 18.93, "lon": 72.83},
         {"name": "Singapore", "country": "Singapore", "lat": 1.26, "lon": 103.82},
         {"name": "Hong Kong", "country": "China", "lat": 22.25, "lon": 114.17},
     ]},
    {"name": "FALCON", "status": "active", "rfs_year": 2006, "length_km": 11500, "capacity_tbps": 4.7,
     "owners": ["FLAG Telecom (Reliance)"], "landing_points": [
         {"name": "Mumbai", "country": "India", "lat": 18.93, "lon": 72.83},
         {"name": "Fujairah", "country": "UAE", "lat": 25.12, "lon": 56.35},
         {"name": "Muscat", "country": "Oman", "lat": 23.59, "lon": 58.54},
         {"name": "Jeddah", "country": "Saudi Arabia", "lat": 21.49, "lon": 39.19},
         {"name": "Suez", "country": "Egypt", "lat": 29.97, "lon": 32.55},
     ]},
    # Arctic / North
    {"name": "Far North Fiber", "status": "construction", "rfs_year": 2027, "length_km": 16500, "capacity_tbps": 200,
     "owners": ["Far North Digital", "Cinia"], "landing_points": [
         {"name": "Tokyo", "country": "Japan", "lat": 35.65, "lon": 139.84},
         {"name": "Kirkenes", "country": "Norway", "lat": 69.73, "lon": 30.05},
         {"name": "Dublin", "country": "Ireland", "lat": 53.35, "lon": -6.26},
         {"name": "Nome", "country": "USA", "lat": 64.50, "lon": -165.41},
     ]},
    # Australia
    {"name": "JGA-S (Japan-Guam-Australia South)", "status": "active", "rfs_year": 2020, "length_km": 7100, "capacity_tbps": 36,
     "owners": ["Google", "AARNet", "Indosat"], "landing_points": [
         {"name": "Shima", "country": "Japan", "lat": 34.33, "lon": 136.83},
         {"name": "Piti", "country": "Guam", "lat": 13.46, "lon": 144.70},
         {"name": "Sydney", "country": "Australia", "lat": -33.87, "lon": 151.21},
     ]},
    {"name": "Indigo", "status": "active", "rfs_year": 2019, "length_km": 9600, "capacity_tbps": 36,
     "owners": ["Google", "AARNet", "Indosat", "SingTel", "SubPartners"], "landing_points": [
         {"name": "Perth", "country": "Australia", "lat": -31.95, "lon": 115.86},
         {"name": "Singapore", "country": "Singapore", "lat": 1.26, "lon": 103.82},
         {"name": "Jakarta", "country": "Indonesia", "lat": -6.13, "lon": 106.85},
     ]},
    # South America
    {"name": "SACS (South Atlantic Cable System)", "status": "active", "rfs_year": 2018, "length_km": 6200, "capacity_tbps": 40,
     "owners": ["Angola Cables"], "landing_points": [
         {"name": "Luanda", "country": "Angola", "lat": -8.84, "lon": 13.23},
         {"name": "Fortaleza", "country": "Brazil", "lat": -3.72, "lon": -38.52},
     ]},
    {"name": "EllaLink", "status": "active", "rfs_year": 2021, "length_km": 12000, "capacity_tbps": 72,
     "owners": ["EllaLink"], "landing_points": [
         {"name": "Sines", "country": "Portugal", "lat": 37.96, "lon": -8.87},
         {"name": "Marseille", "country": "France", "lat": 43.30, "lon": 5.37},
         {"name": "Fortaleza", "country": "Brazil", "lat": -3.72, "lon": -38.52},
     ]},
    # India-specific
    {"name": "India-Asia-Xpress (IAX)", "status": "active", "rfs_year": 2024, "length_km": 7800, "capacity_tbps": 120,
     "owners": ["Reliance Jio", "Meta"], "landing_points": [
         {"name": "Mumbai", "country": "India", "lat": 18.93, "lon": 72.83},
         {"name": "Singapore", "country": "Singapore", "lat": 1.26, "lon": 103.82},
         {"name": "Kuantan", "country": "Malaysia", "lat": 3.80, "lon": 103.33},
         {"name": "Satun", "country": "Thailand", "lat": 6.62, "lon": 100.07},
     ]},
    # North Pacific
    {"name": "NCP (New Cross Pacific)", "status": "active", "rfs_year": 2018, "length_km": 13600, "capacity_tbps": 80,
     "owners": ["Microsoft", "Meta", "Amazon", "SoftBank", "PLDT"], "landing_points": [
         {"name": "Hillsboro", "country": "USA", "lat": 45.53, "lon": -122.99},
         {"name": "Maruyama", "country": "Japan", "lat": 33.48, "lon": 135.76},
         {"name": "Chongming", "country": "China", "lat": 31.62, "lon": 121.73},
         {"name": "Taipei", "country": "Taiwan", "lat": 25.16, "lon": 121.74},
     ]},
    {"name": "Unity", "status": "active", "rfs_year": 2010, "length_km": 10000, "capacity_tbps": 7.68,
     "owners": ["Google", "KDDI"], "landing_points": [
         {"name": "Chikura", "country": "Japan", "lat": 34.93, "lon": 139.95},
         {"name": "Los Angeles", "country": "USA", "lat": 33.94, "lon": -118.45},
     ]},
    # Mediterranean
    {"name": "Blue & Raman", "status": "active", "rfs_year": 2024, "length_km": 16000, "capacity_tbps": 250,
     "owners": ["Google"], "landing_points": [
         {"name": "Genoa", "country": "Italy", "lat": 44.41, "lon": 8.93},
         {"name": "Haifa", "country": "Israel", "lat": 32.82, "lon": 34.98},
         {"name": "Mumbai", "country": "India", "lat": 18.93, "lon": 72.83},
         {"name": "Amman", "country": "Jordan", "lat": 31.95, "lon": 35.93},
     ]},
    {"name": "Oman Australia Cable (OAC)", "status": "active", "rfs_year": 2022, "length_km": 9800, "capacity_tbps": 100,
     "owners": ["Oman Broadband", "SubPartners"], "landing_points": [
         {"name": "Barka", "country": "Oman", "lat": 23.68, "lon": 57.88},
         {"name": "Perth", "country": "Australia", "lat": -31.95, "lon": 115.86},
     ]},
]


def query_cables(
    status: str | None = None,
    country: str | None = None,
    owner: str | None = None,
    min_capacity_tbps: float | None = None,
) -> list[dict]:
    """Filter undersea cables by status, landing country, owner, or min capacity."""
    results = []
    for cable in UNDERSEA_CABLES:
        if status and cable["status"] != status.lower():
            continue
        if min_capacity_tbps and cable["capacity_tbps"] < min_capacity_tbps:
            continue
        if owner:
            owner_lower = owner.lower()
            if not any(owner_lower in o.lower() for o in cable["owners"]):
                continue
        if country:
            country_lower = country.lower()
            if not any(country_lower in lp["country"].lower() for lp in cable["landing_points"]):
                continue
        results.append(cable)
    return results
