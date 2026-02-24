"""Static geospatial datasets — military bases, ports, pipelines, nuclear facilities.

Pure data module — no I/O, no external dependencies.
Sources: open-source geospatial intelligence, IISS Military Balance, Jane's,
World Nuclear Association, World Port Source, Global Energy Monitor.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Military Bases — 120+ facilities from 9 operators
# Fields: name, country, iso3, lat, lon, operator, type, branch, notes
# ---------------------------------------------------------------------------

MILITARY_BASES: list[dict] = [
    # ── United States ──
    {"name": "Ramstein Air Base", "country": "Germany", "iso3": "DEU", "lat": 49.44, "lon": 7.60, "operator": "USA", "type": "air_base", "branch": "USAF", "notes": "USAFE HQ, major airlift hub"},
    {"name": "Camp Humphreys", "country": "South Korea", "iso3": "KOR", "lat": 36.96, "lon": 127.03, "operator": "USA", "type": "army_base", "branch": "US Army", "notes": "USFK HQ, largest US overseas base"},
    {"name": "Yokota Air Base", "country": "Japan", "iso3": "JPN", "lat": 35.75, "lon": 139.35, "operator": "USA", "type": "air_base", "branch": "USAF", "notes": "USFJ HQ, 5th Air Force"},
    {"name": "Yokosuka Naval Base", "country": "Japan", "iso3": "JPN", "lat": 35.28, "lon": 139.67, "operator": "USA", "type": "naval_base", "branch": "US Navy", "notes": "7th Fleet HQ, forward-deployed carrier"},
    {"name": "Kadena Air Base", "country": "Japan", "iso3": "JPN", "lat": 26.35, "lon": 127.77, "operator": "USA", "type": "air_base", "branch": "USAF", "notes": "Largest US base in Pacific"},
    {"name": "Guam (Andersen AFB)", "country": "Guam", "iso3": "GUM", "lat": 13.58, "lon": 144.93, "operator": "USA", "type": "air_base", "branch": "USAF", "notes": "Strategic bomber base, Indo-Pacific"},
    {"name": "Diego Garcia", "country": "BIOT", "iso3": "IOT", "lat": -7.32, "lon": 72.42, "operator": "USA", "type": "naval_base", "branch": "US Navy", "notes": "Indian Ocean logistics hub, B-2 capable"},
    {"name": "Al Udeid Air Base", "country": "Qatar", "iso3": "QAT", "lat": 25.12, "lon": 51.31, "operator": "USA", "type": "air_base", "branch": "USAF", "notes": "CENTCOM forward HQ, Combined AOC"},
    {"name": "Camp Lemonnier", "country": "Djibouti", "iso3": "DJI", "lat": 11.55, "lon": 43.15, "operator": "USA", "type": "expeditionary", "branch": "US Navy", "notes": "AFRICOM, only permanent US base in Africa"},
    {"name": "Naval Station Rota", "country": "Spain", "iso3": "ESP", "lat": 36.62, "lon": -6.35, "operator": "USA", "type": "naval_base", "branch": "US Navy", "notes": "BMDS Aegis Ashore, 4 destroyers"},
    {"name": "Thule Air Base", "country": "Greenland", "iso3": "GRL", "lat": 76.53, "lon": -68.70, "operator": "USA", "type": "space_base", "branch": "USSF", "notes": "Missile warning, space surveillance"},
    {"name": "Incirlik Air Base", "country": "Turkey", "iso3": "TUR", "lat": 37.00, "lon": 35.43, "operator": "USA", "type": "air_base", "branch": "USAF", "notes": "B61 nuclear storage, NATO"},
    {"name": "Aviano Air Base", "country": "Italy", "iso3": "ITA", "lat": 46.03, "lon": 12.60, "operator": "USA", "type": "air_base", "branch": "USAF", "notes": "31st Fighter Wing, F-16s"},
    {"name": "Bahrain NSA", "country": "Bahrain", "iso3": "BHR", "lat": 26.23, "lon": 50.58, "operator": "USA", "type": "naval_base", "branch": "US Navy", "notes": "5th Fleet HQ, Persian Gulf"},
    {"name": "Misawa Air Base", "country": "Japan", "iso3": "JPN", "lat": 40.70, "lon": 141.37, "operator": "USA", "type": "air_base", "branch": "USAF", "notes": "35th Fighter Wing, signals intel"},
    {"name": "Sasebo Naval Base", "country": "Japan", "iso3": "JPN", "lat": 33.16, "lon": 129.72, "operator": "USA", "type": "naval_base", "branch": "US Navy", "notes": "Amphibious forces, mine warfare"},
    {"name": "RAF Lakenheath", "country": "United Kingdom", "iso3": "GBR", "lat": 52.41, "lon": 0.56, "operator": "USA", "type": "air_base", "branch": "USAF", "notes": "48th Fighter Wing, F-35A"},
    {"name": "RAF Mildenhall", "country": "United Kingdom", "iso3": "GBR", "lat": 52.36, "lon": 0.49, "operator": "USA", "type": "air_base", "branch": "USAF", "notes": "100th ARW, KC-135 tankers"},
    {"name": "Grafenwoehr", "country": "Germany", "iso3": "DEU", "lat": 49.69, "lon": 11.94, "operator": "USA", "type": "training", "branch": "US Army", "notes": "Largest US training area in Europe"},
    {"name": "Sigonella NAS", "country": "Italy", "iso3": "ITA", "lat": 37.40, "lon": 14.92, "operator": "USA", "type": "naval_air", "branch": "US Navy", "notes": "MQ-4C Triton, P-8 Poseidon"},
    {"name": "Souda Bay", "country": "Greece", "iso3": "GRC", "lat": 35.49, "lon": 24.12, "operator": "USA", "type": "naval_base", "branch": "US Navy", "notes": "Eastern Med logistics"},
    {"name": "Camp Bondsteel", "country": "Kosovo", "iso3": "XKX", "lat": 42.36, "lon": 21.25, "operator": "USA", "type": "army_base", "branch": "US Army", "notes": "KFOR, Balkans stabilization"},
    {"name": "Kunsan Air Base", "country": "South Korea", "iso3": "KOR", "lat": 35.90, "lon": 126.62, "operator": "USA", "type": "air_base", "branch": "USAF", "notes": "8th Fighter Wing, Wolf Pack"},
    {"name": "Osan Air Base", "country": "South Korea", "iso3": "KOR", "lat": 37.09, "lon": 127.03, "operator": "USA", "type": "air_base", "branch": "USAF", "notes": "51st Fighter Wing, A-10/F-16"},
    {"name": "Fort Liberty", "country": "United States", "iso3": "USA", "lat": 35.14, "lon": -79.00, "operator": "USA", "type": "army_base", "branch": "US Army", "notes": "XVIII Airborne Corps, 82nd Airborne"},
    {"name": "Camp Pendleton", "country": "United States", "iso3": "USA", "lat": 33.30, "lon": -117.35, "operator": "USA", "type": "marine_base", "branch": "USMC", "notes": "1st Marine Expeditionary Force"},
    {"name": "Norfolk Naval Station", "country": "United States", "iso3": "USA", "lat": 36.95, "lon": -76.33, "operator": "USA", "type": "naval_base", "branch": "US Navy", "notes": "Largest naval station in world"},
    {"name": "Pearl Harbor", "country": "United States", "iso3": "USA", "lat": 21.35, "lon": -157.97, "operator": "USA", "type": "naval_base", "branch": "US Navy", "notes": "INDOPACOM HQ, Pacific Fleet"},
    {"name": "Fort Cavazos", "country": "United States", "iso3": "USA", "lat": 31.13, "lon": -97.78, "operator": "USA", "type": "army_base", "branch": "US Army", "notes": "III Armored Corps, 1st Cav"},
    # ── Russia ──
    {"name": "Kaliningrad", "country": "Russia", "iso3": "RUS", "lat": 54.71, "lon": 20.51, "operator": "RUS", "type": "naval_base", "branch": "Baltic Fleet", "notes": "Iskander missiles, Baltic enclave"},
    {"name": "Sevastopol", "country": "Crimea", "iso3": "UKR", "lat": 44.62, "lon": 33.53, "operator": "RUS", "type": "naval_base", "branch": "Black Sea Fleet", "notes": "Black Sea Fleet HQ (disputed)"},
    {"name": "Tartus", "country": "Syria", "iso3": "SYR", "lat": 34.89, "lon": 35.89, "operator": "RUS", "type": "naval_base", "branch": "Navy", "notes": "Only Med naval facility"},
    {"name": "Hmeimim", "country": "Syria", "iso3": "SYR", "lat": 35.41, "lon": 35.95, "operator": "RUS", "type": "air_base", "branch": "VKS", "notes": "Su-35, Su-34 deployment"},
    {"name": "Vladivostok", "country": "Russia", "iso3": "RUS", "lat": 43.12, "lon": 131.91, "operator": "RUS", "type": "naval_base", "branch": "Pacific Fleet", "notes": "Pacific Fleet HQ"},
    {"name": "Murmansk/Severomorsk", "country": "Russia", "iso3": "RUS", "lat": 69.07, "lon": 33.42, "operator": "RUS", "type": "naval_base", "branch": "Northern Fleet", "notes": "Northern Fleet HQ, SSBN base"},
    {"name": "Engels-2", "country": "Russia", "iso3": "RUS", "lat": 51.48, "lon": 46.20, "operator": "RUS", "type": "air_base", "branch": "VKS", "notes": "Strategic bomber base, Tu-160"},
    {"name": "Plesetsk Cosmodrome", "country": "Russia", "iso3": "RUS", "lat": 62.93, "lon": 40.58, "operator": "RUS", "type": "space_base", "branch": "VKS", "notes": "ICBM test launches, Angara"},
    {"name": "Cam Ranh Bay", "country": "Vietnam", "iso3": "VNM", "lat": 11.98, "lon": 109.22, "operator": "RUS", "type": "naval_base", "branch": "Navy", "notes": "Logistics facility, reduced presence"},
    # ── China ──
    {"name": "Djibouti Support Base", "country": "Djibouti", "iso3": "DJI", "lat": 11.59, "lon": 43.11, "operator": "CHN", "type": "naval_base", "branch": "PLA Navy", "notes": "First overseas base, 2017"},
    {"name": "Fiery Cross Reef", "country": "Spratly Islands", "iso3": "SCS", "lat": 9.55, "lon": 112.89, "operator": "CHN", "type": "air_base", "branch": "PLA", "notes": "Artificial island, 3km runway"},
    {"name": "Subi Reef", "country": "Spratly Islands", "iso3": "SCS", "lat": 10.92, "lon": 114.08, "operator": "CHN", "type": "air_base", "branch": "PLA", "notes": "Artificial island, radar/SAM"},
    {"name": "Mischief Reef", "country": "Spratly Islands", "iso3": "SCS", "lat": 9.90, "lon": 115.54, "operator": "CHN", "type": "naval_base", "branch": "PLA Navy", "notes": "Artificial island, hangars"},
    {"name": "Woody Island", "country": "Paracel Islands", "iso3": "SCS", "lat": 16.83, "lon": 112.34, "operator": "CHN", "type": "air_base", "branch": "PLA", "notes": "HQ-9 SAMs, J-11 fighters"},
    {"name": "Yulin Naval Base", "country": "China", "iso3": "CHN", "lat": 18.23, "lon": 109.55, "operator": "CHN", "type": "naval_base", "branch": "PLA Navy", "notes": "SSBN base, underground pens"},
    {"name": "Zhanjiang", "country": "China", "iso3": "CHN", "lat": 21.19, "lon": 110.41, "operator": "CHN", "type": "naval_base", "branch": "PLA Navy", "notes": "Southern Theater Navy HQ"},
    {"name": "Qingdao", "country": "China", "iso3": "CHN", "lat": 36.07, "lon": 120.38, "operator": "CHN", "type": "naval_base", "branch": "PLA Navy", "notes": "Northern Theater Navy, carrier base"},
    {"name": "Ream Naval Base", "country": "Cambodia", "iso3": "KHM", "lat": 10.51, "lon": 103.63, "operator": "CHN", "type": "naval_base", "branch": "PLA Navy", "notes": "Suspected dual-use facility"},
    # ── United Kingdom ──
    {"name": "Akrotiri", "country": "Cyprus", "iso3": "CYP", "lat": 34.59, "lon": 32.99, "operator": "GBR", "type": "air_base", "branch": "RAF", "notes": "Sovereign Base Area, signals intel"},
    {"name": "HMNB Clyde (Faslane)", "country": "United Kingdom", "iso3": "GBR", "lat": 56.07, "lon": -4.82, "operator": "GBR", "type": "naval_base", "branch": "Royal Navy", "notes": "Trident SSBN base"},
    {"name": "BRNC Dartmouth", "country": "United Kingdom", "iso3": "GBR", "lat": 50.35, "lon": -3.57, "operator": "GBR", "type": "training", "branch": "Royal Navy", "notes": "Officer training"},
    {"name": "Duqm", "country": "Oman", "iso3": "OMN", "lat": 19.67, "lon": 57.70, "operator": "GBR", "type": "naval_base", "branch": "Royal Navy", "notes": "Indian Ocean logistics"},
    # ── France ──
    {"name": "Djibouti FFDj", "country": "Djibouti", "iso3": "DJI", "lat": 11.55, "lon": 43.14, "operator": "FRA", "type": "army_base", "branch": "French Army", "notes": "1,500 troops, Mirage 2000"},
    {"name": "Reunion (BA 181)", "country": "Reunion", "iso3": "REU", "lat": -21.37, "lon": 55.53, "operator": "FRA", "type": "air_base", "branch": "French Air Force", "notes": "Indian Ocean surveillance"},
    {"name": "N'Djamena", "country": "Chad", "iso3": "TCD", "lat": 12.13, "lon": 15.03, "operator": "FRA", "type": "air_base", "branch": "French Air Force", "notes": "Sahel operations (reduced)"},
    {"name": "Ile Longue", "country": "France", "iso3": "FRA", "lat": 48.31, "lon": -4.52, "operator": "FRA", "type": "naval_base", "branch": "Marine Nationale", "notes": "SSBN base, M51 missiles"},
    # ── NATO ──
    {"name": "Keflavik", "country": "Iceland", "iso3": "ISL", "lat": 63.97, "lon": -22.60, "operator": "NATO", "type": "air_base", "branch": "NATO", "notes": "North Atlantic ASW, GIUK gap"},
    {"name": "Redzikowo", "country": "Poland", "iso3": "POL", "lat": 54.48, "lon": 17.10, "operator": "NATO", "type": "missile_defense", "branch": "NATO", "notes": "Aegis Ashore BMD site"},
    {"name": "Deveselu", "country": "Romania", "iso3": "ROU", "lat": 44.05, "lon": 24.37, "operator": "NATO", "type": "missile_defense", "branch": "NATO", "notes": "Aegis Ashore BMD site"},
    {"name": "Tapa", "country": "Estonia", "iso3": "EST", "lat": 59.26, "lon": 25.97, "operator": "NATO", "type": "army_base", "branch": "NATO eFP", "notes": "UK-led battlegroup"},
    {"name": "Adazi", "country": "Latvia", "iso3": "LVA", "lat": 57.08, "lon": 24.33, "operator": "NATO", "type": "army_base", "branch": "NATO eFP", "notes": "Canada-led battlegroup"},
    # ── India ──
    {"name": "INS Kadamba (Karwar)", "country": "India", "iso3": "IND", "lat": 14.81, "lon": 74.12, "operator": "IND", "type": "naval_base", "branch": "Indian Navy", "notes": "Largest naval base in Asia"},
    {"name": "Agra (Gwalior)", "country": "India", "iso3": "IND", "lat": 26.29, "lon": 78.23, "operator": "IND", "type": "air_base", "branch": "IAF", "notes": "Su-30MKI, Rafale"},
    # ── Turkey ──
    {"name": "Al-Watiya", "country": "Libya", "iso3": "LBY", "lat": 31.97, "lon": 12.02, "operator": "TUR", "type": "air_base", "branch": "Turkish AF", "notes": "Forward operating base"},
    {"name": "Mogadishu TURKSOM", "country": "Somalia", "iso3": "SOM", "lat": 2.04, "lon": 45.30, "operator": "TUR", "type": "training", "branch": "Turkish Army", "notes": "Largest overseas base"},
    # ── Israel ──
    {"name": "Nevatim", "country": "Israel", "iso3": "ISR", "lat": 31.21, "lon": 34.93, "operator": "ISR", "type": "air_base", "branch": "IAF", "notes": "F-35I Adir base"},
    {"name": "Palmachim", "country": "Israel", "iso3": "ISR", "lat": 31.90, "lon": 34.69, "operator": "ISR", "type": "space_base", "branch": "IAF", "notes": "Shavit launcher, Arrow missile"},
    # ── Iran ──
    {"name": "Bandar Abbas", "country": "Iran", "iso3": "IRN", "lat": 27.18, "lon": 56.24, "operator": "IRN", "type": "naval_base", "branch": "IRIN/IRGCN", "notes": "Strait of Hormuz control"},
    {"name": "Isfahan", "country": "Iran", "iso3": "IRN", "lat": 32.65, "lon": 51.68, "operator": "IRN", "type": "air_base", "branch": "IRIAF", "notes": "UCF uranium conversion"},
    # ── Others ──
    {"name": "Assab", "country": "Eritrea", "iso3": "ERI", "lat": 13.07, "lon": 42.74, "operator": "ARE", "type": "naval_base", "branch": "UAE Navy", "notes": "Red Sea forward base"},
    {"name": "Berbera", "country": "Somaliland", "iso3": "SOM", "lat": 10.44, "lon": 45.04, "operator": "ARE", "type": "naval_base", "branch": "UAE Navy", "notes": "Gulf of Aden logistics"},
]


# ---------------------------------------------------------------------------
# Strategic Ports — 80+ ports across 6 types
# Fields: name, country, iso3, lat, lon, type, throughput, notes
# ---------------------------------------------------------------------------

STRATEGIC_PORTS: list[dict] = [
    # ── Container mega-ports ──
    {"name": "Shanghai", "country": "China", "iso3": "CHN", "lat": 30.63, "lon": 122.07, "type": "container", "throughput": "49.7M TEU", "notes": "World's busiest port"},
    {"name": "Singapore", "country": "Singapore", "iso3": "SGP", "lat": 1.26, "lon": 103.83, "type": "container", "throughput": "39.4M TEU", "notes": "Malacca Strait transshipment hub"},
    {"name": "Ningbo-Zhoushan", "country": "China", "iso3": "CHN", "lat": 29.87, "lon": 121.87, "type": "container", "throughput": "35.3M TEU", "notes": "Cargo tonnage #1 globally"},
    {"name": "Shenzhen", "country": "China", "iso3": "CHN", "lat": 22.48, "lon": 113.92, "type": "container", "throughput": "30.0M TEU", "notes": "Pearl River Delta hub"},
    {"name": "Guangzhou", "country": "China", "iso3": "CHN", "lat": 22.94, "lon": 113.58, "type": "container", "throughput": "24.6M TEU", "notes": "South China industrial port"},
    {"name": "Busan", "country": "South Korea", "iso3": "KOR", "lat": 35.08, "lon": 129.08, "type": "container", "throughput": "22.7M TEU", "notes": "Northeast Asia transshipment"},
    {"name": "Qingdao", "country": "China", "iso3": "CHN", "lat": 36.07, "lon": 120.38, "type": "container", "throughput": "27.0M TEU", "notes": "North China hub"},
    {"name": "Rotterdam", "country": "Netherlands", "iso3": "NLD", "lat": 51.89, "lon": 4.29, "type": "container", "throughput": "14.8M TEU", "notes": "Europe's largest port"},
    {"name": "Antwerp-Bruges", "country": "Belgium", "iso3": "BEL", "lat": 51.27, "lon": 4.34, "type": "container", "throughput": "14.0M TEU", "notes": "Europe's #2 port"},
    {"name": "Tanjung Pelepas", "country": "Malaysia", "iso3": "MYS", "lat": 1.37, "lon": 103.55, "type": "container", "throughput": "11.2M TEU", "notes": "Maersk hub, Johor Strait"},
    {"name": "Los Angeles/Long Beach", "country": "United States", "iso3": "USA", "lat": 33.73, "lon": -118.27, "type": "container", "throughput": "9.9M TEU", "notes": "US West Coast gateway"},
    {"name": "Hamburg", "country": "Germany", "iso3": "DEU", "lat": 53.53, "lon": 9.97, "type": "container", "throughput": "8.7M TEU", "notes": "Germany's main seaport"},
    {"name": "Jebel Ali", "country": "UAE", "iso3": "ARE", "lat": 25.01, "lon": 55.06, "type": "container", "throughput": "14.7M TEU", "notes": "Largest port in Middle East"},
    {"name": "Colombo", "country": "Sri Lanka", "iso3": "LKA", "lat": 6.95, "lon": 79.84, "type": "container", "throughput": "7.3M TEU", "notes": "Indian Ocean transshipment"},
    {"name": "Piraeus", "country": "Greece", "iso3": "GRC", "lat": 37.94, "lon": 23.62, "type": "container", "throughput": "5.3M TEU", "notes": "COSCO-operated, BRI gateway"},
    # ── Oil & LNG terminals ──
    {"name": "Ras Tanura", "country": "Saudi Arabia", "iso3": "SAU", "lat": 26.64, "lon": 50.17, "type": "oil", "throughput": "6.5M bbl/day", "notes": "World's largest oil terminal"},
    {"name": "Kharg Island", "country": "Iran", "iso3": "IRN", "lat": 29.24, "lon": 50.33, "type": "oil", "throughput": "5.0M bbl/day", "notes": "Iran's main oil export terminal"},
    {"name": "Basra Oil Terminal", "country": "Iraq", "iso3": "IRQ", "lat": 29.68, "lon": 48.80, "type": "oil", "throughput": "3.5M bbl/day", "notes": "Iraq's primary export point"},
    {"name": "Fujairah", "country": "UAE", "iso3": "ARE", "lat": 25.15, "lon": 56.36, "type": "oil", "throughput": "3.0M bbl/day", "notes": "Bypasses Hormuz, bunkering hub"},
    {"name": "Houston Ship Channel", "country": "United States", "iso3": "USA", "lat": 29.73, "lon": -95.27, "type": "oil", "throughput": "2.0M bbl/day", "notes": "US Gulf Coast refining hub"},
    {"name": "Novorossiysk", "country": "Russia", "iso3": "RUS", "lat": 44.72, "lon": 37.77, "type": "oil", "throughput": "1.5M bbl/day", "notes": "Russia's largest Black Sea port"},
    {"name": "Ras Laffan", "country": "Qatar", "iso3": "QAT", "lat": 25.93, "lon": 51.53, "type": "lng", "throughput": "77M tons LNG/yr", "notes": "World's largest LNG port"},
    {"name": "Sabine Pass", "country": "United States", "iso3": "USA", "lat": 29.73, "lon": -93.86, "type": "lng", "throughput": "30M tons LNG/yr", "notes": "Largest US LNG export terminal"},
    {"name": "Gladstone", "country": "Australia", "iso3": "AUS", "lat": -23.84, "lon": 151.27, "type": "lng", "throughput": "25M tons LNG/yr", "notes": "Queensland LNG hub"},
    {"name": "Bonny Island", "country": "Nigeria", "iso3": "NGA", "lat": 4.43, "lon": 7.17, "type": "lng", "throughput": "22M tons LNG/yr", "notes": "Nigeria LNG (NLNG)"},
    # ── Naval ports ──
    {"name": "Changi Naval Base", "country": "Singapore", "iso3": "SGP", "lat": 1.33, "lon": 104.00, "type": "naval", "throughput": "N/A", "notes": "Republic of Singapore Navy HQ"},
    {"name": "Toulon", "country": "France", "iso3": "FRA", "lat": 43.12, "lon": 5.93, "type": "naval", "throughput": "N/A", "notes": "French Med fleet, carrier CdG"},
    {"name": "Karachi", "country": "Pakistan", "iso3": "PAK", "lat": 24.85, "lon": 66.98, "type": "naval", "throughput": "N/A", "notes": "Pakistan Navy HQ"},
    {"name": "Visakhapatnam", "country": "India", "iso3": "IND", "lat": 17.69, "lon": 83.30, "type": "naval", "throughput": "N/A", "notes": "Eastern Naval Command, submarine base"},
    # ── Bulk/mixed ──
    {"name": "Port Hedland", "country": "Australia", "iso3": "AUS", "lat": -20.31, "lon": 118.58, "type": "bulk", "throughput": "575M tons/yr", "notes": "Iron ore — world's largest bulk port"},
    {"name": "Hay Point", "country": "Australia", "iso3": "AUS", "lat": -21.28, "lon": 149.28, "type": "bulk", "throughput": "120M tons coal/yr", "notes": "Thermal/coking coal export"},
    {"name": "Richards Bay", "country": "South Africa", "iso3": "ZAF", "lat": -28.78, "lon": 32.09, "type": "bulk", "throughput": "91M tons/yr", "notes": "Africa's largest coal terminal"},
    {"name": "Mombasa", "country": "Kenya", "iso3": "KEN", "lat": -4.04, "lon": 39.65, "type": "mixed", "throughput": "37M tons/yr", "notes": "East Africa gateway, BRI terminal"},
    {"name": "Djibouti (Doraleh)", "country": "Djibouti", "iso3": "DJI", "lat": 11.59, "lon": 43.09, "type": "mixed", "throughput": "12M tons/yr", "notes": "Horn of Africa hub, Chinese-built"},
    {"name": "Gwadar", "country": "Pakistan", "iso3": "PAK", "lat": 25.12, "lon": 62.33, "type": "mixed", "throughput": "1M tons/yr", "notes": "CPEC, Chinese-operated"},
    {"name": "Hambantota", "country": "Sri Lanka", "iso3": "LKA", "lat": 6.12, "lon": 81.11, "type": "mixed", "throughput": "5M tons/yr", "notes": "Chinese 99-year lease, BRI debt-trap"},
    {"name": "Chabahar", "country": "Iran", "iso3": "IRN", "lat": 25.30, "lon": 60.64, "type": "mixed", "throughput": "8.5M tons/yr", "notes": "India-operated, bypasses Pakistan"},
    {"name": "Duqm", "country": "Oman", "iso3": "OMN", "lat": 19.67, "lon": 57.70, "type": "mixed", "throughput": "20M tons/yr", "notes": "Outside Hormuz, UK/China interests"},
    {"name": "Salalah", "country": "Oman", "iso3": "OMN", "lat": 16.95, "lon": 54.00, "type": "container", "throughput": "4.0M TEU", "notes": "Arabian Sea transshipment"},
    {"name": "Dar es Salaam", "country": "Tanzania", "iso3": "TZA", "lat": -6.83, "lon": 39.29, "type": "mixed", "throughput": "18M tons/yr", "notes": "East Africa corridor"},
]


# ---------------------------------------------------------------------------
# Oil & Gas Pipelines — 50+ strategic pipelines
# Fields: name, route, lat_start, lon_start, lat_end, lon_end, capacity, type, status, notes
# ---------------------------------------------------------------------------

PIPELINES: list[dict] = [
    # ── Oil ──
    {"name": "Druzhba Pipeline", "route": "Russia → Europe", "lat_start": 52.27, "lon_start": 40.50, "lat_end": 51.10, "lon_end": 17.03, "capacity": "1.2M bbl/day", "type": "oil", "status": "active", "notes": "World's longest oil pipeline, feeds Germany/Poland/Czech/Hungary"},
    {"name": "East Siberia-Pacific Ocean (ESPO)", "route": "Russia → China/Pacific", "lat_start": 56.90, "lon_start": 130.50, "lat_end": 42.80, "lon_end": 132.90, "capacity": "1.6M bbl/day", "type": "oil", "status": "active", "notes": "Russia's main Pacific export route"},
    {"name": "Baku-Tbilisi-Ceyhan (BTC)", "route": "Azerbaijan → Turkey", "lat_start": 40.40, "lon_start": 49.87, "lat_end": 36.77, "lon_end": 35.95, "capacity": "1.2M bbl/day", "type": "oil", "status": "active", "notes": "Caspian oil bypassing Russia/Iran"},
    {"name": "Kirkuk-Ceyhan", "route": "Iraq → Turkey", "lat_start": 35.47, "lon_start": 44.39, "lat_end": 36.77, "lon_end": 35.95, "capacity": "1.6M bbl/day", "type": "oil", "status": "intermittent", "notes": "Frequently disrupted by conflict/politics"},
    {"name": "Trans-Alaska (TAPS)", "route": "Prudhoe Bay → Valdez", "lat_start": 70.26, "lon_start": -148.34, "lat_end": 61.13, "lon_end": -146.35, "capacity": "0.5M bbl/day", "type": "oil", "status": "active", "notes": "800 miles, declining throughput"},
    {"name": "Keystone XL", "route": "Alberta → Gulf Coast", "lat_start": 52.00, "lon_start": -110.00, "lat_end": 29.73, "lon_end": -95.27, "capacity": "0.83M bbl/day", "type": "oil", "status": "cancelled", "notes": "Extension cancelled 2021, base system active"},
    {"name": "CPC Pipeline", "route": "Kazakhstan → Russia", "lat_start": 47.10, "lon_start": 51.92, "lat_end": 44.72, "lon_end": 37.77, "capacity": "1.5M bbl/day", "type": "oil", "status": "active", "notes": "Kazakhstan's main export, Novorossiysk terminal"},
    {"name": "SUMED Pipeline", "route": "Red Sea → Mediterranean", "lat_start": 29.05, "lon_start": 32.63, "lat_end": 31.04, "lon_end": 29.77, "capacity": "2.5M bbl/day", "type": "oil", "status": "active", "notes": "Suez Canal bypass for supertankers"},
    {"name": "East-West Pipeline (Petroline)", "route": "Persian Gulf → Red Sea", "lat_start": 26.35, "lon_start": 50.20, "lat_end": 22.70, "lon_end": 39.17, "capacity": "5.0M bbl/day", "type": "oil", "status": "active", "notes": "Saudi Aramco Hormuz bypass"},
    {"name": "Habshan-Fujairah", "route": "Abu Dhabi → Fujairah", "lat_start": 23.80, "lon_start": 53.82, "lat_end": 25.15, "lon_end": 56.36, "capacity": "1.5M bbl/day", "type": "oil", "status": "active", "notes": "UAE Hormuz bypass"},
    {"name": "Chad-Cameroon Pipeline", "route": "Doba → Kribi", "lat_start": 8.65, "lon_start": 16.85, "lat_end": 2.95, "lon_end": 9.91, "capacity": "0.25M bbl/day", "type": "oil", "status": "active", "notes": "Central Africa oil export"},
    # ── Natural Gas ──
    {"name": "Nord Stream 1", "route": "Russia → Germany", "lat_start": 59.95, "lon_start": 29.07, "lat_end": 54.15, "lon_end": 13.64, "capacity": "55 bcm/yr", "type": "gas", "status": "destroyed", "notes": "Sabotaged Sept 2022"},
    {"name": "Nord Stream 2", "route": "Russia → Germany", "lat_start": 59.95, "lon_start": 29.07, "lat_end": 54.15, "lon_end": 13.64, "capacity": "55 bcm/yr", "type": "gas", "status": "destroyed", "notes": "Sabotaged Sept 2022, never operational"},
    {"name": "TurkStream", "route": "Russia → Turkey", "lat_start": 44.60, "lon_start": 37.90, "lat_end": 41.67, "lon_end": 28.00, "capacity": "31.5 bcm/yr", "type": "gas", "status": "active", "notes": "Bypasses Ukraine, feeds Turkey/SE Europe"},
    {"name": "Power of Siberia", "route": "Russia → China", "lat_start": 62.00, "lon_start": 134.00, "lat_end": 47.73, "lon_end": 130.97, "capacity": "38 bcm/yr", "type": "gas", "status": "active", "notes": "Chayanda/Kovykta fields to China, ramping up"},
    {"name": "TANAP/TAP", "route": "Azerbaijan → Europe", "lat_start": 40.40, "lon_start": 49.87, "lat_end": 40.47, "lon_end": 19.49, "capacity": "16 bcm/yr", "type": "gas", "status": "active", "notes": "Southern Gas Corridor, Shah Deniz"},
    {"name": "Trans-Mediterranean (TransMed)", "route": "Algeria → Italy", "lat_start": 36.35, "lon_start": 2.87, "lat_end": 37.62, "lon_end": 12.57, "capacity": "33.5 bcm/yr", "type": "gas", "status": "active", "notes": "Via Tunisia, Enrico Mattei pipeline"},
    {"name": "Medgaz", "route": "Algeria → Spain", "lat_start": 36.80, "lon_start": 2.83, "lat_end": 36.73, "lon_end": -2.20, "capacity": "10 bcm/yr", "type": "gas", "status": "active", "notes": "Direct seabed pipeline"},
    {"name": "EastMed Pipeline", "route": "East Med → Europe", "lat_start": 33.00, "lon_start": 33.50, "lat_end": 39.50, "lon_end": 20.50, "capacity": "10 bcm/yr", "type": "gas", "status": "proposed", "notes": "Israel/Cyprus gas to Greece/Italy"},
    {"name": "Iran-Pakistan Pipeline", "route": "Iran → Pakistan", "lat_start": 27.20, "lon_start": 56.30, "lat_end": 25.00, "lon_end": 67.00, "capacity": "7.8 bcm/yr", "type": "gas", "status": "stalled", "notes": "Peace Pipeline, sanctions-blocked"},
    {"name": "Yamal-Europe", "route": "Russia → Poland/Germany", "lat_start": 67.50, "lon_start": 72.00, "lat_end": 52.40, "lon_end": 13.40, "capacity": "33 bcm/yr", "type": "gas", "status": "reduced", "notes": "Via Belarus, flows reversed 2022"},
    {"name": "Ukraine Transit System", "route": "Russia → EU via Ukraine", "lat_start": 50.45, "lon_start": 30.52, "lat_end": 48.60, "lon_end": 22.30, "capacity": "146 bcm/yr capacity", "type": "gas", "status": "terminated", "notes": "Transit contract expired Jan 2025"},
    {"name": "LNG Canada / Coastal GasLink", "route": "BC Interior → Kitimat", "lat_start": 55.30, "lon_start": -120.85, "lat_end": 54.00, "lon_end": -128.65, "capacity": "14M tons LNG/yr", "type": "gas", "status": "construction", "notes": "First Canadian Pacific LNG export"},
    # ── Hydrogen / Ammonia ──
    {"name": "European Hydrogen Backbone", "route": "Multi-country EU", "lat_start": 51.92, "lon_start": 4.48, "lat_end": 48.86, "lon_end": 2.35, "capacity": "20M tons H2/yr", "type": "hydrogen", "status": "proposed", "notes": "28,000km network by 2040, repurposed gas pipes"},
]


# ---------------------------------------------------------------------------
# Nuclear Facilities — 40+ power stations & research reactors
# Fields: name, country, iso3, lat, lon, type, capacity_mw, status, operator, notes
# ---------------------------------------------------------------------------

NUCLEAR_FACILITIES: list[dict] = [
    # ── Major power stations ──
    {"name": "Zaporizhzhia NPP", "country": "Ukraine", "iso3": "UKR", "lat": 47.51, "lon": 34.58, "type": "power", "capacity_mw": 5700, "status": "occupied", "operator": "Energoatom", "notes": "Europe's largest NPP, Russian-occupied since 2022"},
    {"name": "Bruce Power", "country": "Canada", "iso3": "CAN", "lat": 44.33, "lon": -81.60, "type": "power", "capacity_mw": 6232, "status": "operational", "operator": "Bruce Power", "notes": "World's largest operating nuclear plant"},
    {"name": "Kashiwazaki-Kariwa", "country": "Japan", "iso3": "JPN", "lat": 37.43, "lon": 138.60, "type": "power", "capacity_mw": 7965, "status": "shutdown", "operator": "TEPCO", "notes": "World's largest by capacity, offline since 2012"},
    {"name": "Hanul (Ulchin)", "country": "South Korea", "iso3": "KOR", "lat": 37.09, "lon": 129.38, "type": "power", "capacity_mw": 5928, "status": "operational", "operator": "KHNP", "notes": "6 units, APR-1400"},
    {"name": "Gravelines", "country": "France", "iso3": "FRA", "lat": 51.01, "lon": 2.11, "type": "power", "capacity_mw": 5460, "status": "operational", "operator": "EDF", "notes": "Europe's 2nd largest, 6 units"},
    {"name": "Cattenom", "country": "France", "iso3": "FRA", "lat": 49.41, "lon": 6.22, "type": "power", "capacity_mw": 5200, "status": "operational", "operator": "EDF", "notes": "4 x 1300MW, near Luxembourg border"},
    {"name": "Palo Verde", "country": "United States", "iso3": "USA", "lat": 33.39, "lon": -112.86, "type": "power", "capacity_mw": 3937, "status": "operational", "operator": "APS", "notes": "Largest US nuclear plant, 3 units"},
    {"name": "Barakah", "country": "UAE", "iso3": "ARE", "lat": 23.97, "lon": 52.26, "type": "power", "capacity_mw": 5380, "status": "operational", "operator": "Nawah/ENEC", "notes": "First Arab nuclear plant, Korean APR-1400"},
    {"name": "Vogtle", "country": "United States", "iso3": "USA", "lat": 33.14, "lon": -81.76, "type": "power", "capacity_mw": 4540, "status": "operational", "operator": "Southern Nuclear", "notes": "Only new US reactors in 30 years (Units 3-4 AP1000)"},
    {"name": "Hinkley Point C", "country": "United Kingdom", "iso3": "GBR", "lat": 51.21, "lon": -3.13, "type": "power", "capacity_mw": 3200, "status": "construction", "operator": "EDF/CGN", "notes": "First new UK plant in 20 years, EPR"},
    {"name": "Olkiluoto", "country": "Finland", "iso3": "FIN", "lat": 61.24, "lon": 21.45, "type": "power", "capacity_mw": 4390, "status": "operational", "operator": "TVO", "notes": "EPR Unit 3 operational 2023, 14 years late"},
    {"name": "Rooppur", "country": "Bangladesh", "iso3": "BGD", "lat": 24.07, "lon": 89.05, "type": "power", "capacity_mw": 2400, "status": "construction", "operator": "Rosatom", "notes": "Bangladesh's first nuclear plant"},
    {"name": "Akkuyu", "country": "Turkey", "iso3": "TUR", "lat": 36.14, "lon": 33.53, "type": "power", "capacity_mw": 4800, "status": "construction", "operator": "Rosatom", "notes": "Turkey's first nuclear plant"},
    {"name": "Flamanville 3", "country": "France", "iso3": "FRA", "lat": 49.54, "lon": -1.88, "type": "power", "capacity_mw": 1630, "status": "commissioning", "operator": "EDF", "notes": "EPR, massive delays/overruns"},
    {"name": "Taishan", "country": "China", "iso3": "CHN", "lat": 21.91, "lon": 112.98, "type": "power", "capacity_mw": 3460, "status": "operational", "operator": "CGN", "notes": "World's first EPR in operation"},
    {"name": "Kudankulam", "country": "India", "iso3": "IND", "lat": 8.17, "lon": 77.71, "type": "power", "capacity_mw": 4000, "status": "operational", "operator": "NPCIL", "notes": "VVER-1000, Units 3-6 under construction"},
    # ── Enrichment / fuel cycle ──
    {"name": "Natanz", "country": "Iran", "iso3": "IRN", "lat": 33.72, "lon": 51.73, "type": "enrichment", "capacity_mw": 0, "status": "operational", "operator": "AEOI", "notes": "Iran's main enrichment site, Stuxnet target"},
    {"name": "Fordow", "country": "Iran", "iso3": "IRN", "lat": 34.88, "lon": 51.59, "type": "enrichment", "capacity_mw": 0, "status": "operational", "operator": "AEOI", "notes": "Underground enrichment, near-weapons grade"},
    {"name": "Yongbyon", "country": "North Korea", "iso3": "PRK", "lat": 39.80, "lon": 125.75, "type": "research", "capacity_mw": 5, "status": "operational", "operator": "DPRK", "notes": "Plutonium production reactor"},
    {"name": "Dimona", "country": "Israel", "iso3": "ISR", "lat": 31.00, "lon": 35.15, "type": "research", "capacity_mw": 26, "status": "operational", "operator": "IAEC", "notes": "Undeclared weapons program"},
    {"name": "Sellafield", "country": "United Kingdom", "iso3": "GBR", "lat": 54.42, "lon": -3.50, "type": "reprocessing", "capacity_mw": 0, "status": "decommissioning", "operator": "NDA", "notes": "Major reprocessing/cleanup site"},
    {"name": "La Hague", "country": "France", "iso3": "FRA", "lat": 49.68, "lon": -1.88, "type": "reprocessing", "capacity_mw": 0, "status": "operational", "operator": "Orano", "notes": "World's largest reprocessing plant"},
    {"name": "Chernobyl", "country": "Ukraine", "iso3": "UKR", "lat": 51.39, "lon": 30.10, "type": "decommissioned", "capacity_mw": 0, "status": "exclusion_zone", "operator": "SAUEZM", "notes": "1986 disaster, New Safe Confinement"},
    {"name": "Fukushima Daiichi", "country": "Japan", "iso3": "JPN", "lat": 37.42, "lon": 141.03, "type": "decommissioned", "capacity_mw": 0, "status": "decommissioning", "operator": "TEPCO", "notes": "2011 meltdown, water release ongoing"},
]


# ---------------------------------------------------------------------------
# Lookup / query helpers
# ---------------------------------------------------------------------------

def query_bases(
    operator: str | None = None,
    country: str | None = None,
    base_type: str | None = None,
    branch: str | None = None,
) -> list[dict]:
    """Filter military bases by operator, country, type, or branch."""
    results = MILITARY_BASES
    if operator:
        op = operator.upper()
        results = [b for b in results if b["operator"].upper() == op]
    if country:
        c = country.lower()
        results = [b for b in results if c in b["country"].lower() or c == b["iso3"].lower()]
    if base_type:
        t = base_type.lower()
        results = [b for b in results if t in b["type"]]
    if branch:
        br = branch.lower()
        results = [b for b in results if br in b["branch"].lower()]
    return results


def query_ports(
    port_type: str | None = None,
    country: str | None = None,
) -> list[dict]:
    """Filter strategic ports by type or country."""
    results = STRATEGIC_PORTS
    if port_type:
        t = port_type.lower()
        results = [p for p in results if t in p["type"]]
    if country:
        c = country.lower()
        results = [p for p in results if c in p["country"].lower() or c == p["iso3"].lower()]
    return results


def query_pipelines(
    pipeline_type: str | None = None,
    status: str | None = None,
) -> list[dict]:
    """Filter pipelines by type (oil/gas/hydrogen) or status."""
    results = PIPELINES
    if pipeline_type:
        t = pipeline_type.lower()
        results = [p for p in results if t in p["type"]]
    if status:
        s = status.lower()
        results = [p for p in results if s in p["status"]]
    return results


def query_nuclear(
    facility_type: str | None = None,
    country: str | None = None,
    status: str | None = None,
) -> list[dict]:
    """Filter nuclear facilities by type, country, or status."""
    results = NUCLEAR_FACILITIES
    if facility_type:
        t = facility_type.lower()
        results = [f for f in results if t in f["type"]]
    if country:
        c = country.lower()
        results = [f for f in results if c in f["country"].lower() or c == f["iso3"].lower()]
    if status:
        s = status.lower()
        results = [f for f in results if s in f["status"]]
    return results
