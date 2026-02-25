"""Global stock exchanges dataset.

Pure data module — no I/O, no external dependencies.
Sources: World Federation of Exchanges, GFCI, World Bank, press.
92 exchanges organized by tier (mega, major, emerging, frontier).
"""

from __future__ import annotations

STOCK_EXCHANGES: list[dict] = [
    # Mega exchanges (>$3T market cap)
    {"name": "New York Stock Exchange", "acronym": "NYSE", "country": "USA", "iso3": "USA", "city": "New York", "lat": 40.71, "lon": -74.01, "tier": "mega", "market_cap_usd_t": 28.4, "index": "^DJI", "currency": "USD", "timezone": "America/New_York"},
    {"name": "NASDAQ", "acronym": "NASDAQ", "country": "USA", "iso3": "USA", "city": "New York", "lat": 40.76, "lon": -73.99, "tier": "mega", "market_cap_usd_t": 25.5, "index": "^IXIC", "currency": "USD", "timezone": "America/New_York"},
    {"name": "Shanghai Stock Exchange", "acronym": "SSE", "country": "China", "iso3": "CHN", "city": "Shanghai", "lat": 31.23, "lon": 121.47, "tier": "mega", "market_cap_usd_t": 6.9, "index": "000001.SS", "currency": "CNY", "timezone": "Asia/Shanghai"},
    {"name": "Japan Exchange Group", "acronym": "JPX", "country": "Japan", "iso3": "JPN", "city": "Tokyo", "lat": 35.68, "lon": 139.77, "tier": "mega", "market_cap_usd_t": 6.5, "index": "^N225", "currency": "JPY", "timezone": "Asia/Tokyo"},
    {"name": "Shenzhen Stock Exchange", "acronym": "SZSE", "country": "China", "iso3": "CHN", "city": "Shenzhen", "lat": 22.54, "lon": 114.06, "tier": "mega", "market_cap_usd_t": 4.9, "index": "399001.SZ", "currency": "CNY", "timezone": "Asia/Shanghai"},
    {"name": "Hong Kong Exchanges", "acronym": "HKEX", "country": "China", "iso3": "HKG", "city": "Hong Kong", "lat": 22.28, "lon": 114.16, "tier": "mega", "market_cap_usd_t": 4.6, "index": "^HSI", "currency": "HKD", "timezone": "Asia/Hong_Kong"},
    {"name": "National Stock Exchange of India", "acronym": "NSE", "country": "India", "iso3": "IND", "city": "Mumbai", "lat": 19.06, "lon": 72.86, "tier": "mega", "market_cap_usd_t": 4.3, "index": "^NSEI", "currency": "INR", "timezone": "Asia/Kolkata"},
    {"name": "London Stock Exchange", "acronym": "LSE", "country": "UK", "iso3": "GBR", "city": "London", "lat": 51.51, "lon": -0.09, "tier": "mega", "market_cap_usd_t": 3.4, "index": "^FTSE", "currency": "GBP", "timezone": "Europe/London"},
    {"name": "Euronext", "acronym": "ENX", "country": "Netherlands", "iso3": "NLD", "city": "Amsterdam", "lat": 52.37, "lon": 4.89, "tier": "mega", "market_cap_usd_t": 7.3, "index": "^AEX", "currency": "EUR", "timezone": "Europe/Amsterdam"},
    # Major exchanges ($500B-$3T)
    {"name": "Toronto Stock Exchange", "acronym": "TSX", "country": "Canada", "iso3": "CAN", "city": "Toronto", "lat": 43.65, "lon": -79.38, "tier": "major", "market_cap_usd_t": 2.8, "index": "^GSPTSE", "currency": "CAD", "timezone": "America/Toronto"},
    {"name": "Saudi Exchange (Tadawul)", "acronym": "TADAWUL", "country": "Saudi Arabia", "iso3": "SAU", "city": "Riyadh", "lat": 24.71, "lon": 46.67, "tier": "major", "market_cap_usd_t": 2.9, "index": "^TASI", "currency": "SAR", "timezone": "Asia/Riyadh"},
    {"name": "Deutsche Börse", "acronym": "XETRA", "country": "Germany", "iso3": "DEU", "city": "Frankfurt", "lat": 50.11, "lon": 8.68, "tier": "major", "market_cap_usd_t": 2.3, "index": "^GDAXI", "currency": "EUR", "timezone": "Europe/Berlin"},
    {"name": "SIX Swiss Exchange", "acronym": "SIX", "country": "Switzerland", "iso3": "CHE", "city": "Zurich", "lat": 47.37, "lon": 8.54, "tier": "major", "market_cap_usd_t": 1.9, "index": "^SSMI", "currency": "CHF", "timezone": "Europe/Zurich"},
    {"name": "Korea Exchange", "acronym": "KRX", "country": "South Korea", "iso3": "KOR", "city": "Seoul", "lat": 37.52, "lon": 126.93, "tier": "major", "market_cap_usd_t": 1.8, "index": "^KS11", "currency": "KRW", "timezone": "Asia/Seoul"},
    {"name": "Nasdaq Nordic (OMX)", "acronym": "OMX", "country": "Sweden", "iso3": "SWE", "city": "Stockholm", "lat": 59.33, "lon": 18.07, "tier": "major", "market_cap_usd_t": 1.7, "index": "^OMX", "currency": "SEK", "timezone": "Europe/Stockholm"},
    {"name": "Australian Securities Exchange", "acronym": "ASX", "country": "Australia", "iso3": "AUS", "city": "Sydney", "lat": -33.87, "lon": 151.21, "tier": "major", "market_cap_usd_t": 1.6, "index": "^AXJO", "currency": "AUD", "timezone": "Australia/Sydney"},
    {"name": "Taiwan Stock Exchange", "acronym": "TWSE", "country": "Taiwan", "iso3": "TWN", "city": "Taipei", "lat": 25.03, "lon": 121.52, "tier": "major", "market_cap_usd_t": 2.1, "index": "^TWII", "currency": "TWD", "timezone": "Asia/Taipei"},
    {"name": "Bombay Stock Exchange", "acronym": "BSE", "country": "India", "iso3": "IND", "city": "Mumbai", "lat": 18.93, "lon": 72.83, "tier": "major", "market_cap_usd_t": 4.1, "index": "^BSESN", "currency": "INR", "timezone": "Asia/Kolkata"},
    {"name": "Johannesburg Stock Exchange", "acronym": "JSE", "country": "South Africa", "iso3": "ZAF", "city": "Johannesburg", "lat": -26.20, "lon": 28.04, "tier": "major", "market_cap_usd_t": 1.1, "index": "^J203", "currency": "ZAR", "timezone": "Africa/Johannesburg"},
    {"name": "B3 (Brasil Bolsa Balcão)", "acronym": "B3", "country": "Brazil", "iso3": "BRA", "city": "São Paulo", "lat": -23.55, "lon": -46.63, "tier": "major", "market_cap_usd_t": 0.9, "index": "^BVSP", "currency": "BRL", "timezone": "America/Sao_Paulo"},
    {"name": "Borsa Italiana", "acronym": "BIT", "country": "Italy", "iso3": "ITA", "city": "Milan", "lat": 45.46, "lon": 9.19, "tier": "major", "market_cap_usd_t": 0.8, "index": "FTSEMIB.MI", "currency": "EUR", "timezone": "Europe/Rome"},
    {"name": "BME Spanish Exchanges", "acronym": "BME", "country": "Spain", "iso3": "ESP", "city": "Madrid", "lat": 40.42, "lon": -3.70, "tier": "major", "market_cap_usd_t": 0.7, "index": "^IBEX", "currency": "EUR", "timezone": "Europe/Madrid"},
    {"name": "Singapore Exchange", "acronym": "SGX", "country": "Singapore", "iso3": "SGP", "city": "Singapore", "lat": 1.28, "lon": 103.85, "tier": "major", "market_cap_usd_t": 0.6, "index": "^STI", "currency": "SGD", "timezone": "Asia/Singapore"},
    {"name": "Bolsa Mexicana de Valores", "acronym": "BMV", "country": "Mexico", "iso3": "MEX", "city": "Mexico City", "lat": 19.43, "lon": -99.13, "tier": "major", "market_cap_usd_t": 0.5, "index": "^MXX", "currency": "MXN", "timezone": "America/Mexico_City"},
    {"name": "Tel Aviv Stock Exchange", "acronym": "TASE", "country": "Israel", "iso3": "ISR", "city": "Tel Aviv", "lat": 32.07, "lon": 34.77, "tier": "major", "market_cap_usd_t": 0.3, "index": "^TA125", "currency": "ILS", "timezone": "Asia/Jerusalem"},
    # Emerging exchanges ($50B-$500B)
    {"name": "Indonesia Stock Exchange", "acronym": "IDX", "country": "Indonesia", "iso3": "IDN", "city": "Jakarta", "lat": -6.22, "lon": 106.85, "tier": "emerging", "market_cap_usd_t": 0.6, "index": "^JKSE", "currency": "IDR", "timezone": "Asia/Jakarta"},
    {"name": "Bursa Malaysia", "acronym": "BM", "country": "Malaysia", "iso3": "MYS", "city": "Kuala Lumpur", "lat": 3.15, "lon": 101.71, "tier": "emerging", "market_cap_usd_t": 0.4, "index": "^KLSE", "currency": "MYR", "timezone": "Asia/Kuala_Lumpur"},
    {"name": "Stock Exchange of Thailand", "acronym": "SET", "country": "Thailand", "iso3": "THA", "city": "Bangkok", "lat": 13.76, "lon": 100.50, "tier": "emerging", "market_cap_usd_t": 0.5, "index": "^SET", "currency": "THB", "timezone": "Asia/Bangkok"},
    {"name": "Philippine Stock Exchange", "acronym": "PSE", "country": "Philippines", "iso3": "PHL", "city": "Manila", "lat": 14.59, "lon": 120.98, "tier": "emerging", "market_cap_usd_t": 0.3, "index": "PSEI.PS", "currency": "PHP", "timezone": "Asia/Manila"},
    {"name": "Ho Chi Minh Stock Exchange", "acronym": "HOSE", "country": "Vietnam", "iso3": "VNM", "city": "Ho Chi Minh City", "lat": 10.77, "lon": 106.70, "tier": "emerging", "market_cap_usd_t": 0.2, "index": "^VNINDEX", "currency": "VND", "timezone": "Asia/Ho_Chi_Minh"},
    {"name": "Colombo Stock Exchange", "acronym": "CSE", "country": "Sri Lanka", "iso3": "LKA", "city": "Colombo", "lat": 6.93, "lon": 79.84, "tier": "emerging", "market_cap_usd_t": 0.02, "index": "^CSE", "currency": "LKR", "timezone": "Asia/Colombo"},
    {"name": "Abu Dhabi Securities Exchange", "acronym": "ADX", "country": "UAE", "iso3": "ARE", "city": "Abu Dhabi", "lat": 24.45, "lon": 54.65, "tier": "emerging", "market_cap_usd_t": 0.8, "index": "^ADI", "currency": "AED", "timezone": "Asia/Dubai"},
    {"name": "Dubai Financial Market", "acronym": "DFM", "country": "UAE", "iso3": "ARE", "city": "Dubai", "lat": 25.20, "lon": 55.27, "tier": "emerging", "market_cap_usd_t": 0.2, "index": "^DFMGI", "currency": "AED", "timezone": "Asia/Dubai"},
    {"name": "Qatar Stock Exchange", "acronym": "QSE", "country": "Qatar", "iso3": "QAT", "city": "Doha", "lat": 25.29, "lon": 51.53, "tier": "emerging", "market_cap_usd_t": 0.2, "index": "^QSI", "currency": "QAR", "timezone": "Asia/Qatar"},
    {"name": "Kuwait Stock Exchange", "acronym": "BK", "country": "Kuwait", "iso3": "KWT", "city": "Kuwait City", "lat": 29.38, "lon": 47.99, "tier": "emerging", "market_cap_usd_t": 0.1, "index": "^BKP", "currency": "KWD", "timezone": "Asia/Kuwait"},
    {"name": "Bahrain Bourse", "acronym": "BHB", "country": "Bahrain", "iso3": "BHR", "city": "Manama", "lat": 26.22, "lon": 50.59, "tier": "emerging", "market_cap_usd_t": 0.03, "index": "^BAX", "currency": "BHD", "timezone": "Asia/Bahrain"},
    {"name": "Muscat Securities Market", "acronym": "MSM", "country": "Oman", "iso3": "OMN", "city": "Muscat", "lat": 23.61, "lon": 58.59, "tier": "emerging", "market_cap_usd_t": 0.03, "index": "^MSI", "currency": "OMR", "timezone": "Asia/Muscat"},
    {"name": "Casablanca Stock Exchange", "acronym": "CSE", "country": "Morocco", "iso3": "MAR", "city": "Casablanca", "lat": 33.59, "lon": -7.62, "tier": "emerging", "market_cap_usd_t": 0.07, "index": "^MASI", "currency": "MAD", "timezone": "Africa/Casablanca"},
    {"name": "Egyptian Exchange", "acronym": "EGX", "country": "Egypt", "iso3": "EGY", "city": "Cairo", "lat": 30.04, "lon": 31.24, "tier": "emerging", "market_cap_usd_t": 0.04, "index": "^EGX30", "currency": "EGP", "timezone": "Africa/Cairo"},
    {"name": "Nairobi Securities Exchange", "acronym": "NSE", "country": "Kenya", "iso3": "KEN", "city": "Nairobi", "lat": -1.29, "lon": 36.82, "tier": "emerging", "market_cap_usd_t": 0.02, "index": "^NSE20", "currency": "KES", "timezone": "Africa/Nairobi"},
    {"name": "Nigerian Exchange", "acronym": "NGX", "country": "Nigeria", "iso3": "NGA", "city": "Lagos", "lat": 6.45, "lon": 3.40, "tier": "emerging", "market_cap_usd_t": 0.04, "index": "^NGSE", "currency": "NGN", "timezone": "Africa/Lagos"},
    {"name": "Santiago Stock Exchange", "acronym": "BCS", "country": "Chile", "iso3": "CHL", "city": "Santiago", "lat": -33.44, "lon": -70.66, "tier": "emerging", "market_cap_usd_t": 0.2, "index": "^IPSA", "currency": "CLP", "timezone": "America/Santiago"},
    {"name": "Buenos Aires Stock Exchange", "acronym": "BCBA", "country": "Argentina", "iso3": "ARG", "city": "Buenos Aires", "lat": -34.61, "lon": -58.37, "tier": "emerging", "market_cap_usd_t": 0.06, "index": "^MERV", "currency": "ARS", "timezone": "America/Argentina/Buenos_Aires"},
    {"name": "Lima Stock Exchange", "acronym": "BVL", "country": "Peru", "iso3": "PER", "city": "Lima", "lat": -12.05, "lon": -77.04, "tier": "emerging", "market_cap_usd_t": 0.08, "index": "^SPBLPGPT", "currency": "PEN", "timezone": "America/Lima"},
    {"name": "Colombia Stock Exchange", "acronym": "BVC", "country": "Colombia", "iso3": "COL", "city": "Bogotá", "lat": 4.71, "lon": -74.07, "tier": "emerging", "market_cap_usd_t": 0.07, "index": "^COLCAP", "currency": "COP", "timezone": "America/Bogota"},
    {"name": "Warsaw Stock Exchange", "acronym": "WSE", "country": "Poland", "iso3": "POL", "city": "Warsaw", "lat": 52.23, "lon": 21.01, "tier": "emerging", "market_cap_usd_t": 0.2, "index": "^WIG20", "currency": "PLN", "timezone": "Europe/Warsaw"},
    {"name": "Moscow Exchange", "acronym": "MOEX", "country": "Russia", "iso3": "RUS", "city": "Moscow", "lat": 55.76, "lon": 37.62, "tier": "emerging", "market_cap_usd_t": 0.6, "index": "IMOEX.ME", "currency": "RUB", "timezone": "Europe/Moscow"},
    {"name": "Istanbul Stock Exchange", "acronym": "BIST", "country": "Turkey", "iso3": "TUR", "city": "Istanbul", "lat": 41.01, "lon": 28.98, "tier": "emerging", "market_cap_usd_t": 0.3, "index": "^XU100", "currency": "TRY", "timezone": "Europe/Istanbul"},
    {"name": "Athens Stock Exchange", "acronym": "ATHEX", "country": "Greece", "iso3": "GRC", "city": "Athens", "lat": 37.98, "lon": 23.73, "tier": "emerging", "market_cap_usd_t": 0.08, "index": "^ATG", "currency": "EUR", "timezone": "Europe/Athens"},
    {"name": "Bucharest Stock Exchange", "acronym": "BVB", "country": "Romania", "iso3": "ROU", "city": "Bucharest", "lat": 44.43, "lon": 26.10, "tier": "emerging", "market_cap_usd_t": 0.06, "index": "^BET", "currency": "RON", "timezone": "Europe/Bucharest"},
    {"name": "Prague Stock Exchange", "acronym": "PSE", "country": "Czech Republic", "iso3": "CZE", "city": "Prague", "lat": 50.08, "lon": 14.43, "tier": "emerging", "market_cap_usd_t": 0.03, "index": "^PX", "currency": "CZK", "timezone": "Europe/Prague"},
    {"name": "Budapest Stock Exchange", "acronym": "BSE", "country": "Hungary", "iso3": "HUN", "city": "Budapest", "lat": 47.50, "lon": 19.04, "tier": "emerging", "market_cap_usd_t": 0.04, "index": "^BUX", "currency": "HUF", "timezone": "Europe/Budapest"},
    {"name": "Pakistan Stock Exchange", "acronym": "PSX", "country": "Pakistan", "iso3": "PAK", "city": "Karachi", "lat": 24.85, "lon": 67.01, "tier": "emerging", "market_cap_usd_t": 0.04, "index": "^KSE100", "currency": "PKR", "timezone": "Asia/Karachi"},
    {"name": "Dhaka Stock Exchange", "acronym": "DSE", "country": "Bangladesh", "iso3": "BGD", "city": "Dhaka", "lat": 23.73, "lon": 90.39, "tier": "emerging", "market_cap_usd_t": 0.05, "index": "^DSEX", "currency": "BDT", "timezone": "Asia/Dhaka"},
    # Frontier / smaller
    {"name": "Amman Stock Exchange", "acronym": "ASE", "country": "Jordan", "iso3": "JOR", "city": "Amman", "lat": 31.95, "lon": 35.93, "tier": "frontier", "market_cap_usd_t": 0.02, "index": "^AMGNRLX", "currency": "JOD", "timezone": "Asia/Amman"},
    {"name": "Tunis Stock Exchange", "acronym": "BVMT", "country": "Tunisia", "iso3": "TUN", "city": "Tunis", "lat": 36.80, "lon": 10.18, "tier": "frontier", "market_cap_usd_t": 0.01, "index": "^TUNINDEX", "currency": "TND", "timezone": "Africa/Tunis"},
    {"name": "Dar es Salaam Stock Exchange", "acronym": "DSE", "country": "Tanzania", "iso3": "TZA", "city": "Dar es Salaam", "lat": -6.79, "lon": 39.28, "tier": "frontier", "market_cap_usd_t": 0.01, "index": "^DSI", "currency": "TZS", "timezone": "Africa/Dar_es_Salaam"},
    {"name": "Uganda Securities Exchange", "acronym": "USE", "country": "Uganda", "iso3": "UGA", "city": "Kampala", "lat": 0.31, "lon": 32.58, "tier": "frontier", "market_cap_usd_t": 0.005, "index": "^ALSI", "currency": "UGX", "timezone": "Africa/Kampala"},
    {"name": "Rwanda Stock Exchange", "acronym": "RSE", "country": "Rwanda", "iso3": "RWA", "city": "Kigali", "lat": -1.94, "lon": 30.06, "tier": "frontier", "market_cap_usd_t": 0.003, "index": "^RSI", "currency": "RWF", "timezone": "Africa/Kigali"},
    {"name": "Ghana Stock Exchange", "acronym": "GSE", "country": "Ghana", "iso3": "GHA", "city": "Accra", "lat": 5.56, "lon": -0.19, "tier": "frontier", "market_cap_usd_t": 0.01, "index": "^GGSECI", "currency": "GHS", "timezone": "Africa/Accra"},
    {"name": "Zimbabwe Stock Exchange", "acronym": "ZSE", "country": "Zimbabwe", "iso3": "ZWE", "city": "Harare", "lat": -17.83, "lon": 31.05, "tier": "frontier", "market_cap_usd_t": 0.003, "index": "^ZSI", "currency": "ZWL", "timezone": "Africa/Harare"},
    {"name": "Botswana Stock Exchange", "acronym": "BSE", "country": "Botswana", "iso3": "BWA", "city": "Gaborone", "lat": -24.65, "lon": 25.91, "tier": "frontier", "market_cap_usd_t": 0.004, "index": "^DCI", "currency": "BWP", "timezone": "Africa/Gaborone"},
    {"name": "Lusaka Securities Exchange", "acronym": "LuSE", "country": "Zambia", "iso3": "ZMB", "city": "Lusaka", "lat": -15.39, "lon": 28.32, "tier": "frontier", "market_cap_usd_t": 0.005, "index": "^LASI", "currency": "ZMW", "timezone": "Africa/Lusaka"},
    {"name": "Mauritius Stock Exchange", "acronym": "SEM", "country": "Mauritius", "iso3": "MUS", "city": "Port Louis", "lat": -20.16, "lon": 57.50, "tier": "frontier", "market_cap_usd_t": 0.01, "index": "^SEMDEX", "currency": "MUR", "timezone": "Indian/Mauritius"},
    {"name": "Nepal Stock Exchange", "acronym": "NEPSE", "country": "Nepal", "iso3": "NPL", "city": "Kathmandu", "lat": 27.71, "lon": 85.32, "tier": "frontier", "market_cap_usd_t": 0.02, "index": "^NEPSE", "currency": "NPR", "timezone": "Asia/Kathmandu"},
    {"name": "Cambodia Securities Exchange", "acronym": "CSX", "country": "Cambodia", "iso3": "KHM", "city": "Phnom Penh", "lat": 11.56, "lon": 104.93, "tier": "frontier", "market_cap_usd_t": 0.003, "index": "^CSXI", "currency": "KHR", "timezone": "Asia/Phnom_Penh"},
    {"name": "Lao Securities Exchange", "acronym": "LSX", "country": "Laos", "iso3": "LAO", "city": "Vientiane", "lat": 17.97, "lon": 102.63, "tier": "frontier", "market_cap_usd_t": 0.001, "index": "^LSXI", "currency": "LAK", "timezone": "Asia/Vientiane"},
    {"name": "Mongolia Stock Exchange", "acronym": "MSE", "country": "Mongolia", "iso3": "MNG", "city": "Ulaanbaatar", "lat": 47.92, "lon": 106.91, "tier": "frontier", "market_cap_usd_t": 0.002, "index": "^MNT20", "currency": "MNT", "timezone": "Asia/Ulaanbaatar"},
    {"name": "Tehran Stock Exchange", "acronym": "TSE", "country": "Iran", "iso3": "IRN", "city": "Tehran", "lat": 35.69, "lon": 51.42, "tier": "emerging", "market_cap_usd_t": 0.2, "index": "^TEDPIX", "currency": "IRR", "timezone": "Asia/Tehran"},
    {"name": "Karachi Stock Exchange (merged into PSX)", "acronym": "KSE", "country": "Pakistan", "iso3": "PAK", "city": "Karachi", "lat": 24.85, "lon": 67.01, "tier": "emerging", "market_cap_usd_t": 0.0, "index": "", "currency": "PKR", "timezone": "Asia/Karachi"},
    {"name": "Colombo Stock Exchange", "acronym": "CSE", "country": "Sri Lanka", "iso3": "LKA", "city": "Colombo", "lat": 6.93, "lon": 79.85, "tier": "frontier", "market_cap_usd_t": 0.02, "index": "^ASPI", "currency": "LKR", "timezone": "Asia/Colombo"},
    {"name": "New Zealand Exchange", "acronym": "NZX", "country": "New Zealand", "iso3": "NZL", "city": "Wellington", "lat": -41.29, "lon": 174.78, "tier": "major", "market_cap_usd_t": 0.1, "index": "^NZ50", "currency": "NZD", "timezone": "Pacific/Auckland"},
    {"name": "Oslo Stock Exchange", "acronym": "OSE", "country": "Norway", "iso3": "NOR", "city": "Oslo", "lat": 59.91, "lon": 10.75, "tier": "major", "market_cap_usd_t": 0.3, "index": "^OBX", "currency": "NOK", "timezone": "Europe/Oslo"},
    {"name": "Copenhagen Stock Exchange", "acronym": "CSE", "country": "Denmark", "iso3": "DNK", "city": "Copenhagen", "lat": 55.68, "lon": 12.57, "tier": "major", "market_cap_usd_t": 0.7, "index": "^OMXC25", "currency": "DKK", "timezone": "Europe/Copenhagen"},
    {"name": "Helsinki Stock Exchange", "acronym": "OMXH", "country": "Finland", "iso3": "FIN", "city": "Helsinki", "lat": 60.17, "lon": 24.94, "tier": "major", "market_cap_usd_t": 0.3, "index": "^OMXH25", "currency": "EUR", "timezone": "Europe/Helsinki"},
    {"name": "Vienna Stock Exchange", "acronym": "VSE", "country": "Austria", "iso3": "AUT", "city": "Vienna", "lat": 48.21, "lon": 16.37, "tier": "emerging", "market_cap_usd_t": 0.1, "index": "^ATX", "currency": "EUR", "timezone": "Europe/Vienna"},
    {"name": "Lisbon Stock Exchange (Euronext)", "acronym": "ELX", "country": "Portugal", "iso3": "PRT", "city": "Lisbon", "lat": 38.72, "lon": -9.14, "tier": "emerging", "market_cap_usd_t": 0.08, "index": "^PSI20", "currency": "EUR", "timezone": "Europe/Lisbon"},
    {"name": "Brussels Stock Exchange (Euronext)", "acronym": "EBR", "country": "Belgium", "iso3": "BEL", "city": "Brussels", "lat": 50.85, "lon": 4.35, "tier": "major", "market_cap_usd_t": 0.3, "index": "^BFX", "currency": "EUR", "timezone": "Europe/Brussels"},
    {"name": "Irish Stock Exchange (Euronext)", "acronym": "ISE", "country": "Ireland", "iso3": "IRL", "city": "Dublin", "lat": 53.35, "lon": -6.26, "tier": "emerging", "market_cap_usd_t": 0.1, "index": "^ISEQ", "currency": "EUR", "timezone": "Europe/Dublin"},
    {"name": "Zagreb Stock Exchange", "acronym": "ZSE", "country": "Croatia", "iso3": "HRV", "city": "Zagreb", "lat": 45.81, "lon": 15.98, "tier": "frontier", "market_cap_usd_t": 0.03, "index": "^CRBEX", "currency": "EUR", "timezone": "Europe/Zagreb"},
    {"name": "Ljubljana Stock Exchange", "acronym": "LJSE", "country": "Slovenia", "iso3": "SVN", "city": "Ljubljana", "lat": 46.05, "lon": 14.51, "tier": "frontier", "market_cap_usd_t": 0.01, "index": "^SBITOP", "currency": "EUR", "timezone": "Europe/Ljubljana"},
    {"name": "Beirut Stock Exchange", "acronym": "BSE", "country": "Lebanon", "iso3": "LBN", "city": "Beirut", "lat": 33.89, "lon": 35.50, "tier": "frontier", "market_cap_usd_t": 0.003, "index": "^BLOM", "currency": "LBP", "timezone": "Asia/Beirut"},
]


# Country ISO3 → primary exchange index ticker mapping
COUNTRY_INDEX_TICKERS: dict[str, str] = {
    ex["iso3"]: ex["index"]
    for ex in STOCK_EXCHANGES
    if ex["index"] and ex["tier"] in ("mega", "major")
}
# Override duplicates (keep largest by market cap)
COUNTRY_INDEX_TICKERS.update({
    "USA": "^GSPC",   # S&P 500 as default US index
    "CHN": "000001.SS",
    "IND": "^NSEI",
    "ARE": "^ADI",
})


def query_exchanges(
    tier: str | None = None,
    country: str | None = None,
    currency: str | None = None,
) -> list[dict]:
    """Filter stock exchanges by tier, country, or currency."""
    results = []
    for ex in STOCK_EXCHANGES:
        if tier and ex["tier"] != tier.lower():
            continue
        if country:
            c = country.lower()
            if c not in (ex["country"].lower(), ex["iso3"].lower()):
                continue
        if currency and ex["currency"].lower() != currency.lower():
            continue
        results.append(ex)
    return results
