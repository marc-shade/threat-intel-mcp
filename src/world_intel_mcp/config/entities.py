"""Entity reference data for NER extraction.

Pure data module — no I/O, no external dependencies.
Maps leaders, organizations, companies to normalized forms.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# World leaders (name variants → normalized key)
# ---------------------------------------------------------------------------
LEADERS: dict[str, dict] = {
    "biden": {"name": "Joe Biden", "title": "President", "country": "USA"},
    "joe biden": {"name": "Joe Biden", "title": "President", "country": "USA"},
    "trump": {"name": "Donald Trump", "title": "Former President", "country": "USA"},
    "donald trump": {"name": "Donald Trump", "title": "Former President", "country": "USA"},
    "xi jinping": {"name": "Xi Jinping", "title": "President", "country": "CHN"},
    "xi": {"name": "Xi Jinping", "title": "President", "country": "CHN"},
    "putin": {"name": "Vladimir Putin", "title": "President", "country": "RUS"},
    "vladimir putin": {"name": "Vladimir Putin", "title": "President", "country": "RUS"},
    "zelensky": {"name": "Volodymyr Zelensky", "title": "President", "country": "UKR"},
    "zelenskyy": {"name": "Volodymyr Zelensky", "title": "President", "country": "UKR"},
    "macron": {"name": "Emmanuel Macron", "title": "President", "country": "FRA"},
    "starmer": {"name": "Keir Starmer", "title": "Prime Minister", "country": "GBR"},
    "scholz": {"name": "Olaf Scholz", "title": "Chancellor", "country": "DEU"},
    "modi": {"name": "Narendra Modi", "title": "Prime Minister", "country": "IND"},
    "narendra modi": {"name": "Narendra Modi", "title": "Prime Minister", "country": "IND"},
    "netanyahu": {"name": "Benjamin Netanyahu", "title": "Prime Minister", "country": "ISR"},
    "khamenei": {"name": "Ali Khamenei", "title": "Supreme Leader", "country": "IRN"},
    "kim jong un": {"name": "Kim Jong Un", "title": "Supreme Leader", "country": "PRK"},
    "kim jong-un": {"name": "Kim Jong Un", "title": "Supreme Leader", "country": "PRK"},
    "erdogan": {"name": "Recep Tayyip Erdogan", "title": "President", "country": "TUR"},
    "kishida": {"name": "Fumio Kishida", "title": "Prime Minister", "country": "JPN"},
    "trudeau": {"name": "Justin Trudeau", "title": "Prime Minister", "country": "CAN"},
    "lula": {"name": "Luiz Inacio Lula da Silva", "title": "President", "country": "BRA"},
    "al-assad": {"name": "Bashar al-Assad", "title": "Former President", "country": "SYR"},
    "marcos": {"name": "Ferdinand Marcos Jr.", "title": "President", "country": "PHL"},
    "albanese": {"name": "Anthony Albanese", "title": "Prime Minister", "country": "AUS"},
    "milei": {"name": "Javier Milei", "title": "President", "country": "ARG"},
    "meloni": {"name": "Giorgia Meloni", "title": "Prime Minister", "country": "ITA"},
}

# ---------------------------------------------------------------------------
# International organizations
# ---------------------------------------------------------------------------
ORGANIZATIONS: dict[str, dict] = {
    "united nations": {"abbrev": "UN", "type": "intl_org"},
    "un": {"abbrev": "UN", "type": "intl_org"},
    "nato": {"abbrev": "NATO", "type": "military_alliance"},
    "european union": {"abbrev": "EU", "type": "political_bloc"},
    "eu": {"abbrev": "EU", "type": "political_bloc"},
    "who": {"abbrev": "WHO", "type": "intl_org"},
    "world health organization": {"abbrev": "WHO", "type": "intl_org"},
    "imf": {"abbrev": "IMF", "type": "financial"},
    "international monetary fund": {"abbrev": "IMF", "type": "financial"},
    "world bank": {"abbrev": "WB", "type": "financial"},
    "opec": {"abbrev": "OPEC", "type": "energy"},
    "iaea": {"abbrev": "IAEA", "type": "nuclear"},
    "international atomic energy agency": {"abbrev": "IAEA", "type": "nuclear"},
    "red cross": {"abbrev": "ICRC", "type": "humanitarian"},
    "icrc": {"abbrev": "ICRC", "type": "humanitarian"},
    "unhcr": {"abbrev": "UNHCR", "type": "humanitarian"},
    "unicef": {"abbrev": "UNICEF", "type": "humanitarian"},
    "asean": {"abbrev": "ASEAN", "type": "political_bloc"},
    "african union": {"abbrev": "AU", "type": "political_bloc"},
    "brics": {"abbrev": "BRICS", "type": "political_bloc"},
    "g7": {"abbrev": "G7", "type": "political_bloc"},
    "g20": {"abbrev": "G20", "type": "political_bloc"},
    "wto": {"abbrev": "WTO", "type": "trade"},
    "world trade organization": {"abbrev": "WTO", "type": "trade"},
    "hamas": {"abbrev": "Hamas", "type": "militant"},
    "hezbollah": {"abbrev": "Hezbollah", "type": "militant"},
    "houthis": {"abbrev": "Houthis", "type": "militant"},
    "isis": {"abbrev": "ISIS", "type": "militant"},
    "islamic state": {"abbrev": "ISIS", "type": "militant"},
    "al-qaeda": {"abbrev": "AQ", "type": "militant"},
    "al qaeda": {"abbrev": "AQ", "type": "militant"},
    "taliban": {"abbrev": "Taliban", "type": "militant"},
    "wagner": {"abbrev": "Wagner", "type": "pmc"},
    "wagner group": {"abbrev": "Wagner", "type": "pmc"},
    "cia": {"abbrev": "CIA", "type": "intelligence"},
    "fbi": {"abbrev": "FBI", "type": "intelligence"},
    "mossad": {"abbrev": "Mossad", "type": "intelligence"},
    "mi6": {"abbrev": "MI6", "type": "intelligence"},
    "fsb": {"abbrev": "FSB", "type": "intelligence"},
    "pentagon": {"abbrev": "DoD", "type": "military"},
    "department of defense": {"abbrev": "DoD", "type": "military"},
}

# ---------------------------------------------------------------------------
# Major companies (defense, tech, energy)
# ---------------------------------------------------------------------------
COMPANIES: dict[str, dict] = {
    "lockheed martin": {"ticker": "LMT", "sector": "defense"},
    "raytheon": {"ticker": "RTX", "sector": "defense"},
    "northrop grumman": {"ticker": "NOC", "sector": "defense"},
    "boeing": {"ticker": "BA", "sector": "defense"},
    "general dynamics": {"ticker": "GD", "sector": "defense"},
    "bae systems": {"ticker": "BA.L", "sector": "defense"},
    "rheinmetall": {"ticker": "RHM.DE", "sector": "defense"},
    "apple": {"ticker": "AAPL", "sector": "tech"},
    "google": {"ticker": "GOOGL", "sector": "tech"},
    "alphabet": {"ticker": "GOOGL", "sector": "tech"},
    "microsoft": {"ticker": "MSFT", "sector": "tech"},
    "amazon": {"ticker": "AMZN", "sector": "tech"},
    "meta": {"ticker": "META", "sector": "tech"},
    "nvidia": {"ticker": "NVDA", "sector": "tech"},
    "openai": {"ticker": None, "sector": "ai"},
    "anthropic": {"ticker": None, "sector": "ai"},
    "deepmind": {"ticker": None, "sector": "ai"},
    "aramco": {"ticker": "2222.SR", "sector": "energy"},
    "exxonmobil": {"ticker": "XOM", "sector": "energy"},
    "chevron": {"ticker": "CVX", "sector": "energy"},
    "shell": {"ticker": "SHEL", "sector": "energy"},
    "bp": {"ticker": "BP", "sector": "energy"},
    "gazprom": {"ticker": None, "sector": "energy"},
    "tsmc": {"ticker": "TSM", "sector": "semiconductor"},
    "samsung": {"ticker": "005930.KS", "sector": "tech"},
}

# ---------------------------------------------------------------------------
# APT / threat actor names
# ---------------------------------------------------------------------------
APT_GROUPS: set[str] = {
    "apt28", "apt29", "apt30", "apt31", "apt33", "apt34", "apt35", "apt38",
    "apt40", "apt41", "lazarus", "lazarus group", "fancy bear", "cozy bear",
    "sandworm", "turla", "equation group", "kimsuky", "charming kitten",
    "double dragon", "stone panda", "volt typhoon", "salt typhoon",
    "midnight blizzard", "star blizzard", "forest blizzard",
    "scattered spider", "lapsus$", "lockbit", "blackcat", "alphv",
    "cl0p", "conti", "revil", "darkside", "black basta",
}
