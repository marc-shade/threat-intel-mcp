"""
Shared configuration for Threat Intelligence MCP.

Centralizes all configuration, constants, and type definitions
to eliminate duplication across server.py, data_fetcher.py, and dashboard.py.
"""

import os
import re
import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import Any, Optional, TypedDict


# =============================================================================
# Logging Setup
# =============================================================================

def setup_logging(name: str, level: int = logging.INFO, to_stderr: bool = True) -> logging.Logger:
    """
    Set up logging for a module.

    Args:
        name: Logger name
        level: Logging level
        to_stderr: Log to stderr (required for MCP servers)

    Returns:
        Configured logger
    """
    import sys

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr if to_stderr else sys.stdout)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        ))
        logger.addHandler(handler)

    return logger


# =============================================================================
# Path Configuration
# =============================================================================

def get_agentic_path() -> Path:
    """Get the agentic system base path from environment or default."""
    return Path(os.environ.get("AGENTIC_SYSTEM_PATH", "${AGENTIC_SYSTEM_PATH:-/opt/agentic}"))


def get_data_dir() -> Path:
    """Get threat-intel data directory."""
    return get_agentic_path() / "mcp-servers/threat-intel-mcp/data"


def get_cache_dir() -> Path:
    """Get cache directory for threat feeds."""
    return get_data_dir() / "cache"


def ensure_dirs() -> None:
    """Ensure all required directories exist."""
    get_data_dir().mkdir(parents=True, exist_ok=True)
    get_cache_dir().mkdir(parents=True, exist_ok=True)


# =============================================================================
# API Key Configuration
# =============================================================================

@dataclass
class APIKeys:
    """Container for API keys loaded from environment."""
    virustotal: str = field(default_factory=lambda: os.environ.get("VIRUSTOTAL_API_KEY", ""))
    abuseipdb: str = field(default_factory=lambda: os.environ.get("ABUSEIPDB_API_KEY", ""))
    otx: str = field(default_factory=lambda: os.environ.get("OTX_API_KEY", ""))
    shodan: str = field(default_factory=lambda: os.environ.get("SHODAN_API_KEY", ""))

    @property
    def has_virustotal(self) -> bool:
        return bool(self.virustotal)

    @property
    def has_abuseipdb(self) -> bool:
        return bool(self.abuseipdb)

    @property
    def has_otx(self) -> bool:
        return bool(self.otx)

    @property
    def has_shodan(self) -> bool:
        return bool(self.shodan)

    def to_dict(self) -> dict[str, bool]:
        return {
            "virustotal": self.has_virustotal,
            "abuseipdb": self.has_abuseipdb,
            "otx": self.has_otx,
            "shodan": self.has_shodan
        }


# Global API keys instance
API_KEYS = APIKeys()


# =============================================================================
# Threat Feed Configuration
# =============================================================================

class FeedType(str, Enum):
    """Types of threat feeds."""
    IP_LIST = "ip_list"
    URL_LIST = "url_list"
    JSON = "json"
    RSS = "rss"
    TEXT = "text"


@dataclass
class ThreatFeed:
    """Configuration for a single threat feed."""
    name: str
    url: str
    feed_type: FeedType
    description: str
    enabled: bool = True
    requires_api_key: bool = False
    api_key_name: Optional[str] = None
    refresh_interval: int = 3600  # seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "type": self.feed_type.value,
            "description": self.description,
            "enabled": self.enabled,
            "requires_api_key": self.requires_api_key
        }


# All available threat feeds
THREAT_FEEDS: dict[str, ThreatFeed] = {
    "feodo_tracker": ThreatFeed(
        name="feodo_tracker",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        feed_type=FeedType.IP_LIST,
        description="Feodo Tracker Botnet C&C IPs"
    ),
    "urlhaus_recent": ThreatFeed(
        name="urlhaus_recent",
        url="https://urlhaus.abuse.ch/downloads/text_recent/",
        feed_type=FeedType.URL_LIST,
        description="URLhaus Recent Malware URLs"
    ),
    "sslbl_botnet": ThreatFeed(
        name="sslbl_botnet",
        url="https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        feed_type=FeedType.IP_LIST,
        description="SSL Blacklist Botnet C&C IPs"
    ),
    "emerging_threats_compromised": ThreatFeed(
        name="emerging_threats_compromised",
        url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        feed_type=FeedType.IP_LIST,
        description="Emerging Threats Compromised IPs"
    ),
    "cisa_kev": ThreatFeed(
        name="cisa_kev",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        feed_type=FeedType.JSON,
        description="CISA Known Exploited Vulnerabilities"
    ),
    "tor_exit_nodes": ThreatFeed(
        name="tor_exit_nodes",
        url="https://check.torproject.org/torbulkexitlist",
        feed_type=FeedType.IP_LIST,
        description="Tor Exit Node IPs"
    ),
    "threatfox_iocs": ThreatFeed(
        name="threatfox_iocs",
        url="https://threatfox.abuse.ch/export/json/recent/",
        feed_type=FeedType.JSON,
        description="ThreatFox Recent IOCs"
    ),
    "blocklist_de_all": ThreatFeed(
        name="blocklist_de_all",
        url="https://lists.blocklist.de/lists/all.txt",
        feed_type=FeedType.IP_LIST,
        description="Blocklist.de All Attacks"
    ),
    "cinsscore_badguys": ThreatFeed(
        name="cinsscore_badguys",
        url="https://cinsscore.com/list/ci-badguys.txt",
        feed_type=FeedType.IP_LIST,
        description="CI Army Bad Guys List"
    ),
    "spamhaus_drop": ThreatFeed(
        name="spamhaus_drop",
        url="https://www.spamhaus.org/drop/drop.txt",
        feed_type=FeedType.TEXT,  # CIDR notation
        description="Spamhaus Don't Route Or Peer"
    )
}


def get_feed(name: str) -> Optional[ThreatFeed]:
    """Get a threat feed by name."""
    return THREAT_FEEDS.get(name)


def get_enabled_feeds() -> dict[str, ThreatFeed]:
    """Get all enabled threat feeds."""
    return {k: v for k, v in THREAT_FEEDS.items() if v.enabled}


def get_ip_feeds() -> list[str]:
    """Get names of all IP-based threat feeds."""
    return [k for k, v in THREAT_FEEDS.items() if v.feed_type == FeedType.IP_LIST]


# =============================================================================
# Constants
# =============================================================================

# Cache settings
DEFAULT_CACHE_TTL = 3600  # 1 hour
MAX_CACHE_SIZE = 100  # Maximum cached items
MAX_RESPONSE_ITEMS = 500  # Maximum items in API response

# Request settings
DEFAULT_REQUEST_TIMEOUT = 30  # seconds
MAX_RETRIES = 3

# Validation patterns
IP_REGEX = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
MD5_REGEX = re.compile(r'^[a-fA-F0-9]{32}$')
SHA1_REGEX = re.compile(r'^[a-fA-F0-9]{40}$')
SHA256_REGEX = re.compile(r'^[a-fA-F0-9]{64}$')
DOMAIN_REGEX = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

# Severity levels
class Severity(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# IOC types
class IOCType(str, Enum):
    """Types of Indicators of Compromise."""
    IP = "ip"
    IP_PORT = "ip:port"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"


# =============================================================================
# Input Validation
# =============================================================================

def validate_ip(ip: str) -> tuple[bool, Optional[str]]:
    """
    Validate an IP address.

    Args:
        ip: IP address string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        ipaddress.ip_address(ip)
        return True, None
    except ValueError:
        return False, f"Invalid IP address format: {ip}"


def validate_hash(file_hash: str) -> tuple[bool, Optional[str], Optional[str]]:
    """
    Validate a file hash and detect its type.

    Args:
        file_hash: Hash string to validate

    Returns:
        Tuple of (is_valid, hash_type, error_message)
    """
    file_hash = file_hash.strip().lower()

    if MD5_REGEX.match(file_hash):
        return True, "md5", None
    elif SHA1_REGEX.match(file_hash):
        return True, "sha1", None
    elif SHA256_REGEX.match(file_hash):
        return True, "sha256", None
    else:
        return False, None, f"Invalid hash format. Expected MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars). Got {len(file_hash)} chars."


def validate_domain(domain: str) -> tuple[bool, Optional[str]]:
    """
    Validate a domain name.

    Args:
        domain: Domain string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if DOMAIN_REGEX.match(domain):
        return True, None
    return False, f"Invalid domain format: {domain}"


def validate_ioc_type(ioc_type: str) -> tuple[bool, Optional[str]]:
    """
    Validate an IOC type.

    Args:
        ioc_type: IOC type string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    valid_types = [t.value for t in IOCType]
    if ioc_type in valid_types:
        return True, None
    return False, f"Invalid IOC type: {ioc_type}. Valid types: {', '.join(valid_types)}"


# =============================================================================
# Thread-Safe Cache
# =============================================================================

class ThreatCache:
    """Thread-safe cache for threat data with TTL and size limits."""

    def __init__(self, max_size: int = MAX_CACHE_SIZE, default_ttl: int = DEFAULT_CACHE_TTL):
        self._cache: dict[str, Any] = {}
        self._expiry: dict[str, datetime] = {}
        self._lock = Lock()
        self._max_size = max_size
        self._default_ttl = default_ttl

    def get(self, key: str) -> Optional[Any]:
        """Get a value from cache if not expired."""
        with self._lock:
            if key not in self._cache:
                return None

            if key in self._expiry and datetime.now() > self._expiry[key]:
                # Expired, remove it
                del self._cache[key]
                del self._expiry[key]
                return None

            return self._cache[key]

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set a value in cache with TTL."""
        with self._lock:
            # Evict oldest if at capacity
            if len(self._cache) >= self._max_size and key not in self._cache:
                self._evict_oldest()

            self._cache[key] = value
            self._expiry[key] = datetime.now() + timedelta(seconds=ttl or self._default_ttl)

    def delete(self, key: str) -> bool:
        """Delete a key from cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                if key in self._expiry:
                    del self._expiry[key]
                return True
            return False

    def clear(self) -> None:
        """Clear all cached data."""
        with self._lock:
            self._cache.clear()
            self._expiry.clear()

    def _evict_oldest(self) -> None:
        """Evict the oldest entry (by expiry time)."""
        if not self._expiry:
            return

        oldest_key = min(self._expiry, key=self._expiry.get)
        del self._cache[oldest_key]
        del self._expiry[oldest_key]

    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            return {
                "size": len(self._cache),
                "max_size": self._max_size,
                "keys": list(self._cache.keys())
            }


# Global cache instance
threat_cache = ThreatCache()


# =============================================================================
# Type Definitions
# =============================================================================

class ThreatMatch(TypedDict, total=False):
    """A matched threat from a feed."""
    source: str
    description: str
    severity: str
    confidence: int
    detections: int


class IPReputationResult(TypedDict, total=False):
    """Result of an IP reputation check."""
    ip: str
    checked_at: str
    is_malicious: bool
    threat_level: str
    threats_found: list[ThreatMatch]
    sources_checked: list[str]
    abuseipdb: dict
    virustotal: dict


class HashReputationResult(TypedDict, total=False):
    """Result of a hash reputation check."""
    hash: str
    hash_type: str
    checked_at: str
    is_malicious: bool
    threats_found: list[ThreatMatch]
    virustotal: dict


class FeedResult(TypedDict, total=False):
    """Result of fetching a threat feed."""
    success: bool
    feed: str
    description: str
    type: str
    count: int
    cached: bool
    fetched_at: str
    ips: list[str]
    urls: list[str]
    data: dict
    error: str


# =============================================================================
# Helper Functions
# =============================================================================

def get_timestamp() -> str:
    """Get current ISO timestamp."""
    return datetime.now().isoformat()


def parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse an ISO timestamp string."""
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def calculate_severity(score: float, thresholds: tuple[float, float, float] = (25, 50, 75)) -> Severity:
    """
    Calculate severity from a numeric score.

    Args:
        score: Numeric score (0-100)
        thresholds: (low, medium, high) thresholds

    Returns:
        Severity level
    """
    low, medium, high = thresholds
    if score >= high:
        return Severity.CRITICAL
    elif score >= medium:
        return Severity.HIGH
    elif score >= low:
        return Severity.MEDIUM
    else:
        return Severity.LOW
