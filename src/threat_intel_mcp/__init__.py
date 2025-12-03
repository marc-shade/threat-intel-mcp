"""
Threat Intelligence MCP Server

Aggregates threat feeds from multiple sources for comprehensive
security intelligence and reputation checking.
"""

__version__ = "0.2.0"

from .config import (
    # Configuration
    API_KEYS,
    THREAT_FEEDS,
    FeedType,
    Severity,
    IOCType,
    ThreatFeed,
    ThreatCache,
    # Functions
    setup_logging,
    ensure_dirs,
    get_data_dir,
    get_cache_dir,
    get_feed,
    get_enabled_feeds,
    get_ip_feeds,
    get_timestamp,
    # Validation
    validate_ip,
    validate_hash,
    validate_domain,
    validate_ioc_type,
    # Cache
    threat_cache,
)

__all__ = [
    "__version__",
    # Configuration
    "API_KEYS",
    "THREAT_FEEDS",
    "FeedType",
    "Severity",
    "IOCType",
    "ThreatFeed",
    "ThreatCache",
    # Functions
    "setup_logging",
    "ensure_dirs",
    "get_data_dir",
    "get_cache_dir",
    "get_feed",
    "get_enabled_feeds",
    "get_ip_feeds",
    "get_timestamp",
    # Validation
    "validate_ip",
    "validate_hash",
    "validate_domain",
    "validate_ioc_type",
    # Cache
    "threat_cache",
]
