#!/usr/bin/env python3
"""
Threat Intelligence MCP Server v0.2.0

Aggregates threat feeds from multiple sources:
- Feodo Tracker, URLhaus, SSL Blacklist
- Emerging Threats, CISA KEV, Tor Exit Nodes
- ThreatFox, Blocklist.de, CI Army, Spamhaus
- VirusTotal, AbuseIPDB, Shodan (with API keys)

Provides tools for:
- Checking IPs/domains/hashes against threat feeds
- Getting latest threats and IOCs
- Bulk reputation checks
- Network scan integration
- MITRE ATT&CK mapping
"""

import asyncio
import json
import sys
from datetime import datetime, timedelta
from typing import Any, Optional

import aiohttp
from fastmcp import FastMCP

from .config import (
    # Configuration
    API_KEYS,
    THREAT_FEEDS,
    FeedType,
    Severity,
    IOCType,
    # Functions
    setup_logging,
    ensure_dirs,
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
    # Constants
    DEFAULT_REQUEST_TIMEOUT,
    MAX_RESPONSE_ITEMS,
    DEFAULT_CACHE_TTL,
)

# Configure logging
logger = setup_logging("threat-intel-mcp")

# Initialize FastMCP
mcp = FastMCP("threat-intel")


# =============================================================================
# HTTP Helpers
# =============================================================================

async def fetch_url(url: str, headers: Optional[dict] = None, timeout: int = DEFAULT_REQUEST_TIMEOUT) -> str:
    """
    Fetch URL content with proper error handling.

    Args:
        url: URL to fetch
        headers: Optional request headers
        timeout: Request timeout in seconds

    Returns:
        Response text content
    """
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=timeout) as response:
            response.raise_for_status()
            return await response.text()


async def fetch_json(url: str, headers: Optional[dict] = None, timeout: int = DEFAULT_REQUEST_TIMEOUT) -> dict:
    """
    Fetch JSON from URL with proper error handling.

    Args:
        url: URL to fetch
        headers: Optional request headers
        timeout: Request timeout in seconds

    Returns:
        Parsed JSON as dict
    """
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=timeout) as response:
            response.raise_for_status()
            return await response.json()


# =============================================================================
# Parsing Helpers
# =============================================================================

def parse_ip_list(content: str) -> list[str]:
    """
    Parse IP list from text content with proper validation.

    Args:
        content: Raw text content with IPs

    Returns:
        List of valid IP addresses
    """
    import ipaddress

    ips = []
    for line in content.split('\n'):
        line = line.strip()
        if line and not line.startswith('#'):
            # Extract potential IP from line
            parts = line.split()
            if parts:
                potential_ip = parts[0]
                try:
                    # Validate IP using ipaddress module
                    ipaddress.ip_address(potential_ip)
                    ips.append(potential_ip)
                except ValueError:
                    continue
    return ips


def parse_url_list(content: str) -> list[str]:
    """
    Parse URL list from text content.

    Args:
        content: Raw text content with URLs

    Returns:
        List of URLs
    """
    urls = []
    for line in content.split('\n'):
        line = line.strip()
        if line and not line.startswith('#'):
            if line.startswith('http://') or line.startswith('https://'):
                urls.append(line)
    return urls


def parse_cidr_list(content: str) -> list[str]:
    """
    Parse CIDR notation IP ranges.

    Args:
        content: Raw text with CIDR ranges

    Returns:
        List of CIDR strings
    """
    import ipaddress

    cidrs = []
    for line in content.split('\n'):
        line = line.strip()
        if line and not line.startswith(';') and not line.startswith('#'):
            parts = line.split()
            if parts:
                try:
                    ipaddress.ip_network(parts[0], strict=False)
                    cidrs.append(parts[0])
                except ValueError:
                    continue
    return cidrs


# =============================================================================
# MCP Tools
# =============================================================================

@mcp.tool()
async def get_threat_feeds() -> str:
    """
    Get list of all available threat intelligence feeds.

    Returns:
        JSON with available feeds and their descriptions
    """
    feeds = [feed.to_dict() for feed in get_enabled_feeds().values()]

    return json.dumps({
        "success": True,
        "feeds": feeds,
        "total_feeds": len(feeds),
        "api_configured": API_KEYS.to_dict()
    }, indent=2)


@mcp.tool()
async def fetch_threat_feed(feed_name: str) -> str:
    """
    Fetch and parse a specific threat intelligence feed.

    Args:
        feed_name: Name of the feed (feodo_tracker, urlhaus_recent, etc.)

    Returns:
        JSON with IOCs from the feed
    """
    ensure_dirs()

    feed = get_feed(feed_name)
    if not feed:
        available = list(THREAT_FEEDS.keys())
        return json.dumps({
            "success": False,
            "error": f"Unknown feed: {feed_name}",
            "available_feeds": available
        }, indent=2)

    # Check cache
    cache_key = f"feed_{feed_name}"
    cached = threat_cache.get(cache_key)
    if cached:
        return json.dumps({
            "success": True,
            "feed": feed_name,
            "description": feed.description,
            "cached": True,
            **cached
        }, indent=2)

    try:
        result: dict[str, Any] = {}

        if feed.feed_type == FeedType.JSON:
            data = await fetch_json(feed.url)
            result = {
                "type": "json",
                "data": data if isinstance(data, dict) else {"items": data},
                "count": len(data) if isinstance(data, (list, dict)) else 1
            }
        elif feed.feed_type == FeedType.IP_LIST:
            content = await fetch_url(feed.url)
            ips = parse_ip_list(content)
            result = {
                "type": "ip_list",
                "ips": ips[:MAX_RESPONSE_ITEMS],
                "count": len(ips),
                "truncated": len(ips) > MAX_RESPONSE_ITEMS
            }
        elif feed.feed_type == FeedType.URL_LIST:
            content = await fetch_url(feed.url)
            urls = parse_url_list(content)
            result = {
                "type": "url_list",
                "urls": urls[:MAX_RESPONSE_ITEMS],
                "count": len(urls),
                "truncated": len(urls) > MAX_RESPONSE_ITEMS
            }
        elif feed.feed_type == FeedType.TEXT:
            content = await fetch_url(feed.url)
            cidrs = parse_cidr_list(content)
            result = {
                "type": "cidr_list",
                "cidrs": cidrs[:MAX_RESPONSE_ITEMS],
                "count": len(cidrs),
                "truncated": len(cidrs) > MAX_RESPONSE_ITEMS
            }
        else:
            content = await fetch_url(feed.url)
            result = {
                "type": "text",
                "content": content[:10000],
                "count": len(content)
            }

        # Cache result
        result["fetched_at"] = get_timestamp()
        threat_cache.set(cache_key, result)

        return json.dumps({
            "success": True,
            "feed": feed_name,
            "description": feed.description,
            "cached": False,
            **result
        }, indent=2)

    except aiohttp.ClientError as e:
        logger.error(f"Network error fetching {feed_name}: {e}")
        return json.dumps({
            "success": False,
            "feed": feed_name,
            "error": f"Network error: {str(e)}"
        }, indent=2)
    except Exception as e:
        logger.error(f"Error fetching {feed_name}: {e}")
        return json.dumps({
            "success": False,
            "feed": feed_name,
            "error": str(e)
        }, indent=2)


@mcp.tool()
async def check_ip_reputation(ip: str) -> str:
    """
    Check an IP address against multiple threat intelligence sources.

    Args:
        ip: IP address to check

    Returns:
        JSON with reputation data from multiple sources
    """
    # Validate IP
    is_valid, error = validate_ip(ip)
    if not is_valid:
        return json.dumps({
            "success": False,
            "error": error
        }, indent=2)

    ensure_dirs()
    results: dict[str, Any] = {
        "ip": ip,
        "checked_at": get_timestamp(),
        "threats_found": [],
        "sources_checked": []
    }

    # Check against cached IP feeds
    ip_feed_names = get_ip_feeds()

    for feed_name in ip_feed_names:
        cache_key = f"feed_{feed_name}"
        cached = threat_cache.get(cache_key)
        if cached:
            feed_ips = cached.get("ips", [])
            if ip in feed_ips:
                feed = get_feed(feed_name)
                results["threats_found"].append({
                    "source": feed_name,
                    "description": feed.description if feed else feed_name,
                    "severity": Severity.HIGH.value
                })
            results["sources_checked"].append(feed_name)

    # Check AbuseIPDB if API key configured
    if API_KEYS.has_abuseipdb:
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Key": API_KEYS.abuseipdb,
                    "Accept": "application/json"
                }
                params = {"ipAddress": ip, "maxAgeInDays": 90}
                async with session.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers=headers,
                    params=params,
                    timeout=DEFAULT_REQUEST_TIMEOUT
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        results["abuseipdb"] = data.get("data", {})
                        results["sources_checked"].append("abuseipdb")
                        confidence = data.get("data", {}).get("abuseConfidenceScore", 0)
                        if confidence > 50:
                            results["threats_found"].append({
                                "source": "abuseipdb",
                                "confidence": confidence,
                                "severity": Severity.HIGH.value if confidence > 75 else Severity.MEDIUM.value
                            })
        except Exception as e:
            logger.warning(f"AbuseIPDB error: {e}")
            results["abuseipdb_error"] = str(e)

    # Check VirusTotal if API key configured
    if API_KEYS.has_virustotal:
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"x-apikey": API_KEYS.virustotal}
                async with session.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers=headers,
                    timeout=DEFAULT_REQUEST_TIMEOUT
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        results["virustotal"] = stats
                        results["sources_checked"].append("virustotal")
                        malicious = stats.get("malicious", 0)
                        if malicious > 0:
                            results["threats_found"].append({
                                "source": "virustotal",
                                "detections": malicious,
                                "severity": Severity.HIGH.value if malicious > 5 else Severity.MEDIUM.value
                            })
        except Exception as e:
            logger.warning(f"VirusTotal error: {e}")
            results["virustotal_error"] = str(e)

    # Check Shodan if API key configured
    if API_KEYS.has_shodan:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://api.shodan.io/shodan/host/{ip}?key={API_KEYS.shodan}",
                    timeout=DEFAULT_REQUEST_TIMEOUT
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        results["shodan"] = {
                            "ports": data.get("ports", []),
                            "hostnames": data.get("hostnames", []),
                            "country": data.get("country_name"),
                            "org": data.get("org"),
                            "vulns": data.get("vulns", [])
                        }
                        results["sources_checked"].append("shodan")
                        if data.get("vulns"):
                            results["threats_found"].append({
                                "source": "shodan",
                                "vulns": len(data["vulns"]),
                                "severity": Severity.HIGH.value
                            })
        except Exception as e:
            logger.warning(f"Shodan error: {e}")
            results["shodan_error"] = str(e)

    # Calculate overall threat level
    results["is_malicious"] = len(results["threats_found"]) > 0
    results["threat_level"] = (
        Severity.HIGH.value if any(t.get("severity") == Severity.HIGH.value for t in results["threats_found"])
        else Severity.MEDIUM.value if results["threats_found"]
        else Severity.LOW.value
    )

    return json.dumps({"success": True, **results}, indent=2)


@mcp.tool()
async def check_hash_reputation(file_hash: str) -> str:
    """
    Check a file hash (MD5/SHA1/SHA256) against threat intelligence.

    Args:
        file_hash: File hash to check

    Returns:
        JSON with reputation data
    """
    # Validate hash
    is_valid, hash_type, error = validate_hash(file_hash)
    if not is_valid:
        return json.dumps({
            "success": False,
            "error": error
        }, indent=2)

    results: dict[str, Any] = {
        "hash": file_hash.lower(),
        "hash_type": hash_type,
        "checked_at": get_timestamp(),
        "threats_found": []
    }

    # Check VirusTotal if API key configured
    if API_KEYS.has_virustotal:
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"x-apikey": API_KEYS.virustotal}
                async with session.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers=headers,
                    timeout=DEFAULT_REQUEST_TIMEOUT
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        attrs = data.get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        results["virustotal"] = {
                            "stats": stats,
                            "names": attrs.get("names", [])[:10],
                            "type_description": attrs.get("type_description"),
                            "reputation": attrs.get("reputation", 0),
                            "tags": attrs.get("tags", [])[:20]
                        }
                        malicious = stats.get("malicious", 0)
                        if malicious > 0:
                            results["threats_found"].append({
                                "source": "virustotal",
                                "detections": malicious,
                                "total_scanners": sum(stats.values()),
                                "severity": Severity.CRITICAL.value if malicious > 10 else Severity.HIGH.value
                            })
                    elif response.status == 404:
                        results["virustotal"] = {"status": "not_found"}
        except Exception as e:
            logger.warning(f"VirusTotal error: {e}")
            results["virustotal_error"] = str(e)
    else:
        results["note"] = "Configure VIRUSTOTAL_API_KEY for hash lookups"

    results["is_malicious"] = len(results["threats_found"]) > 0

    return json.dumps({"success": True, **results}, indent=2)


@mcp.tool()
async def check_bulk_ips(ips: str) -> str:
    """
    Check multiple IP addresses against threat feeds in bulk.

    Args:
        ips: JSON array of IP addresses or comma-separated list

    Returns:
        JSON with reputation results for all IPs
    """
    # Parse input
    try:
        if ips.startswith('['):
            ip_list = json.loads(ips)
        else:
            ip_list = [ip.strip() for ip in ips.split(',') if ip.strip()]
    except json.JSONDecodeError:
        ip_list = [ip.strip() for ip in ips.split(',') if ip.strip()]

    if not ip_list:
        return json.dumps({
            "success": False,
            "error": "No valid IPs provided"
        }, indent=2)

    if len(ip_list) > 100:
        return json.dumps({
            "success": False,
            "error": "Maximum 100 IPs per request"
        }, indent=2)

    # First, ensure we have threat data loaded
    ip_feed_names = get_ip_feeds()
    threat_ips: set[str] = set()

    for feed_name in ip_feed_names:
        cache_key = f"feed_{feed_name}"
        cached = threat_cache.get(cache_key)
        if cached:
            threat_ips.update(cached.get("ips", []))
        else:
            # Fetch if not cached
            try:
                result = await fetch_threat_feed(feed_name)
                data = json.loads(result)
                if data.get("success") and data.get("ips"):
                    threat_ips.update(data["ips"])
            except Exception as e:
                logger.warning(f"Error loading {feed_name}: {e}")

    # Check each IP
    results: list[dict] = []
    malicious_count = 0

    for ip in ip_list:
        is_valid, error = validate_ip(ip)
        if not is_valid:
            results.append({
                "ip": ip,
                "valid": False,
                "error": error
            })
            continue

        is_threat = ip in threat_ips
        if is_threat:
            malicious_count += 1

        results.append({
            "ip": ip,
            "valid": True,
            "is_malicious": is_threat,
            "threat_level": Severity.HIGH.value if is_threat else Severity.LOW.value
        })

    return json.dumps({
        "success": True,
        "checked_at": get_timestamp(),
        "total_checked": len(ip_list),
        "malicious_count": malicious_count,
        "clean_count": len(ip_list) - malicious_count,
        "feeds_loaded": len(ip_feed_names),
        "threat_ips_available": len(threat_ips),
        "results": results
    }, indent=2)


@mcp.tool()
async def get_cisa_kev(
    days: int = 30,
    vendor: Optional[str] = None
) -> str:
    """
    Get CISA Known Exploited Vulnerabilities.

    Args:
        days: Get vulnerabilities added in last N days (default: 30)
        vendor: Filter by vendor name (optional)

    Returns:
        JSON with recent KEVs
    """
    try:
        feed = get_feed("cisa_kev")
        if not feed:
            return json.dumps({"success": False, "error": "CISA KEV feed not configured"}, indent=2)

        data = await fetch_json(feed.url)

        vulnerabilities = data.get("vulnerabilities", [])
        cutoff = datetime.now() - timedelta(days=days)

        recent = []
        for vuln in vulnerabilities:
            try:
                date_added = datetime.strptime(vuln.get("dateAdded", "2000-01-01"), "%Y-%m-%d")
                if date_added >= cutoff:
                    if vendor is None or vendor.lower() in vuln.get("vendorProject", "").lower():
                        recent.append({
                            "cve_id": vuln.get("cveID"),
                            "vendor": vuln.get("vendorProject"),
                            "product": vuln.get("product"),
                            "name": vuln.get("vulnerabilityName"),
                            "description": vuln.get("shortDescription"),
                            "date_added": vuln.get("dateAdded"),
                            "due_date": vuln.get("dueDate"),
                            "known_ransomware": vuln.get("knownRansomwareCampaignUse"),
                            "notes": vuln.get("notes")
                        })
            except ValueError:
                continue

        return json.dumps({
            "success": True,
            "total_kev": len(vulnerabilities),
            "recent_count": len(recent),
            "days_checked": days,
            "vendor_filter": vendor,
            "vulnerabilities": recent[:50]
        }, indent=2)

    except Exception as e:
        logger.error(f"Error fetching CISA KEV: {e}")
        return json.dumps({"success": False, "error": str(e)}, indent=2)


@mcp.tool()
async def get_dashboard_summary() -> str:
    """
    Get a summary of all threat intelligence for dashboard display.

    Returns:
        JSON with aggregated threat data for visualization
    """
    ensure_dirs()

    summary: dict[str, Any] = {
        "generated_at": get_timestamp(),
        "feeds": {},
        "totals": {
            "malicious_ips": 0,
            "malicious_urls": 0,
            "cidr_blocks": 0,
            "recent_cves": 0
        },
        "alerts": []
    }

    # Fetch all feeds in parallel
    feed_names = list(get_enabled_feeds().keys())
    tasks = [fetch_threat_feed(name) for name in feed_names]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for feed_name, result in zip(feed_names, results):
        if isinstance(result, Exception):
            summary["feeds"][feed_name] = {"error": str(result)}
        else:
            try:
                data = json.loads(result)
                summary["feeds"][feed_name] = {
                    "count": data.get("count", 0),
                    "type": data.get("type"),
                    "fetched_at": data.get("fetched_at"),
                    "success": data.get("success", False)
                }
                if data.get("type") == "ip_list":
                    summary["totals"]["malicious_ips"] += data.get("count", 0)
                elif data.get("type") == "url_list":
                    summary["totals"]["malicious_urls"] += data.get("count", 0)
                elif data.get("type") == "cidr_list":
                    summary["totals"]["cidr_blocks"] += data.get("count", 0)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse {feed_name} result: {e}")
                summary["feeds"][feed_name] = {"error": "parse_failed"}

    # Get CISA KEV count
    try:
        kev_result = await get_cisa_kev(days=7)
        kev_data = json.loads(kev_result)
        summary["totals"]["recent_cves"] = kev_data.get("recent_count", 0)
        if kev_data.get("recent_count", 0) > 0:
            summary["alerts"].append({
                "type": "new_kev",
                "message": f"{kev_data['recent_count']} new CISA KEV in last 7 days",
                "severity": Severity.HIGH.value
            })
    except Exception as e:
        logger.warning(f"Error getting KEV summary: {e}")

    # Add cache stats
    summary["cache_stats"] = threat_cache.stats()

    return json.dumps({"success": True, **summary}, indent=2)


@mcp.tool()
async def get_recent_iocs(
    ioc_type: Optional[str] = None,
    limit: int = 100
) -> str:
    """
    Get recent IOCs (Indicators of Compromise) from ThreatFox.

    Args:
        ioc_type: Filter by type (ip:port, domain, url, md5, sha256)
        limit: Maximum IOCs to return (default: 100, max: 500)

    Returns:
        JSON with recent IOCs
    """
    # Validate IOC type if provided
    if ioc_type:
        is_valid, error = validate_ioc_type(ioc_type)
        if not is_valid:
            return json.dumps({
                "success": False,
                "error": error
            }, indent=2)

    # Clamp limit
    limit = min(max(1, limit), MAX_RESPONSE_ITEMS)

    try:
        feed = get_feed("threatfox_iocs")
        if not feed:
            return json.dumps({"success": False, "error": "ThreatFox feed not configured"}, indent=2)

        data = await fetch_json(feed.url)

        iocs = []
        for item in data.get("data", []):
            ioc = {
                "ioc": item.get("ioc"),
                "ioc_type": item.get("ioc_type"),
                "threat_type": item.get("threat_type"),
                "malware": item.get("malware"),
                "malware_printable": item.get("malware_printable"),
                "confidence": item.get("confidence_level"),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "tags": item.get("tags", []),
                "reference": item.get("reference")
            }
            if ioc_type is None or ioc.get("ioc_type") == ioc_type:
                iocs.append(ioc)
                if len(iocs) >= limit:
                    break

        return json.dumps({
            "success": True,
            "count": len(iocs),
            "filter_type": ioc_type,
            "iocs": iocs
        }, indent=2)

    except Exception as e:
        logger.error(f"Error fetching IOCs: {e}")
        return json.dumps({"success": False, "error": str(e)}, indent=2)


@mcp.tool()
async def check_network_against_threats(scan_results: str) -> str:
    """
    Check network scan results against threat intelligence.

    Args:
        scan_results: JSON string from network scanner with device IPs

    Returns:
        JSON with any matched threats
    """
    try:
        scan_data = json.loads(scan_results)
    except json.JSONDecodeError as e:
        return json.dumps({
            "success": False,
            "error": f"Invalid JSON: {str(e)}"
        }, indent=2)

    # Extract devices from various formats
    devices = scan_data.get("devices", scan_data.get("new_devices", []))

    if not devices:
        return json.dumps({
            "success": False,
            "error": "No devices found in scan results"
        }, indent=2)

    # Load threat IPs from all feeds
    ip_feed_names = get_ip_feeds()
    threat_ips: set[str] = set()

    for feed_name in ip_feed_names:
        try:
            result = await fetch_threat_feed(feed_name)
            data = json.loads(result)
            if data.get("ips"):
                threat_ips.update(data["ips"])
        except Exception as e:
            logger.warning(f"Error loading {feed_name}: {e}")

    # Check each device
    matches = []
    for device in devices:
        ip = device.get("ip")
        if ip and ip in threat_ips:
            matches.append({
                "device": device,
                "threat_match": True,
                "severity": Severity.CRITICAL.value,
                "recommendation": "Isolate device immediately and investigate"
            })

    return json.dumps({
        "success": True,
        "checked_at": get_timestamp(),
        "devices_checked": len(devices),
        "threat_ips_loaded": len(threat_ips),
        "matches_found": len(matches),
        "matches": matches,
        "all_clear": len(matches) == 0,
        "recommendation": "Network is clean" if len(matches) == 0 else f"ALERT: {len(matches)} devices matched threat intelligence!"
    }, indent=2)


@mcp.tool()
async def get_threat_stats() -> str:
    """
    Get statistics about loaded threat data and cache status.

    Returns:
        JSON with threat intelligence statistics
    """
    stats: dict[str, Any] = {
        "generated_at": get_timestamp(),
        "cache": threat_cache.stats(),
        "feeds_configured": len(THREAT_FEEDS),
        "feeds_enabled": len(get_enabled_feeds()),
        "api_keys": API_KEYS.to_dict(),
        "ip_feeds": get_ip_feeds()
    }

    # Count cached threat data
    total_ips = 0
    total_urls = 0

    for feed_name in get_ip_feeds():
        cached = threat_cache.get(f"feed_{feed_name}")
        if cached:
            total_ips += len(cached.get("ips", []))

    for feed_name in ["urlhaus_recent"]:
        cached = threat_cache.get(f"feed_{feed_name}")
        if cached:
            total_urls += len(cached.get("urls", []))

    stats["cached_data"] = {
        "total_threat_ips": total_ips,
        "total_threat_urls": total_urls
    }

    return json.dumps({"success": True, **stats}, indent=2)


@mcp.tool()
async def clear_threat_cache() -> str:
    """
    Clear the threat intelligence cache to force fresh data fetch.

    Returns:
        JSON confirmation
    """
    threat_cache.clear()
    return json.dumps({
        "success": True,
        "message": "Threat cache cleared",
        "timestamp": get_timestamp()
    }, indent=2)


# =============================================================================
# Entry Point
# =============================================================================

def main():
    """Entry point for MCP server."""
    ensure_dirs()
    logger.info("Starting Threat Intelligence MCP server v0.2.0")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
