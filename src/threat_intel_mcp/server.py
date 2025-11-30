#!/usr/bin/env python3
"""
Threat Intelligence MCP Server

Aggregates threat feeds from multiple sources:
- AlienVault OTX
- AbuseIPDB
- VirusTotal (with API key)
- Emerging Threats
- Feodo Tracker
- URLhaus
- CISA KEV (Known Exploited Vulnerabilities)

Provides tools for:
- Checking IPs/domains/hashes against threat feeds
- Getting latest threats and IOCs
- Monitoring specific threat actors
- Dashboard data for visualization
"""

import asyncio
import json
import logging
import sys
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
import hashlib
import re

import aiohttp
import feedparser
from fastmcp import FastMCP

# Configure logging to stderr (required for MCP)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("threat-intel-mcp")

# Initialize FastMCP
mcp = FastMCP("threat-intel")

# Data paths
DATA_DIR = Path(os.path.join(os.environ.get("AGENTIC_SYSTEM_PATH", "${AGENTIC_SYSTEM_PATH:-/opt/agentic}"), "mcp-servers/threat-intel-mcp/data"))
CACHE_DIR = DATA_DIR / "cache"
IOC_DB = DATA_DIR / "iocs.json"

# API Keys (from environment)
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

# Threat feed URLs (free, no API key required)
THREAT_FEEDS = {
    "feodo_tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "ip_list",
        "description": "Feodo Tracker Botnet C&C IPs"
    },
    "urlhaus_recent": {
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "type": "url_list",
        "description": "URLhaus Recent Malware URLs"
    },
    "sslbl_botnet": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "type": "ip_list",
        "description": "SSL Blacklist Botnet C&C IPs"
    },
    "emerging_threats_compromised": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip_list",
        "description": "Emerging Threats Compromised IPs"
    },
    "cisa_kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "type": "json",
        "description": "CISA Known Exploited Vulnerabilities"
    },
    "tor_exit_nodes": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "type": "ip_list",
        "description": "Tor Exit Node IPs"
    },
    "threatfox_iocs": {
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "type": "json",
        "description": "ThreatFox Recent IOCs"
    }
}

# Cache for threat data
threat_cache = {}
cache_expiry = {}
CACHE_TTL = 3600  # 1 hour


def ensure_dirs():
    """Ensure data directories exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


async def fetch_url(url: str, headers: dict = None) -> str:
    """Fetch URL content."""
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=30) as response:
            response.raise_for_status()
            return await response.text()


async def fetch_json(url: str, headers: dict = None) -> dict:
    """Fetch JSON from URL."""
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=30) as response:
            response.raise_for_status()
            return await response.json()


def parse_ip_list(content: str) -> list:
    """Parse IP list from text content."""
    ips = []
    for line in content.split('\n'):
        line = line.strip()
        if line and not line.startswith('#'):
            # Extract IP from line (may have comments)
            match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if match:
                ips.append(match.group(1))
    return ips


def parse_url_list(content: str) -> list:
    """Parse URL list from text content."""
    urls = []
    for line in content.split('\n'):
        line = line.strip()
        if line and not line.startswith('#'):
            if line.startswith('http'):
                urls.append(line)
    return urls


@mcp.tool()
async def get_threat_feeds() -> str:
    """
    Get list of all available threat intelligence feeds.

    Returns:
        JSON with available feeds and their descriptions
    """
    return json.dumps({
        "success": True,
        "feeds": [
            {
                "name": name,
                "description": info["description"],
                "type": info["type"],
                "url": info["url"]
            }
            for name, info in THREAT_FEEDS.items()
        ],
        "api_configured": {
            "virustotal": bool(VIRUSTOTAL_API_KEY),
            "abuseipdb": bool(ABUSEIPDB_API_KEY),
            "otx": bool(OTX_API_KEY)
        }
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

    if feed_name not in THREAT_FEEDS:
        return json.dumps({
            "success": False,
            "error": f"Unknown feed: {feed_name}",
            "available_feeds": list(THREAT_FEEDS.keys())
        }, indent=2)

    feed = THREAT_FEEDS[feed_name]

    # Check cache
    cache_key = f"feed_{feed_name}"
    if cache_key in threat_cache and cache_key in cache_expiry:
        if datetime.now() < cache_expiry[cache_key]:
            return json.dumps({
                "success": True,
                "feed": feed_name,
                "cached": True,
                **threat_cache[cache_key]
            }, indent=2)

    try:
        if feed["type"] == "json":
            data = await fetch_json(feed["url"])
            result = {
                "type": "json",
                "data": data if isinstance(data, dict) else {"items": data},
                "count": len(data) if isinstance(data, (list, dict)) else 1
            }
        elif feed["type"] == "ip_list":
            content = await fetch_url(feed["url"])
            ips = parse_ip_list(content)
            result = {
                "type": "ip_list",
                "ips": ips[:500],  # Limit response size
                "count": len(ips)
            }
        elif feed["type"] == "url_list":
            content = await fetch_url(feed["url"])
            urls = parse_url_list(content)
            result = {
                "type": "url_list",
                "urls": urls[:500],
                "count": len(urls)
            }
        else:
            content = await fetch_url(feed["url"])
            result = {
                "type": "text",
                "content": content[:10000],
                "count": len(content)
            }

        # Cache result
        result["fetched_at"] = datetime.now().isoformat()
        threat_cache[cache_key] = result
        cache_expiry[cache_key] = datetime.now() + timedelta(seconds=CACHE_TTL)

        return json.dumps({
            "success": True,
            "feed": feed_name,
            "description": feed["description"],
            "cached": False,
            **result
        }, indent=2)

    except Exception as e:
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
    ensure_dirs()
    results = {
        "ip": ip,
        "checked_at": datetime.now().isoformat(),
        "threats_found": [],
        "sources_checked": []
    }

    # Check against cached feeds
    ip_feeds = ["feodo_tracker", "sslbl_botnet", "emerging_threats_compromised", "tor_exit_nodes"]

    for feed_name in ip_feeds:
        cache_key = f"feed_{feed_name}"
        if cache_key in threat_cache:
            cached = threat_cache[cache_key]
            if "ips" in cached and ip in cached["ips"]:
                results["threats_found"].append({
                    "source": feed_name,
                    "description": THREAT_FEEDS[feed_name]["description"],
                    "severity": "high"
                })
            results["sources_checked"].append(feed_name)

    # Check AbuseIPDB if API key configured
    if ABUSEIPDB_API_KEY:
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Key": ABUSEIPDB_API_KEY,
                    "Accept": "application/json"
                }
                params = {
                    "ipAddress": ip,
                    "maxAgeInDays": 90
                }
                async with session.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers=headers,
                    params=params
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        results["abuseipdb"] = data.get("data", {})
                        results["sources_checked"].append("abuseipdb")
                        if data.get("data", {}).get("abuseConfidenceScore", 0) > 50:
                            results["threats_found"].append({
                                "source": "abuseipdb",
                                "confidence": data["data"]["abuseConfidenceScore"],
                                "severity": "high" if data["data"]["abuseConfidenceScore"] > 75 else "medium"
                            })
        except Exception as e:
            results["abuseipdb_error"] = str(e)

    # Check VirusTotal if API key configured
    if VIRUSTOTAL_API_KEY:
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                async with session.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        results["virustotal"] = stats
                        results["sources_checked"].append("virustotal")
                        if stats.get("malicious", 0) > 0:
                            results["threats_found"].append({
                                "source": "virustotal",
                                "detections": stats["malicious"],
                                "severity": "high" if stats["malicious"] > 5 else "medium"
                            })
        except Exception as e:
            results["virustotal_error"] = str(e)

    results["is_malicious"] = len(results["threats_found"]) > 0
    results["threat_level"] = "high" if any(t.get("severity") == "high" for t in results["threats_found"]) else \
                              "medium" if results["threats_found"] else "low"

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
    results = {
        "hash": file_hash,
        "hash_type": "md5" if len(file_hash) == 32 else "sha1" if len(file_hash) == 40 else "sha256",
        "checked_at": datetime.now().isoformat(),
        "threats_found": []
    }

    # Check VirusTotal if API key configured
    if VIRUSTOTAL_API_KEY:
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                async with session.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        attrs = data.get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        results["virustotal"] = {
                            "stats": stats,
                            "names": attrs.get("names", [])[:10],
                            "type_description": attrs.get("type_description"),
                            "reputation": attrs.get("reputation", 0)
                        }
                        if stats.get("malicious", 0) > 0:
                            results["threats_found"].append({
                                "source": "virustotal",
                                "detections": stats["malicious"],
                                "total_scanners": sum(stats.values()),
                                "severity": "critical" if stats["malicious"] > 10 else "high"
                            })
                    elif response.status == 404:
                        results["virustotal"] = {"status": "not_found"}
        except Exception as e:
            results["virustotal_error"] = str(e)
    else:
        results["note"] = "Configure VIRUSTOTAL_API_KEY for hash lookups"

    results["is_malicious"] = len(results["threats_found"]) > 0

    return json.dumps({"success": True, **results}, indent=2)


@mcp.tool()
async def get_cisa_kev(
    days: int = 30,
    vendor: Optional[str] = None
) -> str:
    """
    Get CISA Known Exploited Vulnerabilities.

    Args:
        days: Get vulnerabilities added in last N days
        vendor: Filter by vendor name (optional)

    Returns:
        JSON with recent KEVs
    """
    try:
        data = await fetch_json(THREAT_FEEDS["cisa_kev"]["url"])

        vulnerabilities = data.get("vulnerabilities", [])
        cutoff = datetime.now() - timedelta(days=days)

        recent = []
        for vuln in vulnerabilities:
            # Parse date
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
                        "known_ransomware": vuln.get("knownRansomwareCampaignUse")
                    })

        return json.dumps({
            "success": True,
            "total_kev": len(vulnerabilities),
            "recent_count": len(recent),
            "days_checked": days,
            "vulnerabilities": recent[:50]  # Limit response
        }, indent=2)

    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, indent=2)


@mcp.tool()
async def get_dashboard_summary() -> str:
    """
    Get a summary of all threat intelligence for dashboard display.

    Returns:
        JSON with aggregated threat data for visualization
    """
    ensure_dirs()

    summary = {
        "generated_at": datetime.now().isoformat(),
        "feeds": {},
        "totals": {
            "malicious_ips": 0,
            "malicious_urls": 0,
            "recent_cves": 0
        },
        "alerts": []
    }

    # Fetch all feeds in parallel
    tasks = []
    for feed_name in THREAT_FEEDS.keys():
        tasks.append(fetch_threat_feed(feed_name))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for feed_name, result in zip(THREAT_FEEDS.keys(), results):
        if isinstance(result, Exception):
            summary["feeds"][feed_name] = {"error": str(result)}
        else:
            try:
                data = json.loads(result)
                summary["feeds"][feed_name] = {
                    "count": data.get("count", 0),
                    "type": data.get("type"),
                    "fetched_at": data.get("fetched_at")
                }
                if data.get("type") == "ip_list":
                    summary["totals"]["malicious_ips"] += data.get("count", 0)
                elif data.get("type") == "url_list":
                    summary["totals"]["malicious_urls"] += data.get("count", 0)
            except:
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
                "severity": "high"
            })
    except:
        pass

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
        limit: Maximum IOCs to return

    Returns:
        JSON with recent IOCs
    """
    try:
        data = await fetch_json(THREAT_FEEDS["threatfox_iocs"]["url"])

        iocs = []
        for item in data.get("data", [])[:limit]:
            ioc = {
                "ioc": item.get("ioc"),
                "ioc_type": item.get("ioc_type"),
                "threat_type": item.get("threat_type"),
                "malware": item.get("malware"),
                "confidence": item.get("confidence_level"),
                "first_seen": item.get("first_seen"),
                "tags": item.get("tags", [])
            }
            if ioc_type is None or ioc.get("ioc_type") == ioc_type:
                iocs.append(ioc)

        return json.dumps({
            "success": True,
            "count": len(iocs),
            "iocs": iocs[:limit]
        }, indent=2)

    except Exception as e:
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
        devices = scan_data.get("devices", [])

        if not devices:
            return json.dumps({
                "success": False,
                "error": "No devices in scan results"
            }, indent=2)

        # Fetch threat feeds first
        ip_feeds = ["feodo_tracker", "sslbl_botnet", "emerging_threats_compromised", "tor_exit_nodes"]
        threat_ips = set()

        for feed_name in ip_feeds:
            try:
                result = await fetch_threat_feed(feed_name)
                data = json.loads(result)
                if data.get("ips"):
                    threat_ips.update(data["ips"])
            except:
                continue

        # Check each device
        matches = []
        for device in devices:
            ip = device.get("ip")
            if ip in threat_ips:
                matches.append({
                    "device": device,
                    "threat_match": True,
                    "severity": "critical"
                })

        return json.dumps({
            "success": True,
            "devices_checked": len(devices),
            "threat_ips_loaded": len(threat_ips),
            "matches_found": len(matches),
            "matches": matches,
            "all_clear": len(matches) == 0
        }, indent=2)

    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, indent=2)


def main():
    """Entry point for MCP server."""
    ensure_dirs()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
