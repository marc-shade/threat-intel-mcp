#!/usr/bin/env python3
"""
Threat Intelligence Data Fetcher
Background service that fetches and caches threat data.
"""

import asyncio
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
import aiohttp
import os

# Paths
DATA_DIR = Path(os.path.join(os.environ.get("AGENTIC_SYSTEM_PATH", "${AGENTIC_SYSTEM_PATH:-/opt/agentic}"), "mcp-servers/threat-intel-mcp/data"))
CACHE_DIR = DATA_DIR / "cache"

THREAT_FEEDS = {
    "feodo_tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "ip_list"
    },
    "urlhaus_recent": {
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "type": "url_list"
    },
    "sslbl_botnet": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "type": "ip_list"
    },
    "tor_exit_nodes": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "type": "ip_list"
    },
}

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def fetch_url(url: str) -> str:
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=30) as response:
            response.raise_for_status()
            return await response.text()


async def fetch_json(url: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=30) as response:
            response.raise_for_status()
            return await response.json()


def parse_ip_list(content: str) -> list:
    ips = []
    for line in content.split('\n'):
        line = line.strip()
        if line and not line.startswith('#'):
            match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if match:
                ips.append(match.group(1))
    return ips


def parse_url_list(content: str) -> list:
    urls = []
    for line in content.split('\n'):
        line = line.strip()
        if line and not line.startswith('#') and line.startswith('http'):
            urls.append(line)
    return urls


async def fetch_all_feeds():
    """Fetch all threat feeds and cache results."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    summary = {
        "totals": {"malicious_ips": 0, "malicious_urls": 0, "recent_cves": 0},
        "feeds": {},
        "alerts": []
    }

    print(f"[{datetime.now().isoformat()}] Fetching threat feeds...")

    for name, info in THREAT_FEEDS.items():
        try:
            print(f"  Fetching {name}...")
            content = await fetch_url(info["url"])

            if info["type"] == "ip_list":
                items = parse_ip_list(content)
                summary["feeds"][name] = {"count": len(items), "type": "ip_list"}
                summary["totals"]["malicious_ips"] += len(items)
            elif info["type"] == "url_list":
                items = parse_url_list(content)
                summary["feeds"][name] = {"count": len(items), "type": "url_list"}
                summary["totals"]["malicious_urls"] += len(items)

            # Cache individual feed
            feed_cache = CACHE_DIR / f"{name}.json"
            with open(feed_cache, 'w') as f:
                json.dump({
                    "timestamp": datetime.now().isoformat(),
                    "count": len(items) if 'items' in dir() else 0,
                    "items": items[:1000] if 'items' in dir() else []
                }, f)

            print(f"    {name}: {summary['feeds'][name]['count']} items")

        except Exception as e:
            print(f"    {name}: ERROR - {e}")
            summary["feeds"][name] = {"count": 0, "error": str(e)}

    # Fetch CISA KEV
    try:
        print("  Fetching CISA KEV...")
        kev_data = await fetch_json(CISA_KEV_URL)
        vulnerabilities = kev_data.get("vulnerabilities", [])

        # Filter recent
        cutoff = datetime.now() - timedelta(days=7)
        recent = []
        for vuln in vulnerabilities:
            try:
                date_added = datetime.strptime(vuln.get("dateAdded", "2000-01-01"), "%Y-%m-%d")
                if date_added >= cutoff:
                    recent.append({
                        "cve_id": vuln.get("cveID"),
                        "vendor": vuln.get("vendorProject"),
                        "product": vuln.get("product"),
                        "name": vuln.get("vulnerabilityName"),
                        "description": vuln.get("shortDescription"),
                        "date_added": vuln.get("dateAdded"),
                    })
            except:
                continue

        summary["totals"]["recent_cves"] = len(recent)

        # Cache KEV
        kev_cache = CACHE_DIR / "kev_cache.json"
        with open(kev_cache, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "total": len(vulnerabilities),
                "recent_count": len(recent),
                "vulnerabilities": recent
            }, f)

        print(f"    CISA KEV: {len(recent)} recent / {len(vulnerabilities)} total")

        if len(recent) > 0:
            summary["alerts"].append({
                "type": "new_kev",
                "message": f"{len(recent)} new CISA KEV in last 7 days",
                "severity": "high"
            })

    except Exception as e:
        print(f"    CISA KEV: ERROR - {e}")

    # Save summary cache
    summary_cache = CACHE_DIR / "summary_cache.json"
    with open(summary_cache, 'w') as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "data": summary
        }, f)

    print(f"[{datetime.now().isoformat()}] Fetch complete. Summary cached.")
    return summary


async def main():
    """Main loop - fetch data every 30 minutes."""
    print("Threat Intelligence Data Fetcher starting...")

    while True:
        try:
            await fetch_all_feeds()
        except Exception as e:
            print(f"Error in fetch cycle: {e}")

        # Wait 30 minutes
        print("Sleeping for 30 minutes...")
        await asyncio.sleep(1800)


if __name__ == "__main__":
    asyncio.run(main())
