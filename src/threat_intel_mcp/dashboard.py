#!/usr/bin/env python3
"""
Threat Intelligence Dashboard
Real-time web dashboard for threat monitoring.
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from flask import Flask, render_template_string, jsonify, request
from flask_cors import CORS

from .config import (
    THREAT_FEEDS,
    threat_cache,
    validate_ip,
    validate_hash,
    get_enabled_feeds,
    get_timestamp,
    DATA_DIR,
    CACHE_DIR,
)

app = Flask(__name__)
CORS(app)

# Dashboard HTML template
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Intelligence Dashboard - Pixel's Eye</title>
    <style>
        :root {
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #1f2937;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-yellow: #f59e0b;
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --border: #374151;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'SF Mono', 'Monaco', 'Consolas', monospace;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }

        .header {
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
            padding: 1.5rem 2rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header h1 {
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .header h1 .pixel {
            font-size: 2rem;
        }

        .status-badge {
            background: var(--accent-green);
            color: black;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: bold;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 1.5rem;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }

        .card {
            background: var(--bg-card);
            border-radius: 0.75rem;
            border: 1px solid var(--border);
            overflow: hidden;
        }

        .card-header {
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .card-header h2 {
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
        }

        .card-body {
            padding: 1.25rem;
        }

        .stat-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }

        .stat {
            text-align: center;
            padding: 1rem;
            background: var(--bg-secondary);
            border-radius: 0.5rem;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent-blue);
        }

        .stat-label {
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }

        .stat.danger .stat-value { color: var(--accent-red); }
        .stat.warning .stat-value { color: var(--accent-yellow); }
        .stat.success .stat-value { color: var(--accent-green); }

        .feed-list {
            list-style: none;
        }

        .feed-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem;
            border-bottom: 1px solid var(--border);
        }

        .feed-item:last-child { border-bottom: none; }

        .feed-name {
            font-weight: 500;
        }

        .feed-count {
            background: var(--bg-secondary);
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            color: var(--accent-blue);
        }

        .alert-list {
            list-style: none;
        }

        .alert-item {
            padding: 0.75rem;
            margin-bottom: 0.5rem;
            border-radius: 0.5rem;
            border-left: 3px solid;
        }

        .alert-item.critical {
            background: rgba(239, 68, 68, 0.1);
            border-color: var(--accent-red);
        }

        .alert-item.high {
            background: rgba(245, 158, 11, 0.1);
            border-color: var(--accent-yellow);
        }

        .alert-item.medium {
            background: rgba(59, 130, 246, 0.1);
            border-color: var(--accent-blue);
        }

        .kev-list {
            max-height: 400px;
            overflow-y: auto;
        }

        .kev-item {
            padding: 0.75rem;
            border-bottom: 1px solid var(--border);
        }

        .kev-cve {
            font-weight: bold;
            color: var(--accent-red);
        }

        .kev-vendor {
            color: var(--accent-purple);
            font-size: 0.875rem;
        }

        .kev-name {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }

        .refresh-btn {
            background: var(--accent-blue);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            cursor: pointer;
            font-family: inherit;
        }

        .refresh-btn:hover {
            background: #2563eb;
        }

        .last-update {
            font-size: 0.75rem;
            color: var(--text-secondary);
        }

        .wide-card {
            grid-column: span 2;
        }

        @media (max-width: 768px) {
            .wide-card { grid-column: span 1; }
        }

        .loading {
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
        }

        .loading::after {
            content: '...';
            animation: dots 1.5s infinite;
        }

        @keyframes dots {
            0%, 20% { content: '.'; }
            40% { content: '..'; }
            60%, 100% { content: '...'; }
        }

        .search-box {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }

        .search-box input {
            flex: 1;
            padding: 0.5rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            color: var(--text-primary);
            font-family: inherit;
        }

        .search-box button {
            padding: 0.5rem 1rem;
            background: var(--accent-purple);
            border: none;
            border-radius: 0.5rem;
            color: white;
            cursor: pointer;
        }

        .result-box {
            padding: 1rem;
            background: var(--bg-secondary);
            border-radius: 0.5rem;
            font-size: 0.875rem;
            white-space: pre-wrap;
            max-height: 200px;
            overflow-y: auto;
        }

        .threat-clean { color: var(--accent-green); }
        .threat-low { color: var(--accent-blue); }
        .threat-medium { color: var(--accent-yellow); }
        .threat-high { color: var(--accent-red); }
        .threat-critical { color: #ff0000; font-weight: bold; }
    </style>
</head>
<body>
    <header class="header">
        <h1>
            <span class="pixel">🐕</span>
            Threat Intelligence Dashboard
        </h1>
        <div style="display: flex; align-items: center; gap: 1rem;">
            <span class="last-update" id="lastUpdate">Loading...</span>
            <span class="status-badge">LIVE</span>
            <button class="refresh-btn" onclick="refreshAll()">Refresh</button>
        </div>
    </header>

    <div class="container">
        <div class="grid">
            <!-- IP Check Card -->
            <div class="card">
                <div class="card-header">
                    <h2>IP Reputation Check</h2>
                </div>
                <div class="card-body">
                    <div class="search-box">
                        <input type="text" id="ipInput" placeholder="Enter IP address...">
                        <button onclick="checkIP()">Check</button>
                    </div>
                    <div class="result-box" id="ipResult">Enter an IP to check reputation</div>
                </div>
            </div>

            <!-- Hash Check Card -->
            <div class="card">
                <div class="card-header">
                    <h2>Hash Reputation Check</h2>
                </div>
                <div class="card-body">
                    <div class="search-box">
                        <input type="text" id="hashInput" placeholder="Enter MD5/SHA1/SHA256...">
                        <button onclick="checkHash()">Check</button>
                    </div>
                    <div class="result-box" id="hashResult">Enter a hash to check reputation</div>
                </div>
            </div>

            <!-- Summary Stats -->
            <div class="card">
                <div class="card-header">
                    <h2>Threat Summary</h2>
                </div>
                <div class="card-body">
                    <div class="stat-grid">
                        <div class="stat danger">
                            <div class="stat-value" id="maliciousIps">-</div>
                            <div class="stat-label">Malicious IPs</div>
                        </div>
                        <div class="stat warning">
                            <div class="stat-value" id="maliciousUrls">-</div>
                            <div class="stat-label">Malware URLs</div>
                        </div>
                        <div class="stat">
                            <div class="stat-value" id="recentCves">-</div>
                            <div class="stat-label">Recent KEVs (7d)</div>
                        </div>
                        <div class="stat success">
                            <div class="stat-value" id="feedsActive">-</div>
                            <div class="stat-label">Active Feeds</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Feed Status -->
            <div class="card">
                <div class="card-header">
                    <h2>Threat Feeds</h2>
                </div>
                <div class="card-body">
                    <ul class="feed-list" id="feedList">
                        <li class="loading">Loading feeds</li>
                    </ul>
                </div>
            </div>

            <!-- Cache Stats -->
            <div class="card">
                <div class="card-header">
                    <h2>Cache Statistics</h2>
                </div>
                <div class="card-body">
                    <div class="stat-grid">
                        <div class="stat">
                            <div class="stat-value" id="cacheSize">-</div>
                            <div class="stat-label">Cached Items</div>
                        </div>
                        <div class="stat">
                            <div class="stat-value" id="cacheMaxSize">-</div>
                            <div class="stat-label">Max Size</div>
                        </div>
                    </div>
                    <div style="margin-top: 1rem; text-align: center;">
                        <button class="refresh-btn" style="background: var(--accent-red);" onclick="clearCache()">Clear Cache</button>
                    </div>
                </div>
            </div>

            <!-- Network Status -->
            <div class="card">
                <div class="card-header">
                    <h2>Network Devices</h2>
                </div>
                <div class="card-body">
                    <div class="stat-grid">
                        <div class="stat success">
                            <div class="stat-value" id="devicesOnline">-</div>
                            <div class="stat-label">Online</div>
                        </div>
                        <div class="stat">
                            <div class="stat-value" id="clusterNodes">-</div>
                            <div class="stat-label">Cluster Nodes</div>
                        </div>
                        <div class="stat warning">
                            <div class="stat-value" id="unknownDevices">-</div>
                            <div class="stat-label">Unknown</div>
                        </div>
                        <div class="stat danger">
                            <div class="stat-value" id="threatMatches">0</div>
                            <div class="stat-label">Threats Detected</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- CISA KEV -->
            <div class="card wide-card">
                <div class="card-header">
                    <h2>CISA Known Exploited Vulnerabilities (Recent)</h2>
                </div>
                <div class="card-body">
                    <div class="kev-list" id="kevList">
                        <div class="loading">Loading KEV data</div>
                    </div>
                </div>
            </div>

            <!-- Alerts -->
            <div class="card">
                <div class="card-header">
                    <h2>Active Alerts</h2>
                </div>
                <div class="card-body">
                    <ul class="alert-list" id="alertList">
                        <li class="alert-item medium">Dashboard initialized</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <script>
        const API_BASE = window.location.origin;

        async function fetchData(endpoint) {
            try {
                const response = await fetch(`${API_BASE}${endpoint}`);
                return await response.json();
            } catch (error) {
                console.error(`Error fetching ${endpoint}:`, error);
                return null;
            }
        }

        async function checkIP() {
            const ip = document.getElementById('ipInput').value.trim();
            const resultBox = document.getElementById('ipResult');
            if (!ip) {
                resultBox.textContent = 'Please enter an IP address';
                return;
            }
            resultBox.textContent = 'Checking...';
            const data = await fetchData(`/api/check-ip/${ip}`);
            if (data) {
                const level = data.threat_level || 'unknown';
                resultBox.innerHTML = `
<span class="threat-${level}">Threat Level: ${level.toUpperCase()}</span>
IP: ${data.ip}
Sources Checked: ${data.sources_checked || 0}
Threats Found: ${data.threats_found || 0}
${data.details ? 'Details: ' + JSON.stringify(data.details, null, 2) : ''}`;
            } else {
                resultBox.textContent = 'Error checking IP';
            }
        }

        async function checkHash() {
            const hash = document.getElementById('hashInput').value.trim();
            const resultBox = document.getElementById('hashResult');
            if (!hash) {
                resultBox.textContent = 'Please enter a hash';
                return;
            }
            resultBox.textContent = 'Checking...';
            const data = await fetchData(`/api/check-hash/${hash}`);
            if (data) {
                if (data.success === false) {
                    resultBox.textContent = `Error: ${data.error}`;
                } else {
                    resultBox.innerHTML = `
Hash Type: ${data.hash_type || 'unknown'}
Hash: ${data.hash}
Threats Found: ${data.threats_found || 0}
${data.malware_names?.length ? 'Malware: ' + data.malware_names.join(', ') : ''}`;
                }
            } else {
                resultBox.textContent = 'Error checking hash';
            }
        }

        async function clearCache() {
            const data = await fetchData('/api/cache/clear');
            if (data && data.success) {
                alert('Cache cleared successfully');
                updateCacheStats();
            }
        }

        async function updateSummary() {
            const data = await fetchData('/api/summary');
            if (!data) return;

            document.getElementById('maliciousIps').textContent =
                data.totals?.malicious_ips?.toLocaleString() || '0';
            document.getElementById('maliciousUrls').textContent =
                data.totals?.malicious_urls?.toLocaleString() || '0';
            document.getElementById('recentCves').textContent =
                data.totals?.recent_cves || '0';
            document.getElementById('feedsActive').textContent =
                data.feeds_count || Object.keys(data.feeds || {}).length;

            // Update feed list
            const feedList = document.getElementById('feedList');
            if (data.feeds) {
                feedList.innerHTML = Object.entries(data.feeds).map(([name, info]) => `
                    <li class="feed-item">
                        <span class="feed-name">${name.replace(/_/g, ' ')}</span>
                        <span class="feed-count">${info.enabled ? 'Active' : 'Disabled'}</span>
                    </li>
                `).join('');
            }

            // Update alerts
            if (data.alerts && data.alerts.length > 0) {
                const alertList = document.getElementById('alertList');
                alertList.innerHTML = data.alerts.map(alert => `
                    <li class="alert-item ${alert.severity}">
                        ${alert.message}
                    </li>
                `).join('');
            }
        }

        async function updateKEV() {
            const data = await fetchData('/api/kev');
            if (!data || !data.vulnerabilities) return;

            const kevList = document.getElementById('kevList');
            kevList.innerHTML = data.vulnerabilities.slice(0, 20).map(kev => `
                <div class="kev-item">
                    <span class="kev-cve">${kev.cve_id}</span>
                    <span class="kev-vendor">${kev.vendor} - ${kev.product}</span>
                    <div class="kev-name">${kev.name}</div>
                </div>
            `).join('') || '<div class="loading">No recent KEVs</div>';
        }

        async function updateNetworkStatus() {
            const data = await fetchData('/api/network');
            if (!data) return;

            document.getElementById('devicesOnline').textContent =
                data.total_devices || '-';
            document.getElementById('clusterNodes').textContent =
                data.cluster_nodes_online || '-';
            document.getElementById('unknownDevices').textContent =
                data.unknown_devices || '-';
            document.getElementById('threatMatches').textContent =
                data.threat_matches || '0';
        }

        async function updateCacheStats() {
            const data = await fetchData('/api/cache/stats');
            if (!data) return;

            document.getElementById('cacheSize').textContent = data.size || 0;
            document.getElementById('cacheMaxSize').textContent = data.max_size || 0;
        }

        function updateTimestamp() {
            document.getElementById('lastUpdate').textContent =
                `Last updated: ${new Date().toLocaleTimeString()}`;
        }

        async function refreshAll() {
            await Promise.all([
                updateSummary(),
                updateKEV(),
                updateNetworkStatus(),
                updateCacheStats()
            ]);
            updateTimestamp();
        }

        // Initial load
        refreshAll();

        // Auto-refresh every 60 seconds
        setInterval(refreshAll, 60000);
    </script>
</body>
</html>
"""


def main():
    """Entry point for the dashboard."""
    run_dashboard()


@app.route('/')
def index():
    """Serve the main dashboard page."""
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/summary')
def api_summary() -> Any:
    """Get threat summary data."""
    enabled_feeds = get_enabled_feeds()

    summary = {
        "timestamp": get_timestamp(),
        "totals": {
            "malicious_ips": 0,
            "malicious_urls": 0,
            "recent_cves": 0
        },
        "feeds": {name: {"enabled": feed.enabled, "type": feed.feed_type.value}
                 for name, feed in THREAT_FEEDS.items()},
        "feeds_count": len(enabled_feeds),
        "alerts": [],
        "cache_stats": threat_cache.stats()
    }

    # Check cache for feed data
    cache_file = CACHE_DIR / "summary_cache.json"
    if cache_file.exists():
        try:
            with open(cache_file) as f:
                cached = json.load(f)
                if cached.get("timestamp"):
                    cache_time = datetime.fromisoformat(cached["timestamp"])
                    if datetime.now() - cache_time < timedelta(minutes=30):
                        # Merge cached totals
                        summary["totals"] = cached.get("totals", summary["totals"])
        except Exception:
            pass

    return jsonify(summary)


@app.route('/api/kev')
def api_kev() -> Any:
    """Get CISA KEV data."""
    cache_file = CACHE_DIR / "kev_cache.json"
    if cache_file.exists():
        try:
            with open(cache_file) as f:
                data = json.load(f)
                # Filter to recent CVEs (last 30 days)
                cutoff = datetime.now() - timedelta(days=30)
                recent_vulns = []
                for vuln in data.get("vulnerabilities", []):
                    if vuln.get("date_added"):
                        try:
                            added = datetime.fromisoformat(vuln["date_added"])
                            if added >= cutoff:
                                recent_vulns.append(vuln)
                        except ValueError:
                            pass
                return jsonify({"vulnerabilities": recent_vulns})
        except Exception:
            pass
    return jsonify({"vulnerabilities": []})


@app.route('/api/network')
def api_network() -> Any:
    """Get network status."""
    network_data = {
        "total_devices": 0,
        "cluster_nodes_online": 0,
        "unknown_devices": 0,
        "threat_matches": 0
    }

    # Read from network scanner data
    agentic_path = os.environ.get("AGENTIC_SYSTEM_PATH", "${AGENTIC_SYSTEM_PATH:-/opt/agentic}")
    history_file = Path(agentic_path) / "mcp-servers/network-scanner-mcp/data/device_history.json"
    known_file = Path(agentic_path) / "mcp-servers/network-scanner-mcp/data/known_devices.json"

    if history_file.exists():
        try:
            with open(history_file) as f:
                history = json.load(f)
                network_data["total_devices"] = len(history.get("devices", {}))
        except Exception:
            pass

    if known_file.exists():
        try:
            with open(known_file) as f:
                known = json.load(f)
                # Count cluster nodes (infrastructure type)
                cluster_count = sum(1 for d in known.get("devices", {}).values()
                                   if d.get("type") == "infrastructure")
                network_data["cluster_nodes_online"] = cluster_count
                # Count unknown (total - known)
                known_count = len(known.get("devices", {}))
                network_data["unknown_devices"] = max(0, network_data["total_devices"] - known_count)
        except Exception:
            pass

    return jsonify(network_data)


@app.route('/api/check-ip/<ip>')
def api_check_ip(ip: str) -> Any:
    """Check IP reputation via REST API."""
    is_valid, error = validate_ip(ip)
    if not is_valid:
        return jsonify({
            "success": False,
            "error": error,
            "ip": ip
        })

    # Check cache first
    cached = threat_cache.get(f"ip:{ip}")
    if cached:
        return jsonify(cached)

    # Return basic info - full check requires async MCP tools
    result = {
        "success": True,
        "ip": ip,
        "threat_level": "unknown",
        "sources_checked": 0,
        "threats_found": 0,
        "message": "For full reputation check, use the MCP tools directly",
        "timestamp": get_timestamp()
    }

    return jsonify(result)


@app.route('/api/check-hash/<file_hash>')
def api_check_hash(file_hash: str) -> Any:
    """Check hash reputation via REST API."""
    is_valid, hash_type, error = validate_hash(file_hash)
    if not is_valid:
        return jsonify({
            "success": False,
            "error": error,
            "hash": file_hash
        })

    # Check cache first
    cached = threat_cache.get(f"hash:{file_hash.lower()}")
    if cached:
        return jsonify(cached)

    # Return basic info
    result = {
        "success": True,
        "hash": file_hash.lower(),
        "hash_type": hash_type,
        "threats_found": 0,
        "malware_names": [],
        "message": "For full reputation check, use the MCP tools directly",
        "timestamp": get_timestamp()
    }

    return jsonify(result)


@app.route('/api/cache/stats')
def api_cache_stats() -> Any:
    """Get cache statistics."""
    return jsonify(threat_cache.stats())


@app.route('/api/cache/clear', methods=['GET', 'POST'])
def api_cache_clear() -> Any:
    """Clear the threat cache."""
    threat_cache.clear()
    return jsonify({
        "success": True,
        "message": "Cache cleared",
        "timestamp": get_timestamp()
    })


@app.route('/api/feeds')
def api_feeds() -> Any:
    """List all configured threat feeds."""
    feeds = {}
    for name, feed in THREAT_FEEDS.items():
        feeds[name] = {
            "name": feed.name,
            "description": feed.description,
            "url": feed.url,
            "feed_type": feed.feed_type.value,
            "enabled": feed.enabled,
            "requires_api_key": feed.requires_api_key
        }
    return jsonify({
        "success": True,
        "feeds": feeds,
        "total_feeds": len(feeds),
        "enabled_feeds": len(get_enabled_feeds())
    })


@app.route('/api/health')
def api_health() -> Any:
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": get_timestamp(),
        "cache_size": threat_cache.stats()["size"],
        "feeds_configured": len(THREAT_FEEDS)
    })


def run_dashboard(host: str = '0.0.0.0', port: int = 8889) -> None:
    """Run the Flask dashboard."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Starting Threat Intelligence Dashboard on http://{host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
