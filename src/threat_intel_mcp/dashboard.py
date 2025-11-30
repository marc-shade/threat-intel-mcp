#!/usr/bin/env python3
"""
Threat Intelligence Dashboard
Real-time web dashboard for threat monitoring.
"""

import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
import threading
import aiohttp

from flask import Flask, render_template_string, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

# Data directory
DATA_DIR = Path(os.path.join(os.environ.get("AGENTIC_SYSTEM_PATH", "/mnt/agentic-system"), "mcp-servers/threat-intel-mcp/data"))
CACHE_DIR = DATA_DIR / "cache"

# Threat feed URLs
THREAT_FEEDS = {
    "feodo_tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    "urlhaus_recent": "https://urlhaus.abuse.ch/downloads/text_recent/",
    "sslbl_botnet": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "tor_exit_nodes": "https://check.torproject.org/torbulkexitlist",
}

# Cache
feed_cache = {}

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
                Object.keys(data.feeds || {}).length;

            // Update feed list
            const feedList = document.getElementById('feedList');
            feedList.innerHTML = Object.entries(data.feeds || {}).map(([name, info]) => `
                <li class="feed-item">
                    <span class="feed-name">${name.replace(/_/g, ' ')}</span>
                    <span class="feed-count">${info.count?.toLocaleString() || 'N/A'}</span>
                </li>
            `).join('');

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

        function updateTimestamp() {
            document.getElementById('lastUpdate').textContent =
                `Last updated: ${new Date().toLocaleTimeString()}`;
        }

        async function refreshAll() {
            await Promise.all([
                updateSummary(),
                updateKEV(),
                updateNetworkStatus()
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


@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/summary')
def api_summary():
    """Get threat summary data."""
    summary = {
        "totals": {
            "malicious_ips": 0,
            "malicious_urls": 0,
            "recent_cves": 0
        },
        "feeds": {},
        "alerts": []
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
                        return jsonify(cached["data"])
        except:
            pass

    return jsonify(summary)


@app.route('/api/kev')
def api_kev():
    """Get CISA KEV data."""
    cache_file = CACHE_DIR / "kev_cache.json"
    if cache_file.exists():
        try:
            with open(cache_file) as f:
                return jsonify(json.load(f))
        except:
            pass
    return jsonify({"vulnerabilities": []})


@app.route('/api/network')
def api_network():
    """Get network status."""
    # Read from network scanner data
    network_data = {
        "total_devices": 0,
        "cluster_nodes_online": 0,
        "unknown_devices": 0,
        "threat_matches": 0
    }

    history_file = Path(os.path.join(os.environ.get("AGENTIC_SYSTEM_PATH", "/mnt/agentic-system"), "mcp-servers/network-scanner-mcp/data/device_history.json"))
    if history_file.exists():
        try:
            with open(history_file) as f:
                history = json.load(f)
                network_data["total_devices"] = len(history.get("devices", {}))
        except:
            pass

    return jsonify(network_data)


@app.route('/api/check-ip/<ip>')
def api_check_ip(ip):
    """Check IP reputation."""
    # This would call the threat intel MCP tools
    return jsonify({
        "ip": ip,
        "status": "not_implemented",
        "message": "Use the MCP tools directly for IP checks"
    })


def run_dashboard(host='0.0.0.0', port=8889):
    """Run the Flask dashboard."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    print("Starting Threat Intelligence Dashboard on http://localhost:8889")
    run_dashboard()
