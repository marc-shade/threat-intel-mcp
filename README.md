# Threat Intelligence MCP Server

Real-time threat intelligence aggregation for the AGI agentic cluster.

**Version**: 0.2.0

## Features

- **Multi-source threat feeds**: Feodo Tracker, URLhaus, CISA KEV, ThreatFox, Emerging Threats, Spamhaus DROP, Blocklist.de, CINSscore
- **IP/Hash reputation checking**: VirusTotal, AbuseIPDB, Shodan integration
- **Bulk IP checking**: Check up to 100 IPs in a single request
- **Network scanning integration**: Check scanned devices against threat lists
- **Thread-safe caching**: Intelligent caching with TTL and size limits
- **Dashboard API**: Aggregated data for visualization (Flask-based)

## Installation

```bash
cd ${AGENTIC_SYSTEM_PATH:-/opt/agentic}/mcp-servers/threat-intel-mcp
pip install -e .

# For dashboard support:
pip install -e ".[dashboard]"

# For development:
pip install -e ".[dev]"
```

## Configuration

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "threat-intel": {
      "command": "${AGENTIC_SYSTEM_PATH:-/opt/agentic}/.venv/bin/python3",
      "args": ["-m", "threat_intel_mcp.server"]
    }
  }
}
```

## API Keys (Optional)

Set environment variables for enhanced capabilities:

| Variable | Service | Purpose |
|----------|---------|---------|
| `VIRUSTOTAL_API_KEY` | VirusTotal | Hash and IP lookups |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | IP reputation and abuse reports |
| `SHODAN_API_KEY` | Shodan | IP intelligence and port scanning |
| `OTX_API_KEY` | AlienVault OTX | Threat pulse feeds |

## MCP Tools

| Tool | Description |
|------|-------------|
| `get_threat_feeds` | List all available threat intelligence feeds with status |
| `fetch_threat_feed` | Fetch IOCs from a specific feed by name |
| `check_ip_reputation` | Check IP against multiple threat sources (VT, AbuseIPDB, Shodan) |
| `check_hash_reputation` | Check file hash (MD5/SHA1/SHA256) reputation |
| `check_bulk_ips` | **NEW** Check up to 100 IPs in a single request |
| `get_cisa_kev` | Get CISA Known Exploited Vulnerabilities catalog |
| `get_dashboard_summary` | Aggregated threat data for dashboards |
| `get_recent_iocs` | Recent IOCs from ThreatFox (filterable by type) |
| `check_network_against_threats` | Check network scan results for threats |
| `get_threat_stats` | **NEW** Get cache statistics and API key status |
| `clear_threat_cache` | **NEW** Clear the threat intelligence cache |

## Threat Feeds

### Free (No API Key Required)

| Feed | Type | Description |
|------|------|-------------|
| `feodo_tracker` | IP List | Botnet C&C IPs (Dridex, Emotet, TrickBot) |
| `urlhaus_recent` | URL List | Recent malware distribution URLs |
| `sslbl_ip` | IP List | SSL Blacklist malicious IPs |
| `emerging_threats_compromised` | IP List | Compromised host IPs |
| `tor_exit_nodes` | IP List | Known Tor exit node IPs |
| `cisa_kev` | JSON | Known Exploited Vulnerabilities catalog |
| `threatfox_recent` | JSON | Recent malware IOCs |
| `blocklist_de_all` | IP List | All attackers from blocklist.de |
| `cinsscore_badguys` | IP List | CINSscore malicious IPs |
| `spamhaus_drop` | CIDR List | Spamhaus Don't Route Or Peer |

### API-Enhanced

| Feed | API Key | Enhanced Data |
|------|---------|---------------|
| VirusTotal | `VIRUSTOTAL_API_KEY` | Detection ratios, vendor verdicts |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | Abuse confidence score, report counts |
| Shodan | `SHODAN_API_KEY` | Open ports, services, vulnerabilities |
| AlienVault OTX | `OTX_API_KEY` | Threat pulses, related IOCs |

## Usage Examples

### Check IP Reputation

```python
# Returns threat level: clean/low/medium/high/critical
result = await check_ip_reputation("192.0.2.102")
```

### Bulk IP Check

```python
# Comma-separated
result = await check_bulk_ips("8.8.8.8, 1.1.1.1, 192.0.2.102")

# JSON array
result = await check_bulk_ips('["8.8.8.8", "1.1.1.1"]')
```

### Network Scanner Integration

```python
# Check network scan results against threats
scan_results = '{"devices": [{"ip": "192.0.2.217"}, {"ip": "192.0.2.25"}]}'
threat_check = await check_network_against_threats(scan_results)
```

### Get Recent IOCs

```python
# All recent IOCs
result = await get_recent_iocs()

# Filter by type: ip, ip:port, domain, url, md5, sha1, sha256
result = await get_recent_iocs(ioc_type="ip:port", limit=50)
```

## Running the Dashboard

```bash
# Start the Flask dashboard server
threat-intel-dashboard

# Or directly:
python -m threat_intel_mcp.dashboard
```

Dashboard provides REST API endpoints for visualization tools.

## Development

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=threat_intel_mcp --cov-report=html
```

### Project Structure

```
threat-intel-mcp/
├── src/threat_intel_mcp/
│   ├── __init__.py      # Package exports
│   ├── config.py        # Configuration, validation, caching
│   ├── server.py        # FastMCP server and tools
│   └── dashboard.py     # Flask dashboard API
├── tests/
│   ├── conftest.py      # Pytest fixtures
│   ├── test_config.py   # Config module tests
│   └── test_server.py   # Server and tool tests
└── pyproject.toml       # Package configuration
```

## Changelog

### v0.2.0

- **New Features**:
  - Bulk IP checking (up to 100 IPs)
  - Shodan integration for IP intelligence
  - Cache statistics and management tools
  - 3 additional threat feeds (blocklist.de, CINSscore, Spamhaus DROP)

- **Improvements**:
  - Shared configuration module eliminates code duplication
  - Thread-safe caching with TTL and size limits
  - Proper input validation for all IOC types
  - Type hints throughout codebase

- **Bug Fixes**:
  - Fixed all bare except clauses with proper exception handling
  - Removed unused imports and dependencies
  - Fixed variable scope issues

- **Developer Experience**:
  - Comprehensive test suite (67 tests)
  - pytest-asyncio for async testing
  - Optional dependency groups (dashboard, dev)

### v0.1.0

- Initial release with basic threat feed aggregation
