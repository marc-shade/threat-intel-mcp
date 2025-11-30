# Threat Intelligence MCP Server

Real-time threat intelligence aggregation for the AGI agentic cluster.

## Features

- **Multi-source threat feeds**: Feodo Tracker, URLhaus, CISA KEV, ThreatFox, Emerging Threats
- **IP/Hash reputation checking**: VirusTotal, AbuseIPDB integration
- **Network scanning integration**: Check scanned devices against threat lists
- **Dashboard API**: Aggregated data for visualization

## Installation

```bash
cd ${AGENTIC_SYSTEM_PATH:-/opt/agentic}/mcp-servers/threat-intel-mcp
pip install -e .
```

## Configuration

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "threat-intel": {
      "command": "${AGENTIC_SYSTEM_PATH:-/opt/agentic}/.venv/bin/python3",
      "args": ["${AGENTIC_SYSTEM_PATH:-/opt/agentic}/mcp-servers/threat-intel-mcp/src/threat_intel_mcp/server.py"]
    }
  }
}
```

## API Keys (Optional)

Set environment variables for enhanced capabilities:

- `VIRUSTOTAL_API_KEY` - Hash and IP lookups
- `ABUSEIPDB_API_KEY` - IP reputation
- `OTX_API_KEY` - AlienVault OTX feeds

## Tools

| Tool | Description |
|------|-------------|
| `get_threat_feeds` | List available threat intelligence feeds |
| `fetch_threat_feed` | Fetch IOCs from a specific feed |
| `check_ip_reputation` | Check IP against threat sources |
| `check_hash_reputation` | Check file hash (MD5/SHA1/SHA256) |
| `get_cisa_kev` | Get CISA Known Exploited Vulnerabilities |
| `get_dashboard_summary` | Aggregated threat data for dashboards |
| `get_recent_iocs` | Recent IOCs from ThreatFox |
| `check_network_against_threats` | Check network scan results for threats |

## Free Threat Feeds

No API key required:
- Feodo Tracker (botnet C&C)
- URLhaus (malware URLs)
- SSL Blacklist
- Emerging Threats
- CISA KEV
- Tor Exit Nodes
- ThreatFox IOCs

## Integration with Network Scanner

```python
# Check network scan results against threats
scan_results = await scan_network()
threat_check = await check_network_against_threats(scan_results)
```
