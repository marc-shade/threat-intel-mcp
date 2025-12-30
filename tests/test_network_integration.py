"""
Tests for network scanner integration functionality.
"""

import pytest
import json
from threat_intel_mcp import server
from threat_intel_mcp.config import threat_cache


class TestCheckNetworkAgainstThreats:
    """Test check_network_against_threats MCP tool."""

    @pytest.mark.asyncio
    async def test_invalid_json_input(self):
        """Should reject invalid JSON."""
        result = await server.check_network_against_threats("not valid json")
        data = json.loads(result)

        assert data["success"] is False
        assert "Invalid JSON" in data["error"]

    @pytest.mark.asyncio
    async def test_missing_devices(self):
        """Should handle missing devices field."""
        scan_results = json.dumps({"success": True})
        result = await server.check_network_against_threats(scan_results)
        data = json.loads(result)

        assert data["success"] is False
        assert "No devices found" in data["error"]

    @pytest.mark.asyncio
    async def test_check_clean_network(self, clean_cache):
        """Should report clean network with no matches."""
        threat_cache.set("feed_feodo_tracker", {
            "ips": ["192.0.2.1"],
            "count": 1,
            "type": "ip_list"
        })

        scan_results = json.dumps({
            "devices": [
                {"ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "hostname": "router"},
                {"ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "hostname": "laptop"}
            ]
        })

        result = await server.check_network_against_threats(scan_results)
        data = json.loads(result)

        assert data["success"] is True
        assert data["devices_checked"] == 2
        assert data["matches_found"] == 0
        assert data["all_clear"] is True
        assert "clean" in data["recommendation"].lower()

    @pytest.mark.asyncio
    async def test_detect_threat_on_network(self, sample_ip_list_response, clean_cache):
        """Should detect malicious IPs on network."""
        threat_cache.set("feed_feodo_tracker", {
            "ips": ["192.0.2.217", "192.0.2.25"],
            "count": 2,
            "type": "ip_list"
        })

        scan_results = json.dumps({
            "devices": [
                {"ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "hostname": "router"},
                {"ip": "192.0.2.217", "mac": "00:00:00:00:00:02", "hostname": "infected"},
                {"ip": "10.0.0.3", "mac": "00:00:00:00:00:03", "hostname": "laptop"}
            ]
        })

        result = await server.check_network_against_threats(scan_results)
        data = json.loads(result)

        assert data["success"] is True
        assert data["devices_checked"] == 3
        assert data["matches_found"] == 1
        assert data["all_clear"] is False
        assert "ALERT" in data["recommendation"]

        # Check matched device details
        match = data["matches"][0]
        assert match["device"]["ip"] == "192.0.2.217"
        assert match["threat_match"] is True
        assert match["severity"] == "critical"
        assert "Isolate" in match["recommendation"]

    @pytest.mark.asyncio
    async def test_multiple_threats_detected(self, clean_cache):
        """Should detect multiple malicious devices."""
        threat_cache.set("feed_feodo_tracker", {
            "ips": ["192.0.2.1", "192.0.2.2", "192.0.2.3"],
            "count": 3,
            "type": "ip_list"
        })

        scan_results = json.dumps({
            "devices": [
                {"ip": "192.0.2.1", "hostname": "device1"},
                {"ip": "192.0.2.2", "hostname": "device2"},
                {"ip": "10.0.0.1", "hostname": "clean"}
            ]
        })

        result = await server.check_network_against_threats(scan_results)
        data = json.loads(result)

        assert data["success"] is True
        assert data["matches_found"] == 2
        assert len(data["matches"]) == 2

    @pytest.mark.asyncio
    async def test_new_devices_format(self, clean_cache):
        """Should handle 'new_devices' key from scanner."""
        threat_cache.set("feed_feodo_tracker", {
            "ips": ["192.0.2.1"],
            "count": 1,
            "type": "ip_list"
        })

        scan_results = json.dumps({
            "new_devices": [
                {"ip": "192.0.2.1", "hostname": "new_device"}
            ]
        })

        result = await server.check_network_against_threats(scan_results)
        data = json.loads(result)

        assert data["success"] is True
        assert data["devices_checked"] == 1

    @pytest.mark.asyncio
    async def test_threat_ips_loaded_count(self, clean_cache):
        """Should report number of threat IPs loaded."""
        threat_cache.set("feed_feodo_tracker", {
            "ips": ["192.0.2.1", "192.0.2.2"],
            "count": 2,
            "type": "ip_list"
        })
        threat_cache.set("feed_sslbl_botnet", {
            "ips": ["192.0.2.3", "192.0.2.4"],
            "count": 2,
            "type": "ip_list"
        })

        scan_results = json.dumps({
            "devices": [{"ip": "10.0.0.1"}]
        })

        result = await server.check_network_against_threats(scan_results)
        data = json.loads(result)

        assert data["success"] is True
        assert data["threat_ips_available"] >= 4


class TestDashboardSummary:
    """Test get_dashboard_summary MCP tool."""

    @pytest.mark.asyncio
    async def test_dashboard_summary_structure(self, clean_cache):
        """Should return properly structured dashboard data."""
        with pytest.MonkeyPatch.context() as mp:
            # Mock fetch functions to avoid network calls
            async def mock_fetch(*args, **kwargs):
                return json.dumps({"success": True, "count": 10, "type": "ip_list"})

            mp.setattr(server, "fetch_threat_feed", mock_fetch)

            result = await server.get_dashboard_summary()
            data = json.loads(result)

            assert data["success"] is True
            assert "generated_at" in data
            assert "feeds" in data
            assert "totals" in data
            assert "alerts" in data
            assert "cache_stats" in data

    @pytest.mark.asyncio
    async def test_dashboard_totals_aggregation(self, sample_ip_list_response, clean_cache):
        """Should aggregate totals across feeds."""
        from unittest.mock import AsyncMock, patch

        async def mock_fetch_feed(feed_name):
            if "ip" in feed_name:
                return json.dumps({
                    "success": True,
                    "type": "ip_list",
                    "count": 100,
                    "ips": []
                })
            elif "url" in feed_name:
                return json.dumps({
                    "success": True,
                    "type": "url_list",
                    "count": 50,
                    "urls": []
                })
            else:
                return json.dumps({
                    "success": True,
                    "type": "json",
                    "count": 10
                })

        with patch('threat_intel_mcp.server.fetch_threat_feed', new=mock_fetch_feed):
            result = await server.get_dashboard_summary()
            data = json.loads(result)

            assert "totals" in data
            assert "malicious_ips" in data["totals"]
            assert "malicious_urls" in data["totals"]
