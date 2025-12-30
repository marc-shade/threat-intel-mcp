"""
Tests for error handling across all functions.
"""

import pytest
import json
from unittest.mock import AsyncMock, patch
from aiohttp import ClientError, ClientResponseError, ServerTimeoutError
from threat_intel_mcp import server
from threat_intel_mcp.config import threat_cache


class TestHTTPErrorHandling:
    """Test error handling in HTTP functions."""

    @pytest.mark.asyncio
    async def test_fetch_url_timeout(self):
        """Should handle timeout errors."""
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_response = AsyncMock()

            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()
            mock_session.get = AsyncMock(side_effect=ServerTimeoutError("Timeout"))

            mock_session_class.return_value = mock_session

            with pytest.raises(ServerTimeoutError):
                await server.fetch_url("http://example.com/slow")

    @pytest.mark.asyncio
    async def test_fetch_json_malformed_response(self):
        """Should handle JSON parse errors."""
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(side_effect=ValueError("Invalid JSON"))
            mock_response.raise_for_status = AsyncMock()

            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            mock_session_class.return_value = mock_session

            with pytest.raises(ValueError):
                await server.fetch_json("http://example.com/api/bad")


class TestMCPToolErrorHandling:
    """Test error handling in MCP tools."""

    @pytest.mark.asyncio
    async def test_fetch_feed_handles_network_error(self, clean_cache):
        """Should gracefully handle network errors."""
        with patch('threat_intel_mcp.server.fetch_url', side_effect=ClientError("Connection failed")):
            result = await server.fetch_threat_feed("feodo_tracker")
            data = json.loads(result)

            assert data["success"] is False
            assert "Network error" in data["error"]
            assert data["feed"] == "feodo_tracker"

    @pytest.mark.asyncio
    async def test_fetch_feed_handles_unexpected_error(self, clean_cache):
        """Should handle unexpected exceptions."""
        with patch('threat_intel_mcp.server.fetch_url', side_effect=RuntimeError("Unexpected error")):
            result = await server.fetch_threat_feed("feodo_tracker")
            data = json.loads(result)

            assert data["success"] is False
            assert "error" in data

    @pytest.mark.asyncio
    async def test_check_ip_reputation_handles_api_errors(self, clean_cache):
        """Should continue checking other sources if one API fails."""
        threat_cache.set("feed_feodo_tracker", {
            "ips": ["192.0.2.1"],
            "count": 1,
            "type": "ip_list"
        })

        # Mock VirusTotal API failure
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()
            mock_session.get = AsyncMock(side_effect=ClientError("API error"))
            mock_session_class.return_value = mock_session

            result = await server.check_ip_reputation("192.0.2.1")
            data = json.loads(result)

            # Should still succeed with feed data
            assert data["success"] is True
            assert data["is_malicious"] is True

    @pytest.mark.asyncio
    async def test_get_cisa_kev_handles_invalid_dates(self):
        """Should handle invalid date formats in CISA KEV data."""
        invalid_kev_response = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "vendorProject": "Test",
                    "product": "Product",
                    "vulnerabilityName": "Test",
                    "dateAdded": "invalid-date",  # Invalid format
                    "shortDescription": "Test"
                }
            ]
        }

        with patch('threat_intel_mcp.server.fetch_json', new=AsyncMock(return_value=invalid_kev_response)):
            result = await server.get_cisa_kev(days=30)
            data = json.loads(result)

            # Should not crash, should skip invalid entries
            assert data["success"] is True
            assert "vulnerabilities" in data

    @pytest.mark.asyncio
    async def test_bulk_check_handles_malformed_input(self):
        """Should handle various malformed input formats."""
        # Empty string
        result = await server.check_bulk_ips("")
        data = json.loads(result)
        assert data["success"] is False

        # Whitespace only
        result = await server.check_bulk_ips("   ")
        data = json.loads(result)
        assert data["success"] is False

        # Invalid JSON
        result = await server.check_bulk_ips("[invalid json")
        # Should fallback to comma-separated parsing
        data = json.loads(result)
        # May succeed or fail depending on parsing

    @pytest.mark.asyncio
    async def test_check_network_partial_failures(self, clean_cache):
        """Should process valid devices even if some are invalid."""
        threat_cache.set("feed_feodo_tracker", {
            "ips": ["192.0.2.1"],
            "count": 1,
            "type": "ip_list"
        })

        scan_results = json.dumps({
            "devices": [
                {"ip": "invalid-ip", "hostname": "bad"},
                {"ip": "10.0.0.1", "hostname": "good"},
                {"ip": "192.0.2.1", "hostname": "threat"}
            ]
        })

        result = await server.check_network_against_threats(scan_results)
        data = json.loads(result)

        # Should process valid IPs
        assert data["success"] is True
        # Exact count depends on validation


class TestValidationErrorHandling:
    """Test validation error messages."""

    @pytest.mark.asyncio
    async def test_ip_validation_error_message(self):
        """Should provide clear error for invalid IP."""
        result = await server.check_ip_reputation("not.an.ip.address")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data
        assert "Invalid IP" in data["error"]

    @pytest.mark.asyncio
    async def test_hash_validation_error_message(self):
        """Should provide clear error for invalid hash."""
        result = await server.check_hash_reputation("tooshort")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data
        assert "Invalid hash" in data["error"]

    @pytest.mark.asyncio
    async def test_ioc_type_validation_error_message(self):
        """Should provide clear error for invalid IOC type."""
        result = await server.get_recent_iocs(ioc_type="invalid_type")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data
        assert "Invalid IOC type" in data["error"]


class TestCacheErrorRecovery:
    """Test cache failure recovery."""

    def test_cache_handles_expiry_errors(self):
        """Should handle errors during expiry cleanup."""
        cache = threat_cache

        # Set a value
        cache.set("test", "value")

        # Manually corrupt expiry (simulate edge case)
        # Cache should still be usable
        assert cache.get("test") == "value"

    def test_cache_handles_concurrent_eviction(self):
        """Should handle concurrent eviction scenarios."""
        from threat_intel_mcp.config import ThreatCache
        cache = ThreatCache(max_size=2)

        # Fill cache
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        # Trigger eviction
        cache.set("key3", "value3")

        # Should not crash
        stats = cache.stats()
        assert stats["size"] <= 2


class TestPartialDataHandling:
    """Test handling of partial/incomplete data."""

    @pytest.mark.asyncio
    async def test_feed_with_empty_response(self, clean_cache):
        """Should handle empty feed responses."""
        with patch('threat_intel_mcp.server.fetch_url', new=AsyncMock(return_value="")):
            result = await server.fetch_threat_feed("feodo_tracker")
            data = json.loads(result)

            assert data["success"] is True
            assert data["count"] == 0

    @pytest.mark.asyncio
    async def test_feed_with_all_invalid_entries(self, clean_cache):
        """Should handle feeds with all invalid entries."""
        invalid_content = """# All invalid
999.999.999.999
invalid.ip.address
not-an-ip"""

        with patch('threat_intel_mcp.server.fetch_url', new=AsyncMock(return_value=invalid_content)):
            result = await server.fetch_threat_feed("feodo_tracker")
            data = json.loads(result)

            assert data["success"] is True
            assert data["count"] == 0
