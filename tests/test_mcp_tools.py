"""
Tests for MCP tool endpoints in server.py.

Since MCP decorators prevent direct testing, we test the underlying logic
by mocking dependencies and calling the decorated functions.
"""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from threat_intel_mcp import server
from threat_intel_mcp.config import threat_cache


class TestGetThreatFeeds:
    """Test get_threat_feeds MCP tool."""

    @pytest.mark.asyncio
    async def test_get_threat_feeds_success(self):
        """Should return list of available feeds."""
        result = await server.get_threat_feeds()
        data = json.loads(result)

        assert data["success"] is True
        assert "feeds" in data
        assert "total_feeds" in data
        assert data["total_feeds"] > 0
        assert isinstance(data["feeds"], list)

        # Check feed structure
        feed = data["feeds"][0]
        assert "name" in feed
        assert "url" in feed
        assert "description" in feed
        assert "type" in feed

    @pytest.mark.asyncio
    async def test_get_threat_feeds_includes_api_status(self):
        """Should include API key configuration status."""
        result = await server.get_threat_feeds()
        data = json.loads(result)

        assert "api_configured" in data
        assert "virustotal" in data["api_configured"]
        assert "abuseipdb" in data["api_configured"]
        assert "shodan" in data["api_configured"]


class TestFetchThreatFeed:
    """Test fetch_threat_feed MCP tool."""

    @pytest.mark.asyncio
    async def test_fetch_unknown_feed(self):
        """Should return error for unknown feed."""
        result = await server.fetch_threat_feed("nonexistent_feed")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data
        assert "Unknown feed" in data["error"]
        assert "available_feeds" in data

    @pytest.mark.asyncio
    async def test_fetch_ip_feed(self, sample_ip_list_response, clean_cache):
        """Should fetch and parse IP list feed."""
        with patch('threat_intel_mcp.server.fetch_url', new=AsyncMock(return_value=sample_ip_list_response)):
            result = await server.fetch_threat_feed("feodo_tracker")
            data = json.loads(result)

            assert data["success"] is True
            assert data["type"] == "ip_list"
            assert "ips" in data
            assert len(data["ips"]) > 0
            assert "192.0.2.217" in data["ips"]
            assert data["cached"] is False

    @pytest.mark.asyncio
    async def test_fetch_feed_caching(self, sample_ip_list_response, clean_cache):
        """Should cache feed results."""
        with patch('threat_intel_mcp.server.fetch_url', new=AsyncMock(return_value=sample_ip_list_response)) as mock_fetch:
            # First fetch
            result1 = await server.fetch_threat_feed("feodo_tracker")
            data1 = json.loads(result1)
            assert data1["cached"] is False

            # Second fetch should use cache
            result2 = await server.fetch_threat_feed("feodo_tracker")
            data2 = json.loads(result2)
            assert data2["cached"] is True

            # fetch_url should only be called once
            assert mock_fetch.call_count == 1

    @pytest.mark.asyncio
    async def test_fetch_json_feed(self, sample_cisa_kev_response, clean_cache):
        """Should fetch and parse JSON feed."""
        with patch('threat_intel_mcp.server.fetch_json', new=AsyncMock(return_value=sample_cisa_kev_response)):
            result = await server.fetch_threat_feed("cisa_kev")
            data = json.loads(result)

            assert data["success"] is True
            assert data["type"] == "json"
            assert "data" in data

    @pytest.mark.asyncio
    async def test_fetch_feed_network_error(self, clean_cache):
        """Should handle network errors gracefully."""
        from aiohttp import ClientError

        with patch('threat_intel_mcp.server.fetch_url', new=AsyncMock(side_effect=ClientError("Connection failed"))):
            result = await server.fetch_threat_feed("feodo_tracker")
            data = json.loads(result)

            assert data["success"] is False
            assert "error" in data
            assert "Network error" in data["error"]


class TestCheckIPReputation:
    """Test check_ip_reputation MCP tool."""

    @pytest.mark.asyncio
    async def test_check_invalid_ip(self):
        """Should reject invalid IP addresses."""
        result = await server.check_ip_reputation("999.999.999.999")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_check_ip_against_feeds(self, sample_ip_list_response, clean_cache):
        """Should check IP against loaded threat feeds."""
        # Load threat data into cache
        threat_cache.set("feed_feodo_tracker", {
            "ips": ["192.0.2.217", "192.0.2.25"],
            "count": 2,
            "type": "ip_list"
        })

        result = await server.check_ip_reputation("192.0.2.217")
        data = json.loads(result)

        assert data["success"] is True
        assert data["ip"] == "192.0.2.217"
        assert data["is_malicious"] is True
        assert len(data["threats_found"]) > 0
        assert data["threat_level"] == "high"

    @pytest.mark.asyncio
    async def test_check_clean_ip(self, clean_cache):
        """Should report clean IP as safe."""
        threat_cache.set("feed_feodo_tracker", {
            "ips": ["192.0.2.217"],
            "count": 1,
            "type": "ip_list"
        })

        result = await server.check_ip_reputation("8.8.8.8")
        data = json.loads(result)

        assert data["success"] is True
        assert data["is_malicious"] is False
        assert data["threat_level"] == "low"


class TestCheckHashReputation:
    """Test check_hash_reputation MCP tool."""

    @pytest.mark.asyncio
    async def test_check_invalid_hash(self):
        """Should reject invalid hash format."""
        result = await server.check_hash_reputation("invalid_hash")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_check_valid_md5(self):
        """Should accept valid MD5 hash."""
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"

        result = await server.check_hash_reputation(md5_hash)
        data = json.loads(result)

        assert data["success"] is True
        assert data["hash_type"] == "md5"
        assert "is_malicious" in data

    @pytest.mark.asyncio
    async def test_check_valid_sha256(self):
        """Should accept valid SHA256 hash."""
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        result = await server.check_hash_reputation(sha256_hash)
        data = json.loads(result)

        assert data["success"] is True
        assert data["hash_type"] == "sha256"


class TestCheckBulkIPs:
    """Test check_bulk_ips MCP tool."""

    @pytest.mark.asyncio
    async def test_bulk_check_json_array(self, clean_cache):
        """Should accept JSON array of IPs."""
        threat_cache.set("feed_feodo_tracker", {
            "ips": ["192.0.2.1"],
            "count": 1,
            "type": "ip_list"
        })

        ips_json = '["192.0.2.1", "8.8.8.8", "1.1.1.1"]'
        result = await server.check_bulk_ips(ips_json)
        data = json.loads(result)

        assert data["success"] is True
        assert data["total_checked"] == 3
        assert len(data["results"]) == 3

    @pytest.mark.asyncio
    async def test_bulk_check_comma_separated(self, clean_cache):
        """Should accept comma-separated IPs."""
        threat_cache.set("feed_feodo_tracker", {
            "ips": ["192.0.2.1"],
            "count": 1,
            "type": "ip_list"
        })

        ips = "192.0.2.1, 8.8.8.8, 1.1.1.1"
        result = await server.check_bulk_ips(ips)
        data = json.loads(result)

        assert data["success"] is True
        assert data["total_checked"] == 3

    @pytest.mark.asyncio
    async def test_bulk_check_max_limit(self):
        """Should enforce maximum IP limit."""
        ips = ",".join([f"192.0.2.{i}" for i in range(101)])
        result = await server.check_bulk_ips(ips)
        data = json.loads(result)

        assert data["success"] is False
        assert "Maximum 100 IPs" in data["error"]

    @pytest.mark.asyncio
    async def test_bulk_check_counts_threats(self, clean_cache):
        """Should accurately count malicious IPs."""
        threat_cache.set("feed_feodo_tracker", {
            "ips": ["192.0.2.1", "192.0.2.2"],
            "count": 2,
            "type": "ip_list"
        })

        ips = "192.0.2.1, 8.8.8.8, 192.0.2.2"
        result = await server.check_bulk_ips(ips)
        data = json.loads(result)

        assert data["success"] is True
        assert data["malicious_count"] == 2
        assert data["clean_count"] == 1


class TestGetCISAKEV:
    """Test get_cisa_kev MCP tool."""

    @pytest.mark.asyncio
    async def test_get_recent_kevs(self, sample_cisa_kev_response):
        """Should fetch recent KEVs."""
        with patch('threat_intel_mcp.server.fetch_json', new=AsyncMock(return_value=sample_cisa_kev_response)):
            result = await server.get_cisa_kev(days=30)
            data = json.loads(result)

            assert data["success"] is True
            assert "vulnerabilities" in data
            assert "recent_count" in data

    @pytest.mark.asyncio
    async def test_filter_kev_by_vendor(self, sample_cisa_kev_response):
        """Should filter KEVs by vendor."""
        with patch('threat_intel_mcp.server.fetch_json', new=AsyncMock(return_value=sample_cisa_kev_response)):
            result = await server.get_cisa_kev(days=30, vendor="Microsoft")
            data = json.loads(result)

            assert data["success"] is True
            assert data["vendor_filter"] == "Microsoft"
            # Should only include Microsoft vulnerabilities
            for vuln in data["vulnerabilities"]:
                assert "Microsoft" in vuln["vendor"]


class TestGetRecentIOCs:
    """Test get_recent_iocs MCP tool."""

    @pytest.mark.asyncio
    async def test_get_all_iocs(self, sample_threatfox_response):
        """Should fetch recent IOCs."""
        with patch('threat_intel_mcp.server.fetch_json', new=AsyncMock(return_value=sample_threatfox_response)):
            result = await server.get_recent_iocs()
            data = json.loads(result)

            assert data["success"] is True
            assert "iocs" in data
            assert len(data["iocs"]) > 0

    @pytest.mark.asyncio
    async def test_filter_iocs_by_type(self, sample_threatfox_response):
        """Should filter IOCs by type."""
        with patch('threat_intel_mcp.server.fetch_json', new=AsyncMock(return_value=sample_threatfox_response)):
            result = await server.get_recent_iocs(ioc_type="domain")
            data = json.loads(result)

            assert data["success"] is True
            assert data["filter_type"] == "domain"
            for ioc in data["iocs"]:
                assert ioc["ioc_type"] == "domain"

    @pytest.mark.asyncio
    async def test_iocs_limit(self, sample_threatfox_response):
        """Should respect limit parameter."""
        with patch('threat_intel_mcp.server.fetch_json', new=AsyncMock(return_value=sample_threatfox_response)):
            result = await server.get_recent_iocs(limit=1)
            data = json.loads(result)

            assert data["success"] is True
            assert len(data["iocs"]) <= 1


class TestThreatStats:
    """Test get_threat_stats MCP tool."""

    @pytest.mark.asyncio
    async def test_get_stats(self, clean_cache):
        """Should return threat intelligence statistics."""
        result = await server.get_threat_stats()
        data = json.loads(result)

        assert data["success"] is True
        assert "cache" in data
        assert "feeds_configured" in data
        assert "feeds_enabled" in data
        assert "api_keys" in data


class TestClearCache:
    """Test clear_threat_cache MCP tool."""

    @pytest.mark.asyncio
    async def test_clear_cache(self, clean_cache):
        """Should clear the threat cache."""
        # Add some data
        threat_cache.set("test_key", "test_value")

        result = await server.clear_threat_cache()
        data = json.loads(result)

        assert data["success"] is True
        assert threat_cache.get("test_key") is None
