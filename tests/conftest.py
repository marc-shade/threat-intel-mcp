"""
Pytest fixtures for threat-intel-mcp tests.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import json


@pytest.fixture
def mock_aiohttp_session():
    """Mock aiohttp ClientSession for testing without network calls."""
    with patch('aiohttp.ClientSession') as mock_session:
        mock_cm = AsyncMock()
        mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_session.return_value.__aexit__ = AsyncMock(return_value=None)
        yield mock_cm


@pytest.fixture
def sample_ip_list_response():
    """Sample IP list feed response."""
    return """# Comment line
# Another comment
192.0.2.217
192.0.2.25
8.8.8.8
# inline comment
192.0.2.46
"""


@pytest.fixture
def sample_url_list_response():
    """Sample URL list feed response."""
    return """# Malware URLs
http://malware.example.com/payload.exe
https://phishing.example.com/login.php
http://botnet.cc/c2
"""


@pytest.fixture
def sample_cisa_kev_response():
    """Sample CISA KEV JSON response."""
    return {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2024.01.01",
        "dateReleased": "2024-01-01",
        "count": 3,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-0001",
                "vendorProject": "Microsoft",
                "product": "Windows",
                "vulnerabilityName": "Test Vulnerability",
                "dateAdded": "2024-01-01",
                "shortDescription": "A test vulnerability",
                "requiredAction": "Apply updates",
                "dueDate": "2024-02-01",
                "knownRansomwareCampaignUse": "Known"
            },
            {
                "cveID": "CVE-2024-0002",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Log4Shell",
                "dateAdded": "2024-01-02",
                "shortDescription": "Remote code execution",
                "requiredAction": "Patch immediately",
                "dueDate": "2024-01-15",
                "knownRansomwareCampaignUse": "Known"
            },
            {
                "cveID": "CVE-2023-0001",
                "vendorProject": "Linux",
                "product": "Kernel",
                "vulnerabilityName": "Old Vulnerability",
                "dateAdded": "2023-01-01",
                "shortDescription": "Old vuln",
                "requiredAction": "Update",
                "dueDate": "2023-02-01",
                "knownRansomwareCampaignUse": "Unknown"
            }
        ]
    }


@pytest.fixture
def sample_threatfox_response():
    """Sample ThreatFox IOC response."""
    return {
        "query_status": "ok",
        "data": [
            {
                "id": "1",
                "ioc": "192.0.2.102:4444",
                "ioc_type": "ip:port",
                "threat_type": "botnet_cc",
                "malware": "Cobalt Strike",
                "malware_printable": "Cobalt Strike",
                "confidence_level": 100,
                "first_seen": "2024-01-01 00:00:00 UTC",
                "last_seen": "2024-01-02 00:00:00 UTC",
                "tags": ["cobalt-strike", "c2"],
                "reference": "https://example.com/report"
            },
            {
                "id": "2",
                "ioc": "malware.example.com",
                "ioc_type": "domain",
                "threat_type": "malware_download",
                "malware": "Emotet",
                "malware_printable": "Emotet",
                "confidence_level": 90,
                "first_seen": "2024-01-01 00:00:00 UTC",
                "last_seen": None,
                "tags": ["emotet"],
                "reference": None
            }
        ]
    }


@pytest.fixture
def sample_virustotal_ip_response():
    """Sample VirusTotal IP lookup response."""
    return {
        "data": {
            "type": "ip_address",
            "id": "8.8.8.8",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 80,
                    "harmless": 10,
                    "timeout": 0
                },
                "reputation": 0,
                "country": "US",
                "as_owner": "Google LLC"
            }
        }
    }


@pytest.fixture
def sample_virustotal_malicious_ip_response():
    """Sample VirusTotal response for malicious IP."""
    return {
        "data": {
            "type": "ip_address",
            "id": "1.2.3.4",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 15,
                    "suspicious": 5,
                    "undetected": 50,
                    "harmless": 20,
                    "timeout": 0
                },
                "reputation": -50,
                "country": "RU"
            }
        }
    }


@pytest.fixture
def sample_abuseipdb_response():
    """Sample AbuseIPDB response."""
    return {
        "data": {
            "ipAddress": "1.2.3.4",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidenceScore": 85,
            "countryCode": "RU",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Example ISP",
            "totalReports": 150,
            "lastReportedAt": "2024-01-01T00:00:00+00:00"
        }
    }


@pytest.fixture
def sample_network_scan_results():
    """Sample network scanner output."""
    return {
        "success": True,
        "devices": [
            {"ip": "192.0.2.102", "mac": "00:00:00:00:00:63", "hostname": "router"},
            {"ip": "192.0.2.217", "mac": "00:00:00:00:00:1B", "hostname": "laptop"},
            {"ip": "192.0.2.25", "mac": "00:00:00:00:00:D7", "hostname": "malicious-host"}
        ]
    }


@pytest.fixture
def clean_cache():
    """Fixture to ensure clean cache state before each test."""
    from threat_intel_mcp.config import threat_cache
    threat_cache.clear()
    yield threat_cache
    threat_cache.clear()
