# Threat Intel MCP Test Suite

Comprehensive pytest test suite for the threat-intel-mcp server.

## Test Coverage

- **67 passing tests** with **95% coverage** on config.py
- **35% overall coverage** (focuses on core business logic)

## Test Structure

### test_parsing.py (20 tests)
Tests for feed parsing functions:
- `parse_ip_list()` - IP address list parsing
- `parse_url_list()` - URL list parsing
- `parse_cidr_list()` - CIDR notation parsing

Validates handling of:
- Valid/invalid inputs
- Comments and whitespace
- IPv4 and IPv6 addresses
- Edge cases (empty content, malformed data)

### test_validation.py (16 tests)
Tests for input validation functions:
- `validate_ip()` - IP address validation
- `validate_hash()` - File hash validation (MD5/SHA1/SHA256)
- `validate_domain()` - Domain name validation
- `validate_ioc_type()` - IOC type validation

### test_cache.py (12 tests)
Tests for ThreatCache class:
- Basic get/set operations
- TTL (time-to-live) expiry
- Size limits and eviction
- Thread safety
- Complex data types
- Statistics tracking

### test_integration.py (17 tests)
Integration tests for complete workflows:
- Configuration validation
- Multi-feed aggregation
- Cache integration patterns
- Threat detection logic
- Helper function combinations
- Concurrent access scenarios

### test_error_handling.py (2 tests - core only)
Error handling and recovery:
- Cache error recovery
- Concurrent eviction handling

## Running Tests

### Run all tests:
```bash
PYTHONPATH=src:$PYTHONPATH pytest tests/ -v
```

### Run with coverage:
```bash
PYTHONPATH=src:$PYTHONPATH pytest tests/ --cov=src/threat_intel_mcp --cov-report=term-missing
```

### Run specific test file:
```bash
PYTHONPATH=src:$PYTHONPATH pytest tests/test_parsing.py -v
```

### Run specific test:
```bash
PYTHONPATH=src:$PYTHONPATH pytest tests/test_parsing.py::TestParseIPList::test_parse_valid_ips -v
```

## Test Fixtures

### conftest.py
Provides reusable fixtures:
- `sample_ip_list_response` - Mock IP feed data
- `sample_url_list_response` - Mock URL feed data
- `sample_cisa_kev_response` - Mock CISA KEV data
- `sample_threatfox_response` - Mock ThreatFox IOC data
- `sample_virustotal_ip_response` - Mock VirusTotal data
- `sample_abuseipdb_response` - Mock AbuseIPDB data
- `sample_network_scan_results` - Mock network scan data
- `clean_cache` - Fresh cache for each test

## Coverage Report

Current coverage by module:
- `config.py`: 95% (11 lines missed - mostly error paths)
- `server.py`: 21% (HTTP functions and MCP tools tested via integration)
- `__init__.py`: 100%

### Missing Coverage Areas
The MCP-decorated tool functions are tested via integration tests rather than unit tests due to FastMCP decorator constraints. The underlying logic (parsing, validation, caching) has comprehensive coverage.

## Test Patterns

### AsyncMock Usage
HTTP functions use AsyncMock for async operations:
```python
with patch('aiohttp.ClientSession') as mock_session:
    mock_session.return_value.__aenter__ = AsyncMock(...)
    result = await fetch_url("http://example.com")
```

### Cache Testing
Tests use `clean_cache` fixture to ensure isolation:
```python
def test_something(clean_cache):
    cache = clean_cache
    cache.set("key", "value")
    # Test runs with clean cache
```

### Threading Tests
Concurrent access validated with multiple threads:
```python
threads = [threading.Thread(target=writer) for _ in range(5)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

## CI/CD Integration

Tests are designed to run in CI environments:
- No external network calls (all mocked)
- No API keys required for core tests
- Deterministic results
- Fast execution (~5 seconds)

## Future Test Additions

Potential areas for expansion:
1. End-to-end MCP integration tests (requires MCP test harness)
2. Performance/benchmark tests
3. Stress testing for cache under load
4. API integration tests (when API keys available)
5. Dashboard functionality tests

## Contributing

When adding tests:
1. Follow existing patterns (class-based organization)
2. Use descriptive test names (`test_should_do_something`)
3. Include docstrings explaining what's tested
4. Mock external dependencies (network, filesystem)
5. Ensure tests are isolated (no shared state)
6. Aim for 80%+ coverage on new code
