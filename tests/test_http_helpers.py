"""
Tests for HTTP helper functions (fetch_url, fetch_json).
"""

import pytest
from unittest.mock import AsyncMock, patch
from aiohttp import ClientError, ClientResponseError
from threat_intel_mcp.server import fetch_url, fetch_json


class TestFetchURL:
    """Test fetch_url function."""

    @pytest.mark.asyncio
    async def test_fetch_url_success(self):
        """Should successfully fetch URL content."""
        expected_text = "Test content"

        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value=expected_text)
            mock_response.raise_for_status = AsyncMock()

            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            mock_session_class.return_value = mock_session

            result = await fetch_url("http://example.com/test")

            assert result == expected_text
            mock_session.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_fetch_url_with_headers(self):
        """Should pass custom headers to request."""
        expected_text = "Test content"
        custom_headers = {"Authorization": "Bearer token123"}

        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value=expected_text)
            mock_response.raise_for_status = AsyncMock()

            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            mock_session_class.return_value = mock_session

            result = await fetch_url("http://example.com/test", headers=custom_headers)

            assert result == expected_text
            call_args = mock_session.get.call_args
            assert call_args[1]["headers"] == custom_headers

    @pytest.mark.asyncio
    async def test_fetch_url_with_timeout(self):
        """Should use custom timeout."""
        expected_text = "Test content"
        custom_timeout = 60

        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value=expected_text)
            mock_response.raise_for_status = AsyncMock()

            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            mock_session_class.return_value = mock_session

            result = await fetch_url("http://example.com/test", timeout=custom_timeout)

            call_args = mock_session.get.call_args
            assert call_args[1]["timeout"] == custom_timeout

    @pytest.mark.asyncio
    async def test_fetch_url_http_error(self):
        """Should raise exception on HTTP error."""
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 404
            mock_response.raise_for_status = AsyncMock(
                side_effect=ClientResponseError(None, None, status=404)
            )

            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            mock_session_class.return_value = mock_session

            with pytest.raises(ClientResponseError):
                await fetch_url("http://example.com/notfound")


class TestFetchJSON:
    """Test fetch_json function."""

    @pytest.mark.asyncio
    async def test_fetch_json_success(self):
        """Should successfully fetch and parse JSON."""
        expected_data = {"key": "value", "number": 42}

        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=expected_data)
            mock_response.raise_for_status = AsyncMock()

            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            mock_session_class.return_value = mock_session

            result = await fetch_json("http://example.com/api/test")

            assert result == expected_data
            mock_response.json.assert_called_once()

    @pytest.mark.asyncio
    async def test_fetch_json_with_headers(self):
        """Should pass custom headers to JSON request."""
        expected_data = {"result": "success"}
        custom_headers = {"x-api-key": "test-key"}

        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=expected_data)
            mock_response.raise_for_status = AsyncMock()

            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            mock_session_class.return_value = mock_session

            result = await fetch_json("http://example.com/api/test", headers=custom_headers)

            assert result == expected_data
            call_args = mock_session.get.call_args
            assert call_args[1]["headers"] == custom_headers

    @pytest.mark.asyncio
    async def test_fetch_json_array(self):
        """Should handle JSON arrays."""
        expected_data = [{"id": 1}, {"id": 2}]

        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=expected_data)
            mock_response.raise_for_status = AsyncMock()

            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            mock_session_class.return_value = mock_session

            result = await fetch_json("http://example.com/api/items")

            assert result == expected_data
            assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_fetch_json_http_error(self):
        """Should raise exception on HTTP error."""
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 500
            mock_response.raise_for_status = AsyncMock(
                side_effect=ClientResponseError(None, None, status=500)
            )

            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock()
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock()

            mock_session_class.return_value = mock_session

            with pytest.raises(ClientResponseError):
                await fetch_json("http://example.com/api/error")
