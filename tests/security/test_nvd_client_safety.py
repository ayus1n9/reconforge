"""Security and robustness tests for NIST NVD client."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from reconforge.intelligence.cache import VulnerabilityCache
from reconforge.intelligence.nvd_client import AsyncNVDClient, NVDRateLimiter
from reconforge.storage.database import DatabaseManager


@pytest.mark.asyncio
async def test_nvd_rate_limiter_throttling():
    limiter = NVDRateLimiter(has_api_key=False)
    # Drain tokens
    limiter.tokens = 0.0
    start = asyncio.get_event_loop().time()
    task = asyncio.create_task(limiter.acquire())
    # Should sleep because tokens == 0
    await asyncio.sleep(0.05)
    assert not task.done()
    # Replenish token
    limiter.tokens = 1.0
    await task
    elapsed = asyncio.get_event_loop().time() - start
    assert elapsed >= 0.05


def test_nvd_client_rejects_oversized_payload():
    db = DatabaseManager("sqlite:///:memory:")
    cache = VulnerabilityCache(db)
    client = AsyncNVDClient(cache=cache, offline_mode=False)

    # Mock response returning chunks exceeding MAX_RESPONSE_BYTES
    fake_resp = MagicMock()
    # 6MB chunk
    fake_resp.read.side_effect = [b"A" * (6 * 1024 * 1024), b""]
    fake_resp.__enter__.return_value = fake_resp

    with patch("urllib.request.urlopen", return_value=fake_resp):
        with pytest.raises(ValueError, match="exceeded 5242880 bytes limit"):
            client._sync_fetch("https://services.nvd.nist.gov/fake")


@pytest.mark.asyncio
async def test_nvd_client_offline_fallback():
    db = DatabaseManager("sqlite:///:memory:")
    cache = VulnerabilityCache(db)
    client = AsyncNVDClient(cache=cache, offline_mode=True)

    # In offline mode, get_cve queries cache directly without network
    with patch("urllib.request.urlopen") as mock_url:
        item = await client.get_cve("CVE-2024-6387")
        assert item is not None
        assert item.cve_id == "CVE-2024-6387"
        mock_url.assert_not_called()


@pytest.mark.asyncio
async def test_nvd_client_network_error_graceful_fallback():
    db = DatabaseManager("sqlite:///:memory:")
    cache = VulnerabilityCache(db)
    client = AsyncNVDClient(cache=cache, offline_mode=False)

    # Simulate network failure during search_by_cpe
    with patch(
        "reconforge.intelligence.nvd_client.AsyncNVDClient._fetch_with_backoff", return_value=None
    ):
        results = await client.search_by_cpe("cpe:2.3:a:openssh:openssh:*:*:*:*:*:*:*:*")
        # Should gracefully fallback to cache results without throwing exception
        assert len(results) >= 2
        assert any(r.cve_id == "CVE-2024-6387" for r in results)
