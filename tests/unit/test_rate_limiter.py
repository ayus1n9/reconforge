"""Unit tests for AsyncTokenBucketRateLimiter."""

import time

import pytest

from reconforge.discovery.rate_limiter import AsyncTokenBucketRateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_unthrottled():
    limiter = AsyncTokenBucketRateLimiter(rate_per_second=0)
    start = time.monotonic()
    for _ in range(10):
        await limiter.acquire()
    duration = time.monotonic() - start
    assert duration < 0.1, "Zero rate limit should not throttle"


@pytest.mark.asyncio
async def test_rate_limiter_throttles():
    # 20 tokens per second with 2 initial capacity
    limiter = AsyncTokenBucketRateLimiter(rate_per_second=20, burst_capacity=2)
    start = time.monotonic()
    # Consume 4 tokens: first 2 are instant, next 2 require at least ~0.08 - 0.1s
    for _ in range(4):
        await limiter.acquire()
    duration = time.monotonic() - start
    assert duration >= 0.07, f"Rate limiter failed to throttle: took {duration}s"
