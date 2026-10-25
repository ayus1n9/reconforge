"""Asynchronous token-bucket rate limiter for network probe throttling."""

import asyncio
import time


class AsyncTokenBucketRateLimiter:
    """
    Token-bucket rate limiter for throttling asynchronous operations.

    Ensures outbound probe frequency does not overwhelm local buffers or target networks.
    """

    def __init__(self, rate_per_second: int = 100, burst_capacity: int | None = None):
        self.rate = max(0, rate_per_second)
        self.capacity = float(burst_capacity if burst_capacity is not None else max(1, self.rate))
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a probe token is available, then consume it."""
        if self.rate <= 0:
            return  # Rate limiting disabled

        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.last_update = now

                # Replenish tokens based on elapsed time
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return

                # Calculate required sleep time to gain at least 1.0 token
                sleep_duration = (1.0 - self.tokens) / self.rate
                await asyncio.sleep(sleep_duration)
