from __future__ import annotations

import asyncio
import time
from collections.abc import Callable


class RateLimiter:
    """Async token-bucket limiter shared across coroutines.

    `acquire()` blocks until a token is available. Concurrency and rate are
    different controls - this one caps rate; a semaphore caps concurrency.
    """

    def __init__(
        self,
        rate: float,
        burst: int | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self._rate = rate
        self._capacity = float(burst if burst is not None else max(1, int(rate)))
        self._tokens = self._capacity
        self._clock = clock
        self._updated = clock()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self._capacity, self._tokens + (now - self._updated) * self._rate)
        self._updated = now

    async def acquire(self) -> None:
        async with self._lock:
            self._refill()
            if self._tokens < 1:
                wait = (1 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._refill()
            self._tokens -= 1
