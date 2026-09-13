from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from http.cookies import SimpleCookie
from types import TracebackType
from typing import Any

import httpx

from capat.core.config import Config
from capat.http.rate_limiter import RateLimiter

_RETRYABLE = (httpx.TransportError, httpx.TimeoutException)


class Session:
    """One cookie-isolated conversation with the target.

    CAPTCHA answers are bound to a session server-side. If every worker shared
    one cookie jar they would overwrite each other's pending answer and the
    measurement would report failures that are the tool's own fault. Each
    attempt therefore gets its own session; rate limiting stays shared and
    global.
    """

    def __init__(self, config: Config, limiter: RateLimiter) -> None:
        self._config = config
        self._limiter = limiter
        self._client = httpx.AsyncClient(
            timeout=config.timeout,
            verify=config.verify_tls,
            follow_redirects=config.follow_redirects,
            headers={"User-Agent": config.user_agent},
            proxy=config.proxy,
        )

    def _absorb_cookie_header(self, kwargs: dict[str, Any]) -> None:
        """Move an operator-supplied `Cookie:` header into this session's jar.

        httpx lets an explicit `Cookie` header win outright: it is not merged
        with the jar, it replaces it. So `-b 'sess=abc'` - which exists for
        targets that refuse to serve a login page without one - silently
        dropped the application's own session cookie from every request after
        the first. Each attempt then landed in a fresh server-side session, the
        pending CAPTCHA answer was never found, and the run reported a 0% solve
        rate and blamed the operator's solver settings. A broken measurement
        that reads as "the CAPTCHA held" is the one failure this tool must not
        have.

        Re-applied on every request rather than once at construction, so the
        operator's value stays authoritative if the target sets a cookie of the
        same name.
        """
        headers = kwargs.get("headers")
        if not isinstance(headers, Mapping):
            return
        remaining = {k: v for k, v in headers.items() if k.lower() != "cookie"}
        if len(remaining) == len(headers):
            return
        for key, value in headers.items():
            if key.lower() != "cookie":
                continue
            jar = SimpleCookie()
            jar.load(value)
            for name, morsel in jar.items():
                # Domain-less so it rides on every host the run touches, which
                # is what someone pasting a cookie off a browser expects.
                self._client.cookies.set(name, morsel.value)
        kwargs["headers"] = remaining or None

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        self._absorb_cookie_header(kwargs)
        last_exc: Exception | None = None
        for attempt in range(self._config.retries + 1):
            await self._limiter.acquire()
            try:
                resp = await self._client.request(method, url, **kwargs)
            except _RETRYABLE as exc:
                last_exc = exc
                await asyncio.sleep(min(8.0, 0.5 * (2**attempt)))
                continue
            return resp
        assert last_exc is not None
        raise last_exc

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()


class HttpClient:
    """Factory for sessions plus the shared rate limiter.

    Modules receive an instance of this - they never build an httpx client
    themselves, so defaults and guardrails live in exactly one place.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._limiter = RateLimiter(config.requests_per_second)
        self._default = Session(config, self._limiter)

    @asynccontextmanager
    async def session(self) -> AsyncIterator[Session]:
        """A fresh cookie jar for one login attempt."""
        session = Session(self._config, self._limiter)
        try:
            yield session
        finally:
            await session.aclose()

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Stateless request on the shared session."""
        return await self._default.get(url, **kwargs)

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._default.aclose()
