from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from capat import trace
from capat.core.discovery import find_captcha_image, find_inline_captcha
from capat.core.profile import (
    CaptchaChallenge,
    LoginProfile,
    Outcome,
    decode_image_payload,
    extract_hidden_fields,
)
from capat.core.throttle import raise_for_throttle, retry_after, throttled
from capat.http.client import HttpClient, Session
from capat.solvers.base import Solver, SolveResult


@dataclass(frozen=True, slots=True)
class Attempt:
    """One complete login round-trip: fetch form, fetch CAPTCHA, solve, submit."""

    outcome: Outcome
    status_code: int
    final_url: str
    solved: str = ""
    confidence: float = 0.0
    solve_seconds: float = 0.0
    captcha_sha256: str = ""
    challenge_id: str | None = None
    throttled: bool = False
    """The target asked us to slow down. Not a statement about the CAPTCHA."""

    retry_after: float | None = None


@dataclass(slots=True)
class Context:
    """What one attempt has gathered so far: hidden fields and named values."""

    hidden: dict[str, str] = field(default_factory=dict)
    values: dict[str, str] = field(default_factory=dict)
    captcha_url: str = ""
    """Set only under `"captcha_url": "auto"`: the URL this attempt's own login
    page advertised. Empty otherwise, where the URL is rendered instead."""

    captcha_image: bytes = b""
    """Set only under `"captcha_url": "base64"`: the challenge decoded straight
    out of this attempt's login page, since there is no endpoint to fetch."""


class LoginFlow:
    """Drives one login attempt end to end.

    Shared by every module so session handling, token extraction, CAPTCHA
    decoding, and request shaping exist once. Modules decide only what to
    submit and what to make of the answer.

    Everything variable about the target lives in the profile: the body
    encoding, extra headers, where tokens come from, and - when the structured
    fields are not enough - a raw body template.
    """

    def __init__(self, profile: LoginProfile, solver: Solver | None = None) -> None:
        self._profile = profile
        self._solver = solver

    async def fetch_form(self, session: Session) -> Context:
        """Prime the session, collect hidden fields, and run form extractors."""
        resp = await session.get(
            self._profile.page_url, headers=self._profile.static_headers() or None
        )
        # Before parsing: a limiter's short body has no form in it, and
        # "no hidden fields" would be a misleading way to say "slow down".
        raise_for_throttle(resp)
        hidden = extract_hidden_fields(resp.text)
        context = Context(hidden=hidden)
        if self._profile.discovers_captcha_url:
            # Read off this attempt's own page, and from the response already
            # in hand rather than a second request.
            found_url = find_captcha_image(resp.text, str(resp.url))
            if not found_url:
                raise ValueError(
                    f"'captcha_url': 'auto' found no CAPTCHA <img> on {self._profile.page_url}. "
                    "Give the endpoint with --captcha-url instead, using {{placeholders}} and "
                    "--extract if it carries a per-request value."
                )
            context.captcha_url = found_url
        elif self._profile.reads_inline_captcha:
            data_uri = find_inline_captcha(resp.text)
            if not data_uri:
                raise ValueError(
                    f"'captcha_url': 'base64' found no inline CAPTCHA <img> on "
                    f"{self._profile.page_url}. The page must carry a named "
                    '<img src="data:image/...;base64,...">.'
                )
            context.captcha_image = decode_image_payload(data_uri)
        for extractor in self._profile.extract:
            if extractor.from_ == "form":
                found = extractor.apply(resp, hidden)
                context.values[extractor.name] = found or ""
        return context

    def captcha_url_for(self, context: Context) -> str:
        """The challenge URL this attempt will request.

        Resolved per attempt, from what the attempt has read, so a URL
        carrying a per-request nonce is never re-requested stale. Under
        `base64` there is no request, so the login page is what is named.
        """
        if self._profile.reads_inline_captcha:
            return self._profile.page_url
        if self._profile.discovers_captcha_url:
            if not context.captcha_url:
                raise RuntimeError(
                    "fetch_form must run before fetch_captcha when captcha_url is 'auto'"
                )
            return context.captcha_url
        return self._profile.render_captcha_url(context.values)

    async def fetch_captcha(self, session: Session, context: Context) -> CaptchaChallenge:
        if self._profile.reads_inline_captcha:
            # Already in hand: fetch_form decoded it out of the page. Issuing a
            # request here would fetch the page a second time and measure a
            # challenge the attempt is not going to answer.
            if not context.captcha_image:
                raise RuntimeError(
                    "fetch_form must run before fetch_captcha when captcha_url is 'base64'"
                )
            return CaptchaChallenge(image=context.captcha_image)

        url = self.captcha_url_for(context)
        resp = await session.request(
            self._profile.captcha_method,
            url,
            headers={**self._profile.static_headers(), **self._profile.captcha_headers} or None,
        )
        # Before parse_captcha, which would otherwise report a limiter's JSON
        # body as an unreadable CAPTCHA endpoint - blaming the operator's
        # configuration for a control the target is exercising correctly.
        raise_for_throttle(resp)
        for extractor in self._profile.extract:
            if extractor.from_ == "captcha":
                found = extractor.apply(resp, context.hidden)
                context.values[extractor.name] = found or ""
        challenge = self._profile.parse_captcha(
            resp.content, resp.headers.get("content-type", ""), resp.status_code, url=url
        )
        trace.challenge(url, resp)
        return challenge

    async def solve(self, image: bytes) -> SolveResult:
        if self._solver is None:
            raise RuntimeError("this flow needs a solver")
        return await self._solver.solve(image)

    async def submit(
        self,
        session: Session,
        username: str,
        password: str,
        captcha: str,
        context: Context | None = None,
        challenge_id: str | None = None,
        omit_captcha: bool = False,
    ) -> httpx.Response:
        context = context or Context()
        values = {
            **context.values,
            "username": username,
            "password": password,
            "captcha": captcha,
            "captcha_id": challenge_id or "",
        }
        kwargs = self._profile.build_request(values, context.hidden, omit_captcha=omit_captcha)
        url = self._profile.render_login_url(values)
        resp = await session.request(self._profile.method, url, **kwargs)
        if trace.enabled():
            trace.attempt(
                username,
                password,
                "" if omit_captcha else captcha,
                resp,
                self.classify(resp),
            )
        return resp

    def classify(self, resp: httpx.Response) -> Outcome:
        return self._profile.criteria.classify(resp)

    async def attempt(
        self,
        client: HttpClient,
        username: str,
        password: str,
        *,
        answer: str | None = None,
        fetch_challenge: bool = True,
        omit_captcha: bool = False,
    ) -> Attempt:
        """A full attempt in its own session.

        A challenge is requested unless `fetch_challenge` is False, so that the
        enforcement checks submit a bad answer against a genuinely issued
        challenge - otherwise "empty answer accepted" could not be told apart
        from "no challenge was pending". `answer=None` means solve the image;
        anything else is submitted verbatim.
        """
        async with client.session() as session:
            context = await self.fetch_form(session)
            challenge: CaptchaChallenge | None = None
            confidence, seconds = 0.0, 0.0

            if fetch_challenge:
                challenge = await self.fetch_captcha(session, context)

            if answer is None:
                if challenge is None:
                    raise ValueError("cannot solve without fetching a challenge")
                result = await self.solve(challenge.image)
                answer, confidence, seconds = result.text, result.confidence, result.elapsed

            resp = await self.submit(
                session,
                username,
                password,
                answer,
                context,
                challenge_id=challenge.challenge_id if challenge else None,
                omit_captcha=omit_captcha,
            )
            return Attempt(
                outcome=self.classify(resp),
                status_code=resp.status_code,
                final_url=str(resp.url),
                solved=answer,
                confidence=confidence,
                solve_seconds=seconds,
                captcha_sha256=challenge.sha256[:16] if challenge else "",
                challenge_id=challenge.challenge_id if challenge else None,
                throttled=throttled(resp),
                retry_after=retry_after(resp),
            )
