"""A run must not report a check it could not finish as a clean result.

Three ways that used to happen, each pinned here:

- an operator cookie (`-b`) suppressed the target's own session cookie, so
  every attempt landed in a fresh server-side session and the tool printed a
  0% solve rate that measured nothing but its own broken plumbing;
- a module that raised was logged at WARNING and dropped, leaving the report
  saying "no findings" and exiting 0 about a check that never ran;
- a page carrying its CAPTCHA as a `data:` URI was answered with "no CAPTCHA
  image found ... take the URL from the browser's network tab", sending the
  operator after a URL that does not exist instead of naming `-c base64`.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from capat.cli import discover_captcha_url
from capat.core.engine import Engine
from capat.core.result import Finding, Severity
from capat.core.target import Target
from capat.http.client import HttpClient
from capat.modules.base import Module
from tests.conftest import CONFIG

LOGIN_URL = "https://app.example.test/login"


@respx.mock
async def test_an_operator_cookie_does_not_evict_the_targets_session_cookie() -> None:
    """`-b` arrives as a Cookie header, and httpx lets that header replace the
    jar outright rather than merge with it. The application's own session
    cookie was therefore dropped from every request after the first, the
    pending CAPTCHA answer was never found, and the measurement came out at 0%
    while blaming the operator's solver settings."""
    seen: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("cookie", ""))
        return httpx.Response(200, headers={"set-cookie": "sid=server-side; Path=/"})

    respx.get(LOGIN_URL).mock(side_effect=record)

    async with HttpClient(CONFIG) as client, client.session() as session:
        await session.get(LOGIN_URL, headers={"Cookie": "sess=abc"})
        await session.get(LOGIN_URL, headers={"Cookie": "sess=abc"})

    assert "sess=abc" in seen[0]
    # The second request must carry both: the operator's cookie and the one
    # the application set in reply to the first.
    assert "sess=abc" in seen[1], "operator cookie lost once the jar filled"
    assert "sid=server-side" in seen[1], "target session cookie evicted by -b"


@respx.mock
async def test_a_cookie_header_is_not_sent_twice() -> None:
    """Folding the header into the jar must not also leave the header in place,
    or the target sees a duplicated Cookie and may reject the request."""
    seen: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("cookie", ""))
        return httpx.Response(200)

    respx.get(LOGIN_URL).mock(side_effect=record)
    async with HttpClient(CONFIG) as client, client.session() as session:
        await session.get(LOGIN_URL, headers={"Cookie": "a=1; b=2"})

    assert seen[0].count("a=1") == 1
    assert "b=2" in seen[0]


class _Exploding(Module):
    name = "exploding"
    description = "raises, to prove the engine reports it"

    async def run(self, target: Target, client: HttpClient) -> list[Finding]:
        raise RuntimeError("captcha endpoint returned HTML")


class _Quiet(Module):
    name = "quiet"
    description = "returns nothing, like a module whose checks all passed"

    async def run(self, target: Target, client: HttpClient) -> list[Finding]:
        return []


async def test_a_module_that_crashes_becomes_a_finding_not_a_silent_warning() -> None:
    """Isolating a module failure must not launder it into a clean bill of
    health. Without this the run printed "no findings" and exited 0 after a
    check that never ran - the same defect as a false CRITICAL, reversed."""
    engine = Engine(CONFIG, [_Exploding(), _Quiet()])
    findings = await engine.run([LOGIN_URL])

    assert len(findings) == 1
    crash = findings[0]
    assert crash.module == "exploding"
    assert crash.severity is Severity.INFO
    assert "RuntimeError" in crash.title
    assert "captcha endpoint returned HTML" in crash.description
    # It must read as a gap in the run, never as a result about the target.
    assert "not as a control that held" in crash.description


async def test_a_crash_names_the_module_it_came_from() -> None:
    """gather() returns results positionally; pairing them back to the module
    is what lets the finding say which check died."""
    engine = Engine(CONFIG, [_Quiet(), _Exploding()])
    findings = await engine.run([LOGIN_URL])
    assert [f.module for f in findings] == ["exploding"]


@respx.mock
def test_an_inline_captcha_page_is_told_to_use_c_base64() -> None:
    """The page has the challenge, just not as an endpoint. Answering with
    "take the URL from the browser's network tab" sends the operator after a
    URL that does not exist, when -c base64 already handles this page."""
    respx.get(LOGIN_URL).mock(
        return_value=httpx.Response(
            200,
            html='<img id="captcha" src="data:image/png;base64,iVBORw0KGgo=">',
        )
    )
    with pytest.raises(ValueError) as exc:
        discover_captcha_url(CONFIG, LOGIN_URL)

    assert "-c base64" in str(exc.value)
    assert "network tab" not in str(exc.value)


@respx.mock
def test_a_page_with_no_captcha_at_all_still_asks_for_the_endpoint() -> None:
    """The base64 hint must not swallow the ordinary "I could not find it"
    message for a page that genuinely has no challenge on it."""
    respx.get(LOGIN_URL).mock(return_value=httpx.Response(200, html="<img src=/logo.png>"))
    with pytest.raises(ValueError) as exc:
        discover_captcha_url(CONFIG, LOGIN_URL)

    assert "--captcha-url" in str(exc.value)
    assert "-c base64" not in str(exc.value)


def test_a_finding_naming_a_pip_extra_still_names_it_after_rendering() -> None:
    """rich reads `[...]` as a style tag, so the table view silently swallowed
    the only useful token in "pip install \"capat[ddddocr]\"" and told an
    operator with no OCR engine to install the package they already had. A
    discovered password containing a bracket was mangled the same way."""
    import io

    from capat.reporting.reporter import Reporter

    buf = io.StringIO()
    findings = [
        Finding(
            module="captcha-solve-rate",
            title="valid credentials found: admin:p[ass]word",
            target=LOGIN_URL,
            severity=Severity.INFO,
            description='ddddocr is not installed; install it with: pip install "capat[ddddocr]"',
            remediation='or pip install "capat[all-solvers]"',
        )
    ]
    Reporter(stream=buf).render(findings, "table")
    out = buf.getvalue()

    assert "capat[ddddocr]" in out, "rich ate the extra the operator has to type"
    assert "capat[all-solvers]" in out
    assert "p[ass]word" in out, "a bracket in a password must survive the report"
