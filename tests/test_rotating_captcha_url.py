"""Targets that mint a fresh CAPTCHA URL on every page load.

Discovery runs once, at startup, so the URL it finds used to become a constant
for the whole run. Against an application that puts a per-load nonce or id in
`<img src>` - `capture_qw23`, then `capture_ew34` - every attempt then
re-requested one stale challenge, and the gate check reported a HIGH "CAPTCHA
image never changes" against a target that was doing nothing wrong.

These tests pin the three parts of the fix: URLs are rendered per attempt,
`"captcha_url": "auto"` re-reads the URL from each login page, and a rotation
result that only measured our own repeated request no longer claims the
challenge is static.
"""

from __future__ import annotations

import base64
import itertools

import httpx
import pytest
import respx

from capat.core.discovery import find_captcha_image, find_inline_captcha
from capat.core.profile import LoginProfile
from capat.core.result import Severity
from capat.core.target import Target
from capat.http.client import HttpClient
from capat.modules.gate_enforcement import CaptchaGate
from capat.modules.login_flow import LoginFlow
from tests.conftest import CONFIG

TARGET = Target("https://app.example.test/login")
CRITERIA = {
    "captcha_failure": ["invalid captcha"],
    "auth_failure": ["invalid username or password"],
    "success": ["welcome back"],
}


def login_page(n: int) -> str:
    """A login page whose challenge id changes on every load, as seen in the wild."""
    return (
        '<form><input type="hidden" name="_token" value="t0k"></form>'
        f'<img id="capture_qw{n}" src="/captcha?n=nonce{n}">'
    )


def mount_rotating_page() -> list[str]:
    """Serve a fresh login page per GET; return the list the CAPTCHA route fills."""
    pages = itertools.count(1)
    requested: list[str] = []

    def page(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=login_page(next(pages)))

    def challenge(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(
            200, content=f"png-{len(requested)}".encode(), headers={"content-type": "image/png"}
        )

    respx.get("https://app.example.test/login").mock(side_effect=page)
    respx.route(method="GET", host="app.example.test", path="/captcha").mock(side_effect=challenge)
    return requested


def profile_with(captcha_url: str, **extra: object) -> LoginProfile:
    return LoginProfile.from_dict(
        {
            "login_url": "https://app.example.test/login",
            "captcha_url": captcha_url,
            "criteria": CRITERIA,
            **extra,
        }
    )


async def two_attempts(profile: LoginProfile) -> None:
    """Fetch the form and the challenge twice, in a fresh session each time."""
    flow = LoginFlow(profile, solver=None)
    async with HttpClient(CONFIG) as client:
        for _ in range(2):
            async with client.session() as session:
                context = await flow.fetch_form(session)
                await flow.fetch_captcha(session, context)


# --- rendering ------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_a_captcha_url_placeholder_is_rendered_on_every_attempt():
    """Without this the nonce read from the first page load is frozen for the
    whole run: every later attempt re-requests one stale challenge, and the
    identical images that come back are read as a static CAPTCHA."""
    requested = mount_rotating_page()
    await two_attempts(
        profile_with(
            "https://app.example.test/captcha?n={{nonce}}",
            extract=[{"name": "nonce", "source": "regex", "key": r'/captcha\?n=([^"]+)'}],
        )
    )
    assert requested == [
        "https://app.example.test/captcha?n=nonce1",
        "https://app.example.test/captcha?n=nonce2",
    ]


@respx.mock
@pytest.mark.asyncio
async def test_auto_reads_the_challenge_url_off_each_login_page():
    """The no-configuration path for a URL that is unpredictable rather than
    derivable: the operator writes `-c auto` instead of a regex."""
    requested = mount_rotating_page()
    await two_attempts(profile_with("auto"))
    assert requested == [
        "https://app.example.test/captcha?n=nonce1",
        "https://app.example.test/captcha?n=nonce2",
    ]


@respx.mock
@pytest.mark.asyncio
async def test_auto_says_so_when_the_page_has_no_captcha_image():
    """Silently falling back to some other URL would sample the wrong image."""
    respx.get("https://app.example.test/login").mock(
        return_value=httpx.Response(200, text="<form></form>")
    )
    with pytest.raises(ValueError, match="found no CAPTCHA"):
        await two_attempts(profile_with("auto"))


# --- load-time validation -------------------------------------------------


def test_a_url_placeholder_the_attempt_cannot_fill_is_refused_at_load_time():
    """A `{{token}}` in a URL used to pass validation and then go out to the
    target as literal text, because only bodies and headers were checked."""
    with pytest.raises(ValueError, match=r"captcha_url uses unknown placeholder\(s\) token"):
        profile_with("https://app.example.test/captcha?t={{token}}")


def test_a_captcha_url_cannot_use_a_value_read_from_the_captcha_response():
    """Ordering, not spelling: the name exists, but not until after the very
    request that would need it."""
    with pytest.raises(ValueError, match="only extractors reading the form"):
        profile_with(
            "https://app.example.test/captcha?t={{sid}}",
            extract=[{"name": "sid", "source": "json", "key": "id", "from": "captcha"}],
        )


def test_the_form_page_url_cannot_use_a_placeholder_at_all():
    """It is the first request of an attempt; nothing has been read yet."""
    with pytest.raises(ValueError, match="first request of an attempt"):
        profile_with(
            "https://app.example.test/captcha",
            form_url="https://app.example.test/login/{{token}}",
            extract=[{"name": "token", "source": "hidden", "key": "_token"}],
        )


# --- the finding ----------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_a_per_load_url_is_not_reported_as_a_static_challenge():
    """The false HIGH this whole change exists to remove. Asking one frozen URL
    five times proves only that we asked one frozen URL five times; the login
    page offering a different URL each load is the evidence that says so."""
    mount_rotating_page()
    respx.route(method="GET", host="app.example.test", path="/captcha").mock(
        return_value=httpx.Response(
            200, content=b"png-stale", headers={"content-type": "image/png"}
        )
    )
    respx.post("https://app.example.test/login").mock(
        return_value=httpx.Response(200, text="Invalid CAPTCHA")
    )

    frozen = profile_with("https://app.example.test/captcha?n=nonce1")
    async with HttpClient(CONFIG) as client:
        findings = await CaptchaGate(frozen, solver=None, rotation_samples=3).run(TARGET, client)

    rotation = [f for f in findings if "CAPTCHA" in f.title and "rotation" in f.title]
    assert len(rotation) == 1, [f.title for f in findings]
    assert rotation[0].severity is Severity.INFO
    assert not any("never changes" in f.title for f in findings)
    assert rotation[0].evidence["requested_url"].endswith("n=nonce1")
    assert rotation[0].evidence["page_now_offers"] != rotation[0].evidence["requested_url"]
    assert "-c auto" in rotation[0].remediation


# --- inline base64, where there is no endpoint at all ---------------------


def inline_page(n: int, png: bytes) -> str:
    """A login page carrying the challenge itself, as most SPAs now do."""
    payload = base64.b64encode(png).decode("ascii")
    return (
        '<form><input type="hidden" name="_token" value="t0k"></form>'
        f'<img id="captchaImage" src="data:image/png;base64,{payload}">'
    )


@respx.mock
@pytest.mark.asyncio
async def test_base64_reads_the_challenge_out_of_the_page(png_bytes):
    """No endpoint exists, so the bytes have to come from the page the attempt
    already fetched - and a second request would fetch a challenge the attempt
    is never going to answer."""
    pages = itertools.count(1)
    respx.get("https://app.example.test/login").mock(
        side_effect=lambda r: httpx.Response(
            200, text=inline_page(next(pages), png_bytes + str(next(pages)).encode())
        )
    )
    endpoint = respx.route(method="GET", host="app.example.test", path="/captcha").mock(
        return_value=httpx.Response(200, content=b"never")
    )

    seen: list[str] = []
    flow = LoginFlow(profile_with("base64"), solver=None)
    async with HttpClient(CONFIG) as client:
        for _ in range(2):
            async with client.session() as session:
                context = await flow.fetch_form(session)
                seen.append((await flow.fetch_captcha(session, context)).sha256)

    assert not endpoint.called, "base64 mode must not request a CAPTCHA endpoint"
    assert len(set(seen)) == 2, "each page load is a fresh challenge"


@respx.mock
@pytest.mark.asyncio
async def test_base64_says_so_when_the_page_carries_no_inline_image():
    """Falling back to some other image would measure the wrong thing."""
    respx.get("https://app.example.test/login").mock(
        return_value=httpx.Response(200, text='<img id="captcha" src="/captcha.png">')
    )
    flow = LoginFlow(profile_with("base64"), solver=None)
    with pytest.raises(ValueError, match="found no inline CAPTCHA"):
        async with HttpClient(CONFIG) as client, client.session() as session:
            await flow.fetch_form(session)


def test_base64_refuses_settings_that_describe_a_response_it_never_gets():
    """`captcha_id_key` and an `@captcha` extractor both read a CAPTCHA
    response. Under base64 no such request happens, so accepting them would
    leave the operator waiting on an id that can never arrive."""
    with pytest.raises(ValueError, match="needs a CAPTCHA endpoint"):
        profile_with("base64", captcha_id_key="data.id", captcha_id_field="cid")
    with pytest.raises(ValueError, match="no such request is made"):
        profile_with(
            "base64",
            extract=[{"name": "sid", "source": "json", "key": "id", "from": "captcha"}],
        )


def test_discovery_separates_an_inline_challenge_from_a_fetchable_one():
    """The two need different strategies, so one must not be mistaken for the
    other: a data: URI has no URL to sample, and a URL has no bytes to decode."""
    inline = '<img id="captchaImage" src="data:image/png;base64,iVBORw0KGgo=">'
    assert find_captcha_image(inline, "https://h/login") is None
    assert find_inline_captcha(inline).startswith("data:image/png;base64,")

    fetchable = '<img id="captchaImage" src="/c.png">'
    assert find_inline_captcha(fetchable) is None
    assert find_captcha_image(fetchable, "https://h/login") == "https://h/c.png"
