"""Corpus collection: fetch challenges, never authenticate."""

from __future__ import annotations

import base64
import io

import httpx
import pytest
import respx
from PIL import Image

from capat.collector import CorpusCollector, image_suffix
from capat.core.profile import LoginProfile
from capat.http.client import HttpClient
from tests.conftest import CONFIG


def png(colour: str = "white") -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (20, 10), colour).save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
async def client():
    async with HttpClient(CONFIG) as c:
        yield c


@pytest.fixture
def profile():
    return LoginProfile(
        login_url="https://app.example.test/login",
        captcha_url="https://app.example.test/captcha.png",
    )


def test_image_suffix_detects_formats():
    assert image_suffix(png()) == ".png"
    assert image_suffix(b"\xff\xd8\xff\xe0rest") == ".jpg"
    assert image_suffix(b"GIF89a") == ".gif"
    assert image_suffix(b"unknown") == ".png"


@respx.mock
@pytest.mark.asyncio
async def test_collects_without_ever_posting(profile, client, tmp_path):
    """The whole point: no login attempt, so nothing can lock out."""
    respx.get("https://app.example.test/login").mock(return_value=httpx.Response(200, text=""))
    counter = {"n": 0}

    def fresh(request):
        counter["n"] += 1
        shade = f"#{counter['n']:02x}0000"
        return httpx.Response(200, content=png(shade))

    respx.get("https://app.example.test/captcha.png").mock(side_effect=fresh)
    posted = respx.post("https://app.example.test/login").mock(return_value=httpx.Response(200))

    report = await CorpusCollector(profile, tmp_path).collect(client, count=5)

    assert len(report.saved) == 5
    assert not posted.called, "collection must never submit a login"
    assert all(p.read_bytes().startswith(b"\x89PNG") for p in report.saved)


@respx.mock
@pytest.mark.asyncio
async def test_identical_images_are_counted_not_saved_twice(profile, client, tmp_path):
    respx.get("https://app.example.test/login").mock(return_value=httpx.Response(200, text=""))
    respx.get("https://app.example.test/captcha.png").mock(
        return_value=httpx.Response(200, content=png())
    )

    report = await CorpusCollector(profile, tmp_path).collect(client, count=4)

    assert len(report.saved) == 1
    assert report.duplicates == 3


@respx.mock
@pytest.mark.asyncio
async def test_failures_are_counted_and_do_not_abort(profile, client, tmp_path):
    respx.get("https://app.example.test/login").mock(return_value=httpx.Response(200, text=""))
    responses = [
        httpx.Response(500),
        httpx.Response(200, content=png("red")),
        httpx.Response(200, content=b""),
    ]
    respx.get("https://app.example.test/captcha.png").mock(side_effect=responses)

    report = await CorpusCollector(profile, tmp_path).collect(client, count=3)

    # Both the 500 (no body) and the empty 200 fail to parse; the good one
    # in between is still saved, so one bad fetch cannot end the run.
    assert len(report.saved) == 1
    assert report.failed == 2


@respx.mock
@pytest.mark.asyncio
async def test_json_endpoint_images_are_decoded(client, tmp_path):
    profile = LoginProfile(
        login_url="https://app.example.test/login",
        captcha_url="https://app.example.test/api/captcha",
        captcha_response="json",
        captcha_image_key="data.image",
        captcha_id_key="data.id",
        captcha_id_field="captcha_id",
    )
    respx.get("https://app.example.test/login").mock(return_value=httpx.Response(200, text=""))
    respx.get("https://app.example.test/api/captcha").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"id": "c1", "image": base64.b64encode(png()).decode()}},
        )
    )

    report = await CorpusCollector(profile, tmp_path).collect(client, count=1)
    assert report.saved[0].read_bytes() == png()


@respx.mock
@pytest.mark.asyncio
async def test_a_failed_fetch_records_why_not_just_that_it_failed(profile, client, tmp_path):
    """A count alone makes every cause look identical.

    A typo in -c, a certificate the client would not verify and a 404 all
    reached the operator as "3 fetch(es) failed" - no reason, no hint, and
    then instructions to go and label an empty directory. `collect` is
    usually pointed at an unfamiliar host, so the reason is the message.
    """
    respx.get("https://app.example.test/login").mock(return_value=httpx.Response(200, text=""))
    respx.get("https://app.example.test/captcha.png").mock(
        side_effect=httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate")
    )

    report = await CorpusCollector(profile, tmp_path).collect(client, count=3)

    assert report.saved == []
    assert report.failed == 3
    # Three identical failures, one line about them.
    assert len(report.failures) == 1
    assert "CERTIFICATE_VERIFY_FAILED" in report.failures[0]
