"""Parsing the two CAPTCHA endpoint styles.

The classic style serves a raw image bound to the session cookie. The
stateless style returns JSON with a base64 image and an identifier that the
login request must carry back - the identifier *is* the binding there, so
getting it wrong breaks every attempt silently.
"""

from __future__ import annotations

import base64
import io

import pytest
from PIL import Image

from capat.core.profile import (
    CaptchaChallenge,
    LoginProfile,
    decode_image_payload,
    dig,
)


def png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (30, 12), "white").save(buf, format="PNG")
    return buf.getvalue()


def json_profile(**overrides: object) -> LoginProfile:
    base = {
        "login_url": "https://app.example.test/api/login",
        "captcha_url": "https://app.example.test/api/captcha",
        "captcha_response": "json",
        "captcha_image_key": "data.image",
        "captcha_id_key": "data.id",
        "captcha_id_field": "captcha_id",
    }
    base.update(overrides)
    return LoginProfile.from_dict(base)


# --- dotted path lookup ---------------------------------------------------


def test_dig_walks_nested_objects_and_lists():
    data = {"a": {"b": [{"c": "found"}]}}
    assert dig(data, "a.b.0.c") == "found"
    assert dig(data, "a.b.9.c") is None
    assert dig(data, "a.missing") is None
    assert dig(data, "a.b.c.d") is None


# --- base64 decoding ------------------------------------------------------


def test_decodes_plain_base64():
    assert decode_image_payload(base64.b64encode(png()).decode()) == png()


def test_decodes_data_uri_prefix():
    encoded = "data:image/png;base64," + base64.b64encode(png()).decode()
    assert decode_image_payload(encoded) == png()


def test_decodes_despite_wrapped_whitespace():
    raw = base64.b64encode(png()).decode()
    wrapped = "\n".join(raw[i : i + 40] for i in range(0, len(raw), 40))
    assert decode_image_payload(wrapped) == png()


def test_decodes_urlsafe_alphabet_and_missing_padding():
    payload = b"\xfb\xff\xbe\xff\xfe"
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    assert decode_image_payload(encoded) == payload


def test_empty_image_field_is_rejected():
    with pytest.raises(ValueError, match="empty"):
        decode_image_payload("   ")


# --- response parsing -----------------------------------------------------


def test_json_response_yields_image_and_id():
    body = (
        b'{"status":"ok","data":{"id":"ch-42","image":"data:image/png;base64,'
        + base64.b64encode(png())
        + b'"}}'
    )
    challenge = json_profile().parse_captcha(body, "application/json")
    assert isinstance(challenge, CaptchaChallenge)
    assert challenge.image == png()
    assert challenge.challenge_id == "ch-42"


def test_numeric_ids_become_strings():
    body = b'{"data":{"id":90210,"image":"' + base64.b64encode(png()) + b'"}}'
    assert json_profile().parse_captcha(body).challenge_id == "90210"


def test_raw_image_response_has_no_id():
    profile = LoginProfile(
        login_url="https://app.example.test/login",
        captcha_url="https://app.example.test/captcha.png",
    )
    challenge = profile.parse_captcha(png(), "image/png")
    assert challenge.image == png()
    assert challenge.challenge_id is None
    assert not profile.uses_challenge_id


def test_json_served_to_an_image_profile_says_what_to_fix():
    profile = LoginProfile(
        login_url="https://app.example.test/login",
        captcha_url="https://app.example.test/api/captcha",
    )
    with pytest.raises(ValueError, match='"captcha_response": "json"'):
        profile.parse_captcha(b'{"image":"abc"}', "application/json")


def test_wrong_image_key_names_the_available_keys():
    body = b'{"payload":"...","token":"..."}'
    with pytest.raises(ValueError, match="payload, token"):
        json_profile().parse_captcha(body)


def test_missing_id_is_reported():
    body = b'{"data":{"image":"' + base64.b64encode(png()) + b'"}}'
    with pytest.raises(ValueError, match="no challenge id"):
        json_profile().parse_captcha(body)


def test_non_json_body_is_reported():
    with pytest.raises(ValueError, match="did not return valid JSON"):
        json_profile().parse_captcha(b"<html>nope</html>", "text/html")


def test_empty_image_body_is_reported():
    profile = LoginProfile(
        login_url="https://app.example.test/login",
        captcha_url="https://app.example.test/captcha.png",
    )
    with pytest.raises(ValueError, match="empty body"):
        profile.parse_captcha(b"")


# --- payload construction -------------------------------------------------


def test_challenge_id_is_submitted_in_its_configured_field():
    payload = json_profile().build_payload("u", "p", "A8R36", None, "ch-42")
    assert payload["captcha_id"] == "ch-42"
    assert payload["captcha"] == "A8R36"


def test_no_id_field_appears_for_session_bound_captchas():
    profile = LoginProfile(
        login_url="https://app.example.test/login",
        captcha_url="https://app.example.test/captcha.png",
    )
    assert "captcha_id" not in profile.build_payload("u", "p", "A8R36")


# --- configuration guards -------------------------------------------------


def test_reading_an_id_without_sending_it_back_is_rejected():
    """Silently dropping the identifier would fail every attempt."""
    with pytest.raises(ValueError, match="must be set together"):
        LoginProfile.from_dict(
            {
                "login_url": "https://app.example.test/login",
                "captcha_url": "https://app.example.test/api/captcha",
                "captcha_response": "json",
                "captcha_id_key": "data.id",
            }
        )


def test_sending_an_id_that_is_never_read_is_rejected():
    with pytest.raises(ValueError, match="must be set together"):
        LoginProfile.from_dict(
            {
                "login_url": "https://app.example.test/login",
                "captcha_url": "https://app.example.test/api/captcha",
                "captcha_response": "json",
                "captcha_id_field": "captcha_id",
            }
        )


def test_id_key_requires_json_mode():
    with pytest.raises(ValueError, match="captcha_response='json'"):
        LoginProfile.from_dict(
            {
                "login_url": "https://app.example.test/login",
                "captcha_url": "https://app.example.test/captcha.png",
                "captcha_id_key": "id",
                "captcha_id_field": "captcha_id",
            }
        )


def test_unknown_response_style_is_rejected():
    with pytest.raises(ValueError, match="must be 'image' or 'json'"):
        LoginProfile.from_dict(
            {
                "login_url": "https://app.example.test/login",
                "captcha_url": "https://app.example.test/c",
                "captcha_response": "xml",
            }
        )


def test_an_unreadable_endpoint_quotes_what_it_actually_answered():
    """A gateway that interposes a block page must be recognisable as one.

    The endpoint is the part of a run that can start answering differently
    halfway through. "did not return valid JSON" alone forces a re-run to
    find out what happened; the status and a short quote do not.
    """
    block_page = (
        b"<html><head><title>Request Rejected</title></head><body>Support ID: 1234</body></html>"
    )
    with pytest.raises(ValueError) as exc:
        json_profile().parse_captcha(block_page, "text/html", 403)

    message = str(exc.value)
    assert "HTTP 403" in message
    assert "Request Rejected" in message
    assert "text/html" in message


def test_the_quoted_excerpt_stays_short():
    with pytest.raises(ValueError) as exc:
        json_profile().parse_captcha(b"x" * 5000, "text/html", 200)
    assert len(str(exc.value)) < 500
