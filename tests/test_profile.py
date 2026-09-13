import httpx
import pytest

from capat.core.profile import (
    LoginProfile,
    Outcome,
    SuccessCriteria,
    extract_hidden_fields,
)


def resp(text="", url="https://x.test/login", status=200, **kw):
    return httpx.Response(status, text=text, request=httpx.Request("POST", url), **kw)


CRITERIA = SuccessCriteria(
    captcha_failure=["invalid captcha"],
    auth_failure=["invalid username or password"],
    success=["welcome back"],
    success_url_contains="/dashboard",
)


def test_classifies_captcha_failure_distinctly_from_auth_failure():
    assert CRITERIA.classify(resp("Invalid CAPTCHA")) is Outcome.CAPTCHA_FAILURE
    assert CRITERIA.classify(resp("Invalid username or password")) is Outcome.AUTH_FAILURE


def test_redirect_to_success_url_wins():
    assert CRITERIA.classify(resp(url="https://x.test/dashboard")) is Outcome.SUCCESS


def test_unmatched_response_is_unknown():
    assert CRITERIA.classify(resp("something else")) is Outcome.UNKNOWN


def test_is_usable_requires_both_failure_markers():
    assert CRITERIA.is_usable()
    assert not SuccessCriteria(captcha_failure=["a"]).is_usable()
    assert not SuccessCriteria().is_usable()


def test_probe_username_defaults_to_random_nonexistent_identity():
    a = LoginProfile(login_url="https://x.test/l", captcha_url="https://x.test/c")
    b = LoginProfile(login_url="https://x.test/l", captcha_url="https://x.test/c")
    assert a.probe_username.startswith("cb-probe-")
    assert a.probe_username != b.probe_username
    assert a.username == ""


def test_build_payload_includes_csrf_from_hidden_fields():
    profile = LoginProfile(
        login_url="https://x.test/l",
        captcha_url="https://x.test/c",
        csrf_field="_token",
    )
    payload = profile.build_payload("u", "p", "ABC", {"_token": "t0k", "other": "ignored"})
    assert payload == {"username": "u", "password": "p", "captcha": "ABC", "_token": "t0k"}


def test_extract_hidden_fields():
    html = (
        '<form><input type="hidden" name="_token" value="abc123">'
        '<input type="text" name="username"></form>'
    )
    assert extract_hidden_fields(html) == {"_token": "abc123"}


def test_unknown_profile_key_is_rejected():
    with pytest.raises(ValueError, match="unknown profile keys"):
        LoginProfile.from_dict(
            {"login_url": "https://x.test/l", "captcha_url": "https://x.test/c", "typo": 1}
        )


def test_profile_requires_urls():
    with pytest.raises(ValueError):
        LoginProfile(login_url="", captcha_url="https://x.test/c")
