"""The parts an operator customizes per application.

Every web app answers differently and expects a differently shaped request.
These cover the knobs that make one tool work against all of them: matchers,
extractors, body encodings, and the raw template escape hatch.
"""

from __future__ import annotations

import json

import httpx
import pytest

from capat.core.matching import Matcher, Outcome, ResponseView, SuccessCriteria
from capat.core.profile import LoginProfile, nest
from capat.core.template import Extractor, placeholders, render


def resp(text="", url="https://app.example.test/login", status=200, headers=None):
    return httpx.Response(
        status,
        text=text,
        headers=headers or {},
        request=httpx.Request("POST", url),
    )


def view(**kwargs):
    return ResponseView.of(resp(**kwargs))


# --------------------------------------------------------------------------
# matchers
# --------------------------------------------------------------------------


def test_bare_list_is_shorthand_for_body_substrings():
    assert Matcher.parse(["nope"]).body == ["nope"]
    assert Matcher.parse("nope").body == ["nope"]
    assert Matcher.parse(None).is_empty()


def test_parsing_is_idempotent():
    built = Matcher(body=["x"])
    assert Matcher.parse(built) is built


def test_matches_a_json_code_regardless_of_number_or_string():
    matcher = Matcher(json={"data.code": 4001})
    assert matcher.matches(view(text='{"data":{"code":4001}}'))
    assert matcher.matches(view(text='{"data":{"code":"4001"}}'))
    assert not matcher.matches(view(text='{"data":{"code":4002}}'))


def test_json_matcher_ignores_non_json_bodies():
    assert not Matcher(json={"code": 1}).matches(view(text="<html>hi</html>"))


def test_matches_a_regex():
    matcher = Matcher(regex=[r"captcha.{0,20}(invalid|expired)"])
    assert matcher.matches(view(text="The CAPTCHA code has EXPIRED"))
    assert not matcher.matches(view(text="wrong password"))


def test_matches_status_header_and_url():
    assert Matcher(status=[422]).matches(view(status=422))
    assert Matcher(header={"x-error": "captcha"}).matches(view(headers={"X-Error": "CAPTCHA-BAD"}))
    assert Matcher(url=["/dashboard"]).matches(view(url="https://app.example.test/dashboard"))


def test_conditions_are_or_by_default():
    matcher = Matcher(body=["nope"], status=[422])
    assert matcher.matches(view(text="nope", status=200))
    assert matcher.matches(view(text="fine", status=422))


def test_all_mode_requires_every_condition():
    matcher = Matcher(body=["nope"], status=[422], mode="all")
    assert matcher.matches(view(text="nope", status=422))
    assert not matcher.matches(view(text="nope", status=200))


def test_invalid_regex_and_mode_are_rejected_at_load():
    with pytest.raises(ValueError, match="invalid regex"):
        Matcher(regex=["(unclosed"])
    with pytest.raises(ValueError, match="'any' or 'all'"):
        Matcher(mode="maybe")
    with pytest.raises(ValueError, match="unknown matcher keys"):
        Matcher.parse({"bod": ["typo"]})


def test_json_api_criteria_classify_by_code():
    criteria = SuccessCriteria(
        captcha_failure={"json": {"code": 4001}},
        auth_failure={"json": {"code": 4002}},
        success={"json": {"code": 0}},
    )
    assert criteria.classify(resp('{"code":4001}')) is Outcome.CAPTCHA_FAILURE
    assert criteria.classify(resp('{"code":4002}')) is Outcome.AUTH_FAILURE
    assert criteria.classify(resp('{"code":0}')) is Outcome.SUCCESS
    assert criteria.classify(resp('{"code":9}')) is Outcome.UNKNOWN
    assert criteria.is_usable()


def test_captcha_failure_wins_over_auth_failure():
    """An app naming both must not be read as a solved CAPTCHA."""
    criteria = SuccessCriteria(
        captcha_failure=["invalid captcha"], auth_failure=["invalid username"]
    )
    both = resp("Invalid captcha. Invalid username or password.")
    assert criteria.classify(both) is Outcome.CAPTCHA_FAILURE


# --------------------------------------------------------------------------
# templates
# --------------------------------------------------------------------------


def test_renders_placeholders():
    assert render("u={{username}}&c={{captcha}}", {"username": "a", "captcha": "B2"}) == "u=a&c=B2"
    assert render("{{ username }}", {"username": "a"}) == "a"


def test_json_filter_keeps_the_body_well_formed():
    body = render('{"c": {{captcha|json}}}', {"captcha": 'A"B\\'})
    assert json.loads(body) == {"c": 'A"B\\'}


def test_url_filter_percent_encodes():
    assert render("{{captcha|url}}", {"captcha": "a b&c"}) == "a%20b%26c"


def test_unknown_placeholder_and_filter_are_reported():
    with pytest.raises(ValueError, match="unknown placeholder"):
        render("{{nope}}", {"username": "a"})
    with pytest.raises(ValueError, match="unknown filter"):
        render("{{username|xml}}", {"username": "a"})


def test_placeholders_are_discoverable():
    assert placeholders("{{a}} {{b|json}}") == {"a", "b"}


# --------------------------------------------------------------------------
# extractors
# --------------------------------------------------------------------------


def test_extracts_a_token_from_a_meta_tag():
    page = resp('<meta name="csrf-token" content="tok-123">')
    extractor = Extractor(name="csrf", source="regex", key=r'name="csrf-token" content="([^"]+)"')
    assert extractor.apply(page, {}) == "tok-123"


def test_extracts_from_json_header_and_cookie():
    page = resp(
        '{"session":{"nonce":"n-9"}}',
        headers={"X-Token": "hdr-1", "Set-Cookie": "XSRF-TOKEN=ck-7; Path=/"},
    )
    assert Extractor(name="n", source="json", key="session.nonce").apply(page, {}) == "n-9"
    assert Extractor(name="h", source="header", key="X-Token").apply(page, {}) == "hdr-1"
    assert Extractor(name="c", source="cookie", key="XSRF-TOKEN").apply(page, {}) == "ck-7"


def test_extracts_a_hidden_input():
    extractor = Extractor(name="t", source="hidden", key="_token")
    assert extractor.apply(resp(), {"_token": "h1"}) == "h1"


def test_missing_required_value_says_where_it_looked():
    extractor = Extractor(name="csrf", source="json", key="a.b")
    with pytest.raises(ValueError, match="found nothing at json:'a.b'"):
        extractor.apply(resp("{}"), {})


def test_optional_value_falls_back_to_its_default():
    extractor = Extractor(name="csrf", source="json", key="a.b", required=False, default="none")
    assert extractor.apply(resp("{}"), {}) == "none"


def test_extractor_configuration_is_validated():
    with pytest.raises(ValueError, match="unknown extractor source"):
        Extractor(name="x", source="telepathy", key="k")
    with pytest.raises(ValueError, match="needs a capture group"):
        Extractor(name="x", source="regex", key="no-group-here")
    with pytest.raises(ValueError, match="needs a key"):
        Extractor(name="x", source="hidden")
    with pytest.raises(ValueError, match="unknown extractor keys"):
        Extractor.parse({"name": "x", "key": "k", "sauce": "bad"})


def test_from_is_accepted_as_a_json_key():
    assert Extractor.parse({"name": "x", "key": "k", "from": "captcha"}).from_ == "captcha"


# --------------------------------------------------------------------------
# request shaping
# --------------------------------------------------------------------------


def profile(**overrides):
    base = {
        "login_url": "https://app.example.test/login",
        "captcha_url": "https://app.example.test/captcha",
    }
    base.update(overrides)
    return LoginProfile.from_dict(base)


VALUES = {"username": "u", "password": "p", "captcha": "A8R36", "captcha_id": ""}


def test_form_encoding_is_the_default():
    kwargs = profile().build_request(VALUES)
    assert kwargs["data"]["username"] == "u"
    assert "json" not in kwargs


def test_json_encoding_sends_a_json_body():
    kwargs = profile(encoding="json").build_request(VALUES)
    assert kwargs["json"] == {"username": "u", "password": "p", "captcha": "A8R36"}


def test_dotted_field_names_nest_only_for_json():
    assert nest({"user.name": "x", "flat": "y"}) == {"user": {"name": "x"}, "flat": "y"}
    json_kwargs = profile(encoding="json", username_field="user.name").build_request(VALUES)
    assert json_kwargs["json"]["user"] == {"name": "u"}
    form_kwargs = profile(username_field="user.name").build_request(VALUES)
    assert form_kwargs["data"]["user.name"] == "u"


def test_multipart_encoding_emits_plain_fields():
    kwargs = profile(encoding="multipart").build_request(VALUES)
    assert kwargs["files"]["username"] == (None, "u")


def test_headers_are_sent_and_may_use_extracted_values():
    p = profile(
        headers={"X-Requested-With": "XMLHttpRequest", "X-XSRF-TOKEN": "{{xsrf}}"},
        extract=[{"name": "xsrf", "source": "cookie", "key": "XSRF-TOKEN"}],
    )
    kwargs = p.build_request({**VALUES, "xsrf": "ck-7"})
    assert kwargs["headers"]["X-Requested-With"] == "XMLHttpRequest"
    assert kwargs["headers"]["X-XSRF-TOKEN"] == "ck-7"


def test_body_template_overrides_the_structured_fields():
    p = profile(
        encoding="json",
        body_template='{"login":{"u":{{username|json}},"code":{{captcha|json}}}}',
    )
    kwargs = p.build_request(VALUES)
    assert json.loads(kwargs["content"]) == {"login": {"u": "u", "code": "A8R36"}}
    assert kwargs["headers"]["Content-Type"] == "application/json"


def test_challenge_id_is_available_to_a_template():
    p = profile(
        captcha_response="json",
        captcha_id_key="id",
        captcha_id_field="cid",
        body_template="c={{captcha}}&k={{captcha_id}}",
    )
    body = p.build_request({**VALUES, "captcha_id": "ch-42"})["content"]
    assert body == b"c=A8R36&k=ch-42"


def test_omitting_the_captcha_drops_only_that_field():
    kwargs = profile(encoding="json").build_request(VALUES, omit_captcha=True)
    assert "captcha" not in kwargs["json"]
    assert kwargs["json"]["username"] == "u"


# --------------------------------------------------------------------------
# load-time validation
# --------------------------------------------------------------------------


def test_unknown_placeholder_in_a_profile_fails_at_load_not_mid_run():
    with pytest.raises(ValueError, match="unknown placeholder"):
        profile(body_template="{{nonesuch}}")
    with pytest.raises(ValueError, match="unknown placeholder"):
        profile(headers={"X-T": "{{nonesuch}}"})


def test_extractor_names_become_valid_placeholders():
    p = profile(
        extract=[{"name": "nonce", "source": "hidden", "key": "n"}],
        body_template="n={{nonce}}",
    )
    assert p.build_request({**VALUES, "nonce": "abc"})["content"] == b"n=abc"


def test_unknown_encoding_is_rejected():
    with pytest.raises(ValueError, match="encoding must be one of"):
        profile(encoding="protobuf")


def test_unknown_profile_key_lists_the_valid_ones():
    with pytest.raises(ValueError, match="Known keys:"):
        profile(headerz={})
