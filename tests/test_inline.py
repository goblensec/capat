"""Building a profile from flags, the ffuf-shaped entry point."""

from __future__ import annotations

import json

import pytest

from capat.cli import build_parser
from capat.core.discovery import find_captcha_image
from capat.core.inline import (
    apply_cli_overrides,
    parse_extract,
    parse_field,
    parse_header,
    parse_matcher,
    profile_data,
)
from capat.core.profile import LoginProfile


def parse(*argv: str):
    return build_parser().parse_args(["audit", *argv])


def test_a_url_and_two_phrases_are_enough_for_a_profile():
    args = parse(
        "-u",
        "https://app.example.com/login",
        "-c",
        "https://app.example.com/captcha.png",
        "--captcha-fail",
        "invalid captcha",
        "--auth-fail",
        "invalid username or password",
    )
    profile = LoginProfile.from_dict(profile_data(args))

    assert profile.login_url == "https://app.example.com/login"
    assert profile.captcha_url == "https://app.example.com/captcha.png"
    assert profile.criteria.is_usable()


def test_flags_override_the_profile_file(tmp_path):
    path = tmp_path / "app.json"
    path.write_text(
        json.dumps(
            {
                "login_url": "https://prod.example.com/login",
                "captcha_url": "https://prod.example.com/captcha.png",
                "csrf_field": "_token",
                "criteria": {"captcha_failure": ["bad captcha"], "auth_failure": ["bad login"]},
            }
        ),
        encoding="utf-8",
    )
    args = parse("--profile", str(path), "-u", "https://staging.example.com/login")
    profile = LoginProfile.from_dict(profile_data(args))

    assert profile.login_url == "https://staging.example.com/login"
    # Untouched keys survive: overriding a URL must not discard the criteria
    # that make the run measurable.
    assert profile.captcha_url == "https://prod.example.com/captcha.png"
    assert profile.csrf_field == "_token"
    assert profile.criteria.is_usable()


def test_headers_and_fields_merge_rather_than_replace(tmp_path):
    path = tmp_path / "app.json"
    path.write_text(
        json.dumps(
            {
                "login_url": "https://example.com/login",
                "captcha_url": "https://example.com/c.png",
                "headers": {"Accept": "application/json"},
                "extra_fields": {"remember": "0"},
            }
        ),
        encoding="utf-8",
    )
    args = parse(
        "--profile",
        str(path),
        "-H",
        "X-Requested-With: XMLHttpRequest",
        "-F",
        "remember=1",
        "-F",
        "locale=en",
    )
    profile = LoginProfile.from_dict(profile_data(args))

    assert profile.headers == {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
    assert profile.extra_fields == {"remember": "1", "locale": "en"}


def test_header_and_field_syntax_is_checked():
    assert parse_header("X-Token: abc") == ("X-Token", "abc")
    assert parse_field("remember=1") == ("remember", "1")
    with pytest.raises(ValueError):
        parse_header("X-Token abc")
    with pytest.raises(ValueError):
        parse_field("remember")


def test_matchers_take_typed_prefixes_for_apis():
    matcher = parse_matcher(["invalid captcha", "re:captcha.{0,20}expired", "status:422"])
    assert matcher == {
        "body": ["invalid captcha"],
        "regex": ["captcha.{0,20}expired"],
        "status": [422],
    }
    assert parse_matcher(["json:data.code=4001"]) == {"json": {"data.code": "4001"}}
    assert parse_matcher(["header:location=/home"]) == {"header": {"location": "/home"}}


def test_a_phrase_containing_a_colon_stays_a_phrase():
    # "Error: invalid captcha" must not be read as a prefix named "error".
    assert parse_matcher(["Error: invalid captcha"]) == {"body": ["Error: invalid captcha"]}


def test_a_bad_status_match_fails_before_the_run():
    with pytest.raises(ValueError, match="must be a number"):
        parse_matcher(["status:nope"])


def test_extractors_are_validated_at_parse_time():
    assert parse_extract("token=hidden:_token") == {
        "name": "token",
        "source": "hidden",
        "key": "_token",
        "from": "form",
    }
    assert parse_extract("id=json:data.id@captcha")["from"] == "captcha"
    # A source with no key, an unknown source, and a regex with no capture
    # group are all mistakes that would otherwise surface mid-run.
    with pytest.raises(ValueError):
        parse_extract("token=nowhere:x")
    with pytest.raises(ValueError, match="capture group"):
        parse_extract("token=regex:csrf")


def test_the_json_api_shape_is_reachable_from_flags():
    args = parse(
        "-u",
        "https://api.example.com/login",
        "-c",
        "https://api.example.com/captcha",
        "--encoding",
        "json",
        "--captcha-response",
        "json",
        "--captcha-image-key",
        "data.image",
        "--captcha-id-key",
        "data.id",
        "--captcha-id-field",
        "captcha_id",
        "--captcha-fail",
        "json:code=4001",
        "--auth-fail",
        "json:code=4002",
    )
    profile = LoginProfile.from_dict(profile_data(args))

    assert profile.uses_challenge_id
    assert profile.encoding == "json"
    assert profile.criteria.captcha_failure.json == {"code": "4001"}


def test_discovery_finds_a_named_image_and_resolves_it():
    html = '<img src="/logo.png"><img src="/img/x.php?t=1" id="captchaImg">'
    assert (
        find_captcha_image(html, "https://example.com/account/login")
        == "https://example.com/img/x.php?t=1"
    )


def test_discovery_finds_a_captcha_image_under_an_unconventional_name():
    """Real elements are called capture_qw23, securityCode or authImg. A name
    the pattern does not know forces the operator into full manual config,
    which is the cost this function exists to avoid."""
    for name in ("capture_qw23", "securityCode", "authImg", "checkCode", "yzm"):
        html = f'<img src="/logo.png"><img id="{name}" src="/img/x.php">'
        assert (
            find_captcha_image(html, "https://example.com/login") == "https://example.com/img/x.php"
        )


def test_discovery_still_declines_ordinary_page_furniture():
    """Widening the pattern must not start picking the logo: a solve rate
    measured against the wrong image is a wrong number presented as a fact."""
    for name in ("logo", "avatar", "hero-banner", "loading", "user-profile"):
        html = f'<img id="{name}" src="/img/x.png">'
        assert find_captcha_image(html, "https://example.com/login") is None


def test_discovery_declines_rather_than_guessing():
    # One unnamed image is not evidence: picking it would measure the logo.
    assert find_captcha_image('<img src="/logo.png">', "https://example.com/") is None
    assert find_captcha_image("", "https://example.com/") is None


def test_discovery_ignores_an_inline_challenge():
    # A data: URI is a challenge with no endpoint to sample.
    html = '<img alt="captcha" src="data:image/png;base64,iVBORw0KGgo=">'
    assert find_captcha_image(html, "https://example.com/") is None


def test_a_json_boolean_matches_how_the_response_reads():
    # JSON spells it `true`; Python prints `True`. A matcher written the way
    # the operator sees the response must fire, or a successful login is
    # silently unclassifiable.
    from capat.core.matching import Matcher, ResponseView

    view = ResponseView(
        status_code=200, url="https://x/login", text='{"isSuccess": true}', headers={}
    )
    assert Matcher(json={"isSuccess": "true"}).matches(view)
    assert Matcher(json={"isSuccess": "True"}).matches(view)
    assert not Matcher(json={"isSuccess": "false"}).matches(view)


def test_numeric_codes_still_compare_exactly():
    from capat.core.matching import Matcher, ResponseView

    view = ResponseView(status_code=200, url="https://x", text='{"code": 4001}', headers={})
    assert Matcher(json={"code": "4001"}).matches(view)
    assert not Matcher(json={"code": "401"}).matches(view)


def test_tuning_is_stored_in_the_profile_and_reused():
    """A recipe that worked should not have to be retyped every run."""
    args = parse(
        "-u",
        "https://x/login",
        "-c",
        "https://x/c.png",
        "--solver",
        "ensemble-fast",
        "--length",
        "5",
        "--min-saturation",
        "60",
        "--dilate",
        "3",
    )
    data = profile_data(args)
    assert data["solver"] == {
        "name": "ensemble-fast",
        "length": 5,
        "min_saturation": 60,
        "dilate": 3,
    }

    profile = LoginProfile.from_dict(data)
    assert profile.solver.name == "ensemble-fast"
    assert profile.solver.min_saturation == 60
    # Untouched knobs keep their defaults rather than being written out.
    assert profile.solver.scale == 3.0
    assert "scale" not in data["solver"]


def test_a_solver_flag_overrides_the_stored_tuning():
    stored = {
        "login_url": "https://x/login",
        "captcha_url": "https://x/c.png",
        "solver": {"name": "ensemble-fast", "min_saturation": 60, "dilate": 3},
    }
    args = parse("-u", "https://x/login", "--solver", "ddddocr", "--dilate", "0")
    merged = apply_cli_overrides(stored, args)
    profile = LoginProfile.from_dict(merged)

    assert profile.solver.name == "ddddocr"
    assert profile.solver.dilate == 0
    # Only what the flags named changes; the rest of the recipe survives.
    assert profile.solver.min_saturation == 60


def test_captcha_shape_at_the_top_level_still_reaches_the_solver():
    profile = LoginProfile.from_dict(
        {
            "login_url": "https://x/login",
            "captcha_url": "https://x/c.png",
            "captcha_length": 5,
            "captcha_charset": "ABC123",
        }
    )
    assert profile.solver.length == 5
    assert profile.solver.charset == "ABC123"


def test_unknown_solver_keys_are_rejected_when_the_profile_loads():
    with pytest.raises(ValueError, match="unknown solver keys"):
        LoginProfile.from_dict(
            {
                "login_url": "https://x/login",
                "captcha_url": "https://x/c.png",
                "solver": {"nmae": "ddddocr"},
            }
        )


def test_lockout_protection_is_on_until_one_flag_turns_it_off():
    """Protection is the default, and exactly one flag disables it.

    Briefly this was a `--stop-if-lockout` / `--no-stop-if-lockout` pair, which
    put a switch in the help that did nothing: stopping was already what
    happened. The question that pair existed to answer - "will this lock out
    the account if I type nothing?" - is answered in `--ignore-lockout`'s help
    text instead, which is where it was missing in the first place.
    """
    assert parse("-u", "https://app.example.com/login").ignore_lockout is False
    assert parse("-u", "https://app.example.com/login", "--ignore-lockout").ignore_lockout is True


def test_a_run_needs_no_confirmation_to_start():
    """capat takes a URL and runs, the way ffuf does.

    The authorization prompt and its -y escape hatch are both gone. A test
    rather than an absence of one because the prompt read stdin: if it came
    back, every piped or scripted run would abort at EOF instead of failing
    visibly here.
    """
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["audit", "-u", "https://app.example.com/login", "-y"])
    assert not hasattr(parse("-u", "https://app.example.com/login"), "yes")
