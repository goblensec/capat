"""The interactive way in. Scripted answers stand in for a person typing."""

from __future__ import annotations

import io

import pytest

from capat.core.profile import LoginProfile
from capat.wizard import Prompter, command_line, run_wizard


class ScriptedPrompter(Prompter):
    """Answers each prompt from a list; "" means take the default."""

    def __init__(self, answers: list[str]) -> None:
        super().__init__(io.StringIO())
        self._answers = list(answers)
        self.asked: list[str] = []

    def ask(self, label, default="", *, required=False, choices=()):  # type: ignore[no-untyped-def]
        self.asked.append(label)
        if not self._answers:
            raise AssertionError(f"wizard asked more than the script covers: {label!r}")
        answer = self._answers.pop(0) or default
        if choices and answer not in choices:
            raise AssertionError(f"scripted answer {answer!r} not in {choices} for {label!r}")
        if required and not answer:
            raise AssertionError(f"scripted blank for a required prompt: {label!r}")
        return answer


UWALLET = [
    "https://app.example.com/api/auth/login",  # login URL
    "https://app.example.com/api/captcha",  # CAPTCHA URL
    "json",  # captcha response
    "image",  # image key
    "id",  # id key
    "captchaId",  # id field
    "json",  # body encoding
    "",  # username field -> username
    "",  # password field -> password
    "captchaValue",  # captcha field
    "lang=en",  # extra field
    "",  # extra field, done
    "",  # csrf field, none
    "Invalid CAPTCHA",  # wrong captcha
    "Invalid username or password",  # wrong credentials
    "json:isSuccess=true",  # success
    "",  # probe username -> random
    "10",  # samples
    "1",  # rps
    "",  # password wordlist -> skip
    "app.json",  # save to
]


def test_the_wizard_builds_a_working_profile():
    prompter = ScriptedPrompter(UWALLET)
    data, flags, path = run_wizard(prompter)
    profile = LoginProfile.from_dict(data)

    assert profile.login_url == "https://app.example.com/api/auth/login"
    assert profile.captcha_response == "json"
    assert profile.captcha_id_field == "captchaId"
    assert profile.captcha_field == "captchaValue"
    assert profile.encoding == "json"
    assert profile.extra_fields == {"lang": "en"}
    assert profile.criteria.is_usable()
    assert profile.criteria.success.json == {"isSuccess": "true"}
    # The body carries exactly the fields the application reads.
    assert sorted(profile.build_fields("u", "p", "ABC12", challenge_id="cid")) == [
        "captchaId",
        "captchaValue",
        "lang",
        "password",
        "username",
    ]
    assert path == "app.json"
    assert flags[:2] == ["-n", "10"]


def test_the_wizard_prints_the_command_it_ran():
    _, flags, path = run_wizard(ScriptedPrompter(UWALLET))
    line = command_line(path, flags)
    assert line.startswith("capat audit -p app.json")
    assert "-n 10" in line


def test_a_credential_test_is_opt_in_and_asks_for_a_lockout_budget():
    answers = list(UWALLET)
    answers[-2] = "passwords.txt"  # password wordlist
    answers[-1:] = ["users.txt", "3", "app.json"]  # user list, lockout budget, path
    _, flags, _ = run_wizard(ScriptedPrompter(answers))

    assert "-w" in flags and flags[flags.index("-w") + 1] == "passwords.txt"
    assert "-U" in flags and flags[flags.index("-U") + 1] == "users.txt"
    assert flags[flags.index("--lockout-threshold") + 1] == "3"


def test_a_plain_image_captcha_skips_the_json_questions():
    answers = [
        "https://example.com/login",
        "https://example.com/captcha.png",
        "image",  # -> no image/id key prompts
        "form",
        "",
        "",
        "",
        "",  # no extra fields
        "_token",  # csrf
        "invalid captcha",
        "invalid username or password",
        "",  # no success rule
        "",
        "25",
        "1",
        "",
        "app.json",
    ]
    prompter = ScriptedPrompter(answers)
    profile = LoginProfile.from_dict(run_wizard(prompter)[0])

    assert profile.captcha_response == "image"
    assert not profile.uses_challenge_id
    assert profile.csrf_field == "_token"
    assert not any("base64" in label for label in prompter.asked)


def test_the_wizard_gives_up_on_a_non_interactive_terminal(monkeypatch):
    def no_input() -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", no_input)
    with pytest.raises(ValueError, match="interactive terminal"):
        Prompter(io.StringIO()).ask("login URL")
