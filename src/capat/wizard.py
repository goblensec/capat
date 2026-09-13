"""An interactive way in: ask for the facts, then run.

`audit` takes a lot of flags because applications differ a lot. Nearly all of
them have a sane default, and the handful that do not are things the operator
already knows or can read off one request in devtools. Asking directly beats
handing someone a twenty-flag command line and letting them find out which
part was wrong from a number that looks plausible.

This asks, writes the profile, prints the equivalent command, and runs it. The
printed command is the point: after the first time, nobody needs the wizard.

It only asks. It does not probe the target, and it does not guess - deciding
what the application's answers mean is the operator's call, and getting it
wrong is the one mistake that produces a confident wrong measurement.
"""

from __future__ import annotations

import sys
from typing import Any

from capat.core.inline import parse_field, parse_matcher

__all__ = ["Prompter", "run_wizard"]

INTRO = """
capat setup - answer these and it writes the profile, then runs.
Enter takes the [default]; ^C quits. Nothing is sent until the end.
"""

MATCH_HINT = (
    "  Paste the phrase the application shows. For an API answering with codes, "
    "write json:code=4001, status:422, or re:PATTERN.\n"
)


class Prompter:
    """Line-oriented prompts on stderr, so stdout stays the report."""

    def __init__(self, stream: Any = None) -> None:
        self._out = stream or sys.stderr

    def say(self, text: str = "") -> None:
        print(text, file=self._out)

    def ask(
        self,
        label: str,
        default: str = "",
        *,
        required: bool = False,
        choices: tuple[str, ...] = (),
    ) -> str:
        suffix = f" [{default}]" if default else ""
        if choices:
            suffix = f" ({'/'.join(choices)})" + suffix
        while True:
            try:
                print(f"  {label}{suffix}: ", end="", file=self._out, flush=True)
                answer = input().strip() or default
            except EOFError:
                raise ValueError("setup needs an interactive terminal") from None
            if choices and answer not in choices:
                self.say(f"    -> one of: {', '.join(choices)}")
                continue
            if required and not answer:
                self.say("    -> required")
                continue
            return answer

    def ask_yes(self, label: str, default: bool = True) -> bool:
        answer = self.ask(label, "y" if default else "n", choices=("y", "n"))
        return answer == "y"

    def ask_list(self, label: str) -> list[str]:
        """Repeat a prompt until it comes back empty."""
        values: list[str] = []
        while True:
            answer = self.ask(f"{label} (blank when done)")
            if not answer:
                return values
            values.append(answer)


def run_wizard(p: Prompter) -> tuple[dict[str, Any], list[str], str]:
    """Ask everything. Returns the profile, the audit flags, and where to save."""
    p.say(INTRO)

    p.say("target")
    login_url = p.ask("login URL, where the form posts", required=True)
    # 'auto' is offered here because the wizard is the path for someone who has
    # not read the flags, and a per-load URL is otherwise a silent wrong answer.
    captcha_url = p.ask("CAPTCHA URL, or 'auto' if it changes on every page load", required=True)

    p.say()
    p.say("the CAPTCHA endpoint")
    profile: dict[str, Any] = {"login_url": login_url, "captcha_url": captcha_url}
    response_type = p.ask("what it returns", "image", choices=("image", "json"))
    if response_type == "json":
        profile["captcha_response"] = "json"
        profile["captcha_image_key"] = p.ask("JSON path to the base64 image", "image")
        id_key = p.ask("JSON path to the challenge id, blank if none", "id")
        if id_key:
            profile["captcha_id_key"] = id_key
            profile["captcha_id_field"] = p.ask(
                "field name the id is submitted back in", "captchaId", required=True
            )

    p.say()
    p.say("the login request")
    profile["encoding"] = p.ask("body encoding", "form", choices=("form", "json", "multipart"))
    profile["username_field"] = p.ask("username field name", "username", required=True)
    profile["password_field"] = p.ask("password field name", "password", required=True)
    profile["captcha_field"] = p.ask("CAPTCHA answer field name", "captcha", required=True)
    extra = dict(parse_field(spec) for spec in p.ask_list("extra field, name=value"))
    if extra:
        profile["extra_fields"] = extra
    csrf = p.ask("hidden CSRF field to carry over, blank if none")
    if csrf:
        profile["csrf_field"] = csrf

    p.say()
    p.say("how the application answers - this is what the measurement reads")
    p.say(MATCH_HINT)
    criteria: dict[str, Any] = {
        "captcha_failure": parse_matcher([p.ask("it says WRONG CAPTCHA", required=True)]),
        "auth_failure": parse_matcher([p.ask("it says WRONG USERNAME/PASSWORD", required=True)]),
    }
    success = p.ask("it says SUCCESS, blank to skip")
    if success:
        criteria["success"] = parse_matcher([success])
    profile["criteria"] = criteria

    p.say()
    p.say("probing")
    p.say(
        "  Measuring the solve rate submits logins. It uses an identity that does not\n"
        "  exist, with a fresh random password every time, so nothing can lock out and\n"
        "  nothing can accidentally succeed.\n"
    )
    probe_user = p.ask("username to probe with, wrong on purpose", "cb-probe-<random>")
    if not probe_user.startswith("cb-probe-<"):
        profile["probe_username"] = probe_user
    samples = p.ask("CAPTCHAs to measure", "25")
    rps = p.ask("max requests per second", "1")

    flags = ["-n", samples, "-r", rps]

    p.say()
    p.say("credential test - optional, submits real login attempts")
    passwords = p.ask("password wordlist, blank to skip")
    if passwords:
        flags += ["-w", passwords]
        users = p.ask("username wordlist, blank to use one account")
        if users:
            flags += ["-U", users]
        else:
            profile["username"] = p.ask("account to test", required=True)
        flags += ["--lockout-threshold", p.ask("stop after this many failures per account", "3")]

    p.say()
    path = p.ask("write the profile to", "app.json")
    return profile, flags, path


def quote(value: str) -> str:
    return f'"{value}"' if " " in value or "|" in value else value


def command_line(path: str, flags: list[str]) -> str:
    return " ".join(["capat audit -p", path, *(quote(f) for f in flags)])
