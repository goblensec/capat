"""The gate checks must not report a missing control they had no way to detect.

Every enforcement check in `gate_enforcement` reads "the CAPTCHA was accepted"
off the *absence* of a CAPTCHA_FAILURE outcome. `SuccessCriteria.captcha_failure`
is empty by default, and an empty Matcher never matches, so with no `-cf` that
outcome is unreachable: the application's CAPTCHA rejection falls through to
whatever `-af` describes. A broad but entirely reasonable `-af "Invalid"` then
matches "Invalid CAPTCHA", and a correctly implemented target is reported
CRITICAL "CAPTCHA not required when the field is omitted".

`SuccessCriteria.is_usable` already existed for exactly this reason but was
consulted only by the solve-rate module. These tests pin the gate module
refusing to guess, while keeping the rotation check - which compares image
bytes and needs no criteria - running.
"""

from __future__ import annotations

import pytest
import respx

from capat.core.profile import LoginProfile, SuccessCriteria
from capat.core.result import Severity
from capat.modules.gate_enforcement import CaptchaGate
from tests.conftest import ScriptedSolver
from tests.test_modules import TARGET, FakeApp, client, mount  # noqa: F401

CAPTCHA_URL = "https://app.example.test/captcha.png"


def _profile(**criteria: list[str]) -> LoginProfile:
    return LoginProfile(
        login_url="https://app.example.test/login",
        captcha_url=CAPTCHA_URL,
        username="auditee",
        criteria=SuccessCriteria(**criteria),
    )


@respx.mock
@pytest.mark.asyncio
async def test_an_overbroad_auth_marker_does_not_become_a_missing_captcha(client):  # noqa: F811
    """The regression itself. `-af "Invalid"` matches this app's "Invalid
    CAPTCHA" rejection, so without the guard the omitted- and empty-answer
    checks both see AUTH_FAILURE, conclude the answer was accepted, and put a
    CRITICAL and a HIGH in front of a client about a target that enforces its
    CAPTCHA correctly."""
    mount(FakeApp())
    profile = _profile(auth_failure=["invalid"])

    findings = await CaptchaGate(profile, ScriptedSolver(["A8R36"] * 4)).run(TARGET, client)

    assert not [f for f in findings if f.severity >= Severity.HIGH], (
        "a correctly enforced CAPTCHA was reported as missing"
    )
    assert any("no captcha-failure criteria" in f.title for f in findings)


@respx.mock
@pytest.mark.asyncio
async def test_missing_captcha_criteria_is_reported_rather_than_passed_over(client):  # noqa: F811
    """Staying silent would be the same defect pointing the other way: the
    report would say nothing about enforcement and read as a clean result for
    checks that never ran. The gap is stated at INFO, and the remediation names
    the flag that closes it."""
    mount(FakeApp())
    profile = _profile(auth_failure=["invalid username or password"])

    findings = await CaptchaGate(profile, ScriptedSolver(["A8R36"] * 4)).run(TARGET, client)

    unconfigured = [f for f in findings if "no captcha-failure criteria" in f.title]
    assert len(unconfigured) == 1
    assert unconfigured[0].severity is Severity.INFO
    assert "--captcha-fail" in unconfigured[0].remediation


@respx.mock
@pytest.mark.asyncio
async def test_rotation_is_still_measured_without_any_criteria(client):  # noqa: F811
    """Rotation compares image bytes and never classifies a login response, so
    it is unaffected by the missing marker. Skipping the whole module would
    lose a real HIGH the run was perfectly able to establish."""
    mount(FakeApp(rotate=False))
    profile = _profile()

    findings = await CaptchaGate(profile, ScriptedSolver(["A8R36"] * 4), rotation_samples=4).run(
        TARGET, client
    )

    static = [f for f in findings if "never changes" in f.title]
    assert static and static[0].severity is Severity.HIGH
    assert static[0].evidence["unique_images"] == 1


@respx.mock
@pytest.mark.asyncio
async def test_replay_without_an_auth_marker_does_not_blame_the_solver(client):  # noqa: F811
    """`_replay_once` discards any attempt whose control submission is not
    AUTH_FAILURE. With no `-af` that is every attempt, so the retry loop ran
    REPLAY_TRIES times and then reported "could not solve a CAPTCHA to test
    with", sending the operator to tune preprocessing over a missing flag."""
    mount(FakeApp())
    profile = _profile(captcha_failure=["invalid captcha"])

    findings = await CaptchaGate(profile, ScriptedSolver(["A8R36"] * 8)).run(TARGET, client)

    assert any("no auth-failure criteria" in f.title for f in findings)
    assert not [f for f in findings if "could not solve" in f.title], (
        "a missing marker was reported as a solver failure"
    )


@respx.mock
@pytest.mark.asyncio
async def test_fully_configured_criteria_still_find_a_real_missing_gate(client):  # noqa: F811
    """The guard must not swallow the finding it exists to keep honest: with
    both markers set, an application that ignores an absent CAPTCHA is still
    CRITICAL."""
    mount(FakeApp(require_captcha=False))
    profile = _profile(
        captcha_failure=["invalid captcha"],
        auth_failure=["invalid username or password"],
    )

    findings = await CaptchaGate(profile, ScriptedSolver(["A8R36"] * 4)).run(TARGET, client)

    critical = [f for f in findings if f.severity is Severity.CRITICAL]
    assert critical and "omitted" in critical[0].title
