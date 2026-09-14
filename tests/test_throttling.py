"""A throttle anywhere in an attempt is rate limiting, not a broken target.

Only the login response used to be checked. A target that rate-limited its
CAPTCHA endpoint therefore produced "cannot read the CAPTCHA endpoint" - which
reads as the operator's profile being wrong, and denies the target credit for
the one control the report actually asks for.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from capat.core.profile import LoginProfile, SuccessCriteria
from capat.core.result import Severity
from capat.core.target import Target
from capat.core.throttle import Throttled
from capat.http.client import HttpClient
from capat.modules.credential_audit import CredentialAudit
from capat.modules.gate_enforcement import CaptchaGate
from capat.modules.login_flow import LoginFlow
from capat.modules.solve_rate import CaptchaSolveRate
from tests.conftest import CONFIG, ScriptedSolver

TARGET = Target("https://app.example.test/login")
LOGIN_PAGE = '<form><input type="hidden" name="_token" value="t0k"></form>'


def profile() -> LoginProfile:
    return LoginProfile(
        login_url="https://app.example.test/login",
        captcha_url="https://app.example.test/captcha.png",
        username="auditee",
        criteria=SuccessCriteria(
            captcha_failure=["invalid captcha"],
            auth_failure=["invalid username or password"],
            success=["welcome back"],
        ),
    )


def mount(*, captcha: httpx.Response, page: httpx.Response | None = None) -> None:
    respx.get("https://app.example.test/login").mock(
        return_value=page or httpx.Response(200, text=LOGIN_PAGE)
    )
    respx.get("https://app.example.test/captcha.png").mock(return_value=captcha)
    respx.post("https://app.example.test/login").mock(
        return_value=httpx.Response(200, text="invalid username or password")
    )


LIMITED = httpx.Response(429, json={"error": "too many requests"}, headers={"Retry-After": "30"})


@respx.mock
@pytest.mark.asyncio
async def test_a_throttled_captcha_endpoint_raises_rather_than_parsing():
    """parse_captcha would otherwise call a limiter's JSON body an unreadable
    CAPTCHA endpoint."""
    mount(captcha=LIMITED)
    flow = LoginFlow(profile(), solver=None)
    async with HttpClient(CONFIG) as client, client.session() as session:
        context = await flow.fetch_form(session)
        with pytest.raises(Throttled) as caught:
            await flow.fetch_captcha(session, context)
    assert caught.value.status == 429
    assert caught.value.retry_after == 30.0


@respx.mock
@pytest.mark.asyncio
async def test_a_throttled_login_page_stops_before_it_is_parsed_for_a_form():
    """ "No hidden fields" is a misleading way to say "slow down"."""
    mount(captcha=httpx.Response(200, content=b"png"), page=LIMITED)
    flow = LoginFlow(profile(), solver=None)
    async with HttpClient(CONFIG) as client, client.session() as session:
        with pytest.raises(Throttled):
            await flow.fetch_form(session)


@respx.mock
@pytest.mark.asyncio
async def test_the_gate_credits_a_target_that_rate_limits():
    mount(captcha=LIMITED)
    async with HttpClient(CONFIG) as client:
        findings = await CaptchaGate(profile(), solver=None).run(TARGET, client)

    assert len(findings) == 1
    assert "rate-limited" in findings[0].title
    assert findings[0].severity is Severity.INFO
    assert findings[0].evidence["status_code"] == 429
    assert "cannot read" not in findings[0].title


@respx.mock
@pytest.mark.asyncio
async def test_the_solve_rate_reports_the_limit_instead_of_a_percentage():
    """A rate that counted throttled attempts as failures would understate the
    target twice: a wrong number, and no credit for the limiter."""
    mount(captcha=LIMITED)
    async with HttpClient(CONFIG) as client:
        findings = await CaptchaSolveRate(profile(), ScriptedSolver(["A8R36"] * 5), samples=5).run(
            TARGET, client
        )

    assert len(findings) == 1
    assert "rate-limited" in findings[0].title
    assert findings[0].evidence["samples_requested"] == 5
    assert "solve_rate" not in findings[0].evidence


@respx.mock
@pytest.mark.asyncio
async def test_the_credential_audit_stops_rather_than_burning_the_wordlist(tmp_path):
    wordlist = tmp_path / "w.txt"
    wordlist.write_text("a\nb\nc\nd\ne\n", encoding="utf-8")
    mount(captcha=LIMITED)
    async with HttpClient(CONFIG) as client:
        findings = await CredentialAudit(
            profile(), ScriptedSolver(["A8R36"] * 5), wordlist=str(wordlist)
        ).run(TARGET, client)

    assert any("rate-limited" in f.title for f in findings)


def test_a_limiter_that_trips_on_the_first_attempt_reads_as_one_attempt():
    """A report that says "after 1 attempts" undercuts the page around it.

    The title is the line that gets pasted into a findings table, and a
    limiter tripping immediately is the case most worth reporting - the
    template must not be at its ugliest exactly there.
    """
    from capat.core.throttle import rate_limit_finding

    assert "after 1 attempt" in rate_limit_finding("m", "https://h/login", 429, 1).title
    assert "after 1 attempts" not in rate_limit_finding("m", "https://h/login", 429, 1).title
    assert "after 3 attempts" in rate_limit_finding("m", "https://h/login", 429, 3).title


def test_a_limiter_that_trips_before_any_attempt_is_not_reported_as_zero_attempts() -> None:
    """A check throttled on its first request is the strongest result it can
    return. It read "after 0 attempts", which a client reads as the tool having
    done nothing at all."""
    from capat.core.throttle import rate_limit_finding

    f = rate_limit_finding("captcha-gate", "https://x.test/login", 429, done=0)
    assert "0 attempts" not in f.title
    assert "0 attempts" not in f.description
    assert "on the first request" in f.title
    assert "before any attempt completed" in f.description


def test_attempt_counts_still_read_as_english() -> None:
    """The singular and the sample-count forms share one template with the
    zero case, so they break together."""
    from capat.core.throttle import rate_limit_finding

    one = rate_limit_finding("captcha-gate", "https://x.test/login", 429, done=1)
    assert "after 1 attempt" in one.title
    assert "1 attempts" not in one.title + one.description
    many = rate_limit_finding("captcha-solve-rate", "https://x.test/login", 429, done=3, asked=40)
    assert "after 3 attempts" in many.title
    assert "3 of 40 samples in" in many.description


def test_every_module_reports_a_throttle_through_the_shared_helper() -> None:
    """solve-rate kept a private copy for a 429 on the login response while using
    the shared helper for a 429 during a fetch, so one run could emit two
    wordings for one condition - and only one of them got the fix that stopped
    it saying "after 0 attempts"."""
    import inspect

    from capat.modules import credential_audit, gate_enforcement, solve_rate

    for module in (solve_rate, gate_enforcement, credential_audit):
        source = inspect.getsource(module)
        assert "rate_limit_finding" in source
        assert "rate-limited the run" not in source, (
            f"{module.__name__} builds its own throttle finding; call rate_limit_finding"
        )
