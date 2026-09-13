"""Module tests against a scripted fake login application.

Every response is canned; no test touches the network or a real OCR model.
"""

from __future__ import annotations

import base64
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from capat.core.profile import LoginProfile, Matcher, SuccessCriteria
from capat.core.result import Severity
from capat.core.target import Target
from capat.http.client import HttpClient
from capat.modules.credential_audit import CredentialAudit, stream_wordlist
from capat.modules.gate_enforcement import CaptchaGate
from capat.modules.solve_rate import CaptchaSolveRate
from tests.conftest import CONFIG, ScriptedSolver

TARGET = Target("https://app.example.test/login")
LOGIN_PAGE = '<form><input type="hidden" name="_token" value="t0k"></form>'


class FakeApp:
    """A login endpoint whose behavior each test dials in.

    Defaults model a correctly implemented CAPTCHA: required, single-use,
    rotating, and checked before credentials.
    """

    def __init__(
        self,
        answer: str = "A8R36",
        *,
        require_captcha: bool = True,
        allow_empty: bool = False,
        single_use: bool = True,
        rotate: bool = True,
        valid_password: str | None = None,
    ) -> None:
        self.answer = answer
        self.require_captcha = require_captcha
        self.allow_empty = allow_empty
        self.single_use = single_use
        self.rotate = rotate
        self.valid_password = valid_password
        self.consumed = False
        self.images_served = 0
        self.login_attempts = 0

    def captcha(self, request: httpx.Request) -> httpx.Response:
        self.images_served += 1
        self.consumed = False
        body = f"png-{self.images_served}".encode() if self.rotate else b"png-static"
        return httpx.Response(200, content=body, headers={"content-type": "image/png"})

    def login(self, request: httpx.Request) -> httpx.Response:
        self.login_attempts += 1
        # keep_blank_values matters: "field absent" and "field empty" are
        # different checks, and parse_qs collapses them by default.
        form = {
            k: v[0] for k, v in parse_qs(request.content.decode(), keep_blank_values=True).items()
        }
        supplied = form.get("captcha")

        if supplied is None:
            if self.require_captcha:
                return httpx.Response(200, text="Invalid CAPTCHA")
        elif supplied == "" and not self.allow_empty:
            return httpx.Response(200, text="Invalid CAPTCHA")
        elif supplied:
            if supplied.casefold() != self.answer.casefold():
                return httpx.Response(200, text="Invalid CAPTCHA")
            if self.single_use and self.consumed:
                return httpx.Response(200, text="Invalid CAPTCHA")
            self.consumed = True

        if self.valid_password and form.get("password") == self.valid_password:
            return httpx.Response(200, text="Welcome back")
        return httpx.Response(200, text="Invalid username or password")


def mount(app: FakeApp) -> None:
    respx.get("https://app.example.test/login").mock(
        return_value=httpx.Response(200, text=LOGIN_PAGE)
    )
    respx.get("https://app.example.test/captcha.png").mock(side_effect=app.captcha)
    respx.post("https://app.example.test/login").mock(side_effect=app.login)


@pytest.fixture
async def client():
    async with HttpClient(CONFIG) as c:
        yield c


# --------------------------------------------------------------------------
# solve rate
# --------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_solve_rate_counts_auth_failure_as_a_correct_solve(profile, client):
    mount(FakeApp(answer="A8R36"))
    solver = ScriptedSolver(["A8R36", "WRONG", "A8R36", "A8R36"])
    findings = await CaptchaSolveRate(profile, solver, samples=4).run(TARGET, client)

    assert len(findings) == 1
    evidence = findings[0].evidence
    assert evidence["solved"] == 3
    assert evidence["wrong"] == 1
    assert evidence["solve_rate"] == 0.75
    assert findings[0].severity is Severity.HIGH


@respx.mock
@pytest.mark.asyncio
async def test_solve_rate_probes_a_nonexistent_identity(profile, client):
    """The measurement must never touch the account named in the profile."""
    app = FakeApp()
    mount(app)
    seen: list[str] = []

    def capture(request: httpx.Request) -> httpx.Response:
        seen.append({k: v[0] for k, v in parse_qs(request.content.decode()).items()}["username"])
        return app.login(request)

    respx.post("https://app.example.test/login").mock(side_effect=capture)
    await CaptchaSolveRate(profile, ScriptedSolver(["A8R36"] * 3), samples=3).run(TARGET, client)

    assert seen, "no login attempts were made"
    assert profile.username == "auditee"
    assert all(name == profile.probe_username for name in seen)
    assert all(name != profile.username for name in seen)


@respx.mock
@pytest.mark.asyncio
async def test_solve_rate_reports_zero_without_flagging(profile, client):
    mount(FakeApp(answer="A8R36"))
    findings = await CaptchaSolveRate(profile, ScriptedSolver(["ZZZZZ"] * 3), samples=3).run(
        TARGET, client
    )
    assert findings[0].severity is Severity.INFO
    assert findings[0].evidence["solve_rate"] == 0.0


@pytest.mark.asyncio
async def test_solve_rate_refuses_to_guess_without_both_markers(profile, client):
    profile.criteria.auth_failure = Matcher()
    findings = await CaptchaSolveRate(profile, ScriptedSolver([]), samples=3).run(TARGET, client)
    assert "markers incomplete" in findings[0].title
    assert findings[0].severity is Severity.INFO


# --------------------------------------------------------------------------
# gate enforcement
# --------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_gate_clean_on_a_correct_implementation(profile, client):
    mount(FakeApp())
    findings = await CaptchaGate(profile, ScriptedSolver(["A8R36"] * 4)).run(TARGET, client)
    assert findings == []


@respx.mock
@pytest.mark.asyncio
async def test_gate_flags_captcha_that_is_optional(profile, client):
    mount(FakeApp(require_captcha=False))
    findings = await CaptchaGate(profile, ScriptedSolver(["A8R36"] * 4)).run(TARGET, client)
    critical = [f for f in findings if f.severity is Severity.CRITICAL]
    assert critical and "omitted" in critical[0].title


@respx.mock
@pytest.mark.asyncio
async def test_gate_flags_accepted_empty_value(profile, client):
    mount(FakeApp(allow_empty=True))
    findings = await CaptchaGate(profile, ScriptedSolver(["A8R36"] * 4)).run(TARGET, client)
    assert any("empty CAPTCHA value accepted" in f.title for f in findings)


@respx.mock
@pytest.mark.asyncio
async def test_gate_flags_static_image(profile, client):
    mount(FakeApp(rotate=False))
    findings = await CaptchaGate(profile, ScriptedSolver(["A8R36"] * 4), rotation_samples=4).run(
        TARGET, client
    )
    static = [f for f in findings if "never changes" in f.title]
    assert static and static[0].severity is Severity.HIGH
    assert static[0].evidence["unique_images"] == 1


@respx.mock
@pytest.mark.asyncio
async def test_gate_flags_replayable_answer(profile, client):
    mount(FakeApp(single_use=False))
    findings = await CaptchaGate(profile, ScriptedSolver(["A8R36"] * 4)).run(TARGET, client)
    assert any("can be replayed" in f.title for f in findings)


@respx.mock
@pytest.mark.asyncio
async def test_gate_runs_without_a_solver(profile, client):
    """The enforcement checks must work with no OCR dependency installed."""
    mount(FakeApp(require_captcha=False, rotate=False))
    findings = await CaptchaGate(profile, solver=None, rotation_samples=3).run(TARGET, client)
    titles = {f.title for f in findings}
    assert any("omitted" in t for t in titles)
    assert any("never changes" in t for t in titles)


# --------------------------------------------------------------------------
# credential audit
# --------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_credential_audit_reports_the_password_it_found(profile, client, tmp_path):
    mount(FakeApp(valid_password="hunter2"))
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("# comment\nletmein\n\nhunter2\nunused\n", encoding="utf-8")

    module = CredentialAudit(profile, ScriptedSolver(["A8R36"] * 10), wordlist=wordlist)
    findings = await module.run(TARGET, client)

    finding = findings[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.evidence["wordlist_line"] == 4
    assert finding.evidence["username"] == "auditee"
    # The credential is the finding: an operator has to verify it, and the
    # line number alone makes the reader take the tool's word for it.
    assert finding.evidence["password"] == "hunter2"
    assert "auditee:hunter2" in finding.title


@respx.mock
@pytest.mark.asyncio
async def test_credential_audit_stops_before_lockout(profile, client, tmp_path):
    mount(FakeApp(valid_password=None))
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("\n".join(f"pw{i}" for i in range(50)), encoding="utf-8")

    module = CredentialAudit(
        profile, ScriptedSolver(["A8R36"] * 60), wordlist=wordlist, lockout_threshold=3
    )
    summary = (await module.run(TARGET, client))[-1]

    assert summary.evidence["stopped_for_lockout"] == ["auditee"]
    assert summary.evidence["attempts"] == 3


@respx.mock
@pytest.mark.asyncio
async def test_wrong_solves_do_not_consume_the_lockout_budget(profile, client, tmp_path):
    """A rejected CAPTCHA is not a failed login and must not count."""
    mount(FakeApp(answer="A8R36", valid_password=None))
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("\n".join(f"pw{i}" for i in range(3)), encoding="utf-8")

    # Every password is misread once, then solved on the retry: 6 attempts, 3
    # of which reach credential checking. With a threshold of 4 the wordlist
    # must run out first - if the 3 rejected CAPTCHAs counted towards the
    # budget, the run would stop early instead.
    solver = ScriptedSolver(["NOPE", "A8R36"] * 3)
    module = CredentialAudit(profile, solver, wordlist=wordlist, lockout_threshold=4)
    summary = (await module.run(TARGET, client))[-1]

    assert summary.evidence["stopped_for_lockout"] == []
    assert summary.evidence["passed_captcha"] == 3
    assert summary.evidence["failed_captcha"] == 3
    assert summary.evidence["passwords_never_tested"] == 0


@respx.mock
@pytest.mark.asyncio
async def test_a_misread_captcha_retries_the_same_password(profile, client, tmp_path):
    """A password whose CAPTCHA failed has not been tested, and must be retried.

    Dropping it would silently shrink the wordlist: at a 25% solve rate three
    quarters of an engagement's passwords would never reach the application,
    and the run would report a clean result for words it never tried.
    """
    mount(FakeApp(answer="A8R36", valid_password="pw2"))
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("pw0\npw1\npw2\n", encoding="utf-8")

    # pw0 and pw1 are misread twice each; pw2 - the valid one - misread once.
    solver = ScriptedSolver(["X", "X", "A8R36", "X", "X", "A8R36", "X", "A8R36"])
    module = CredentialAudit(profile, solver, wordlist=wordlist, captcha_retries=2)
    findings = await module.run(TARGET, client)

    critical = [f for f in findings if f.severity is Severity.CRITICAL]
    assert critical and critical[0].evidence["password"] == "pw2"
    assert findings[-1].evidence["passwords_never_tested"] == 0


@respx.mock
@pytest.mark.asyncio
async def test_a_password_the_solver_never_gets_through_is_reported_untested(
    profile, client, tmp_path
):
    """Giving up is allowed; giving up quietly is not."""
    mount(FakeApp(answer="A8R36", valid_password=None))
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("pw0\n", encoding="utf-8")

    module = CredentialAudit(
        profile, ScriptedSolver(["X"] * 10), wordlist=wordlist, captcha_retries=2
    )
    summary = (await module.run(TARGET, client))[-1]

    assert summary.evidence["passwords_never_tested"] == 1
    assert summary.evidence["passed_captcha"] == 0
    assert "never tested" in summary.description
    # A run that skipped a password is not a clean "nothing found" result.
    assert summary.severity is Severity.LOW


def test_credential_audit_requires_a_named_account(profile):
    profile.username = ""
    with pytest.raises(ValueError, match="username list"):
        CredentialAudit(profile, ScriptedSolver([]), wordlist="x")


def test_wordlist_streaming_skips_blanks_comments_and_duplicates(tmp_path):
    path = tmp_path / "w.txt"
    path.write_text("a\n\n# note\nb\na\n", encoding="utf-8")
    assert list(stream_wordlist(path)) == [(1, "a"), (4, "b")]


# --------------------------------------------------------------------------
# JSON + base64 + challenge-id deployments
# --------------------------------------------------------------------------


class JsonCaptchaApp(FakeApp):
    """A CAPTCHA API: JSON body, base64 image, and an id keyed server-side.

    The answer is bound to the identifier rather than the cookie, so a login
    that does not carry the id back cannot be validated at all.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.issued: dict[str, str] = {}
        self.last_id: str | None = None

    def captcha(self, request):
        self.images_served += 1
        body = f"png-{self.images_served}".encode() if self.rotate else b"png-static"
        self.last_id = f"ch-{self.images_served}"
        self.issued[self.last_id] = self.answer
        return httpx.Response(
            200,
            json={
                "status": "ok",
                "data": {
                    "id": self.last_id,
                    "image": "data:image/png;base64," + base64.b64encode(body).decode(),
                },
            },
        )

    def login(self, request):
        self.login_attempts += 1
        form = {
            k: v[0] for k, v in parse_qs(request.content.decode(), keep_blank_values=True).items()
        }
        supplied = form.get("captcha")
        challenge_id = form.get("captcha_id", "")
        expected = self.issued.get(challenge_id)

        if supplied is None:
            if self.require_captcha:
                return httpx.Response(200, text="Invalid CAPTCHA")
        elif supplied == "" and not self.allow_empty:
            return httpx.Response(200, text="Invalid CAPTCHA")
        elif supplied:
            if expected is None or supplied.casefold() != expected.casefold():
                return httpx.Response(200, text="Invalid CAPTCHA")
            if not self.single_use:
                pass
            else:
                self.issued.pop(challenge_id, None)

        if self.valid_password and form.get("password") == self.valid_password:
            return httpx.Response(200, text="Welcome back")
        return httpx.Response(200, text="Invalid username or password")


@pytest.fixture
def json_profile():
    return LoginProfile(
        login_url="https://app.example.test/login",
        captcha_url="https://app.example.test/captcha.png",
        captcha_response="json",
        captcha_image_key="data.image",
        captcha_id_key="data.id",
        captcha_id_field="captcha_id",
        username="auditee",
        criteria=SuccessCriteria(
            captcha_failure=["invalid captcha"],
            auth_failure=["invalid username or password"],
            success=["welcome back"],
        ),
    )


@respx.mock
@pytest.mark.asyncio
async def test_solve_rate_works_against_a_json_captcha_api(json_profile, client):
    mount(JsonCaptchaApp(answer="A8R36"))
    solver = ScriptedSolver(["A8R36", "A8R36", "NOPE", "A8R36"])
    findings = await CaptchaSolveRate(json_profile, solver, samples=4).run(TARGET, client)

    assert findings[0].evidence["solved"] == 3
    assert findings[0].evidence["wrong"] == 1


@respx.mock
@pytest.mark.asyncio
async def test_challenge_id_reaches_the_login_request(json_profile, client):
    app = JsonCaptchaApp(answer="A8R36")
    mount(app)
    seen: list[str] = []

    def capture(request):
        form = {
            k: v[0] for k, v in parse_qs(request.content.decode(), keep_blank_values=True).items()
        }
        seen.append(form.get("captcha_id", ""))
        return app.login(request)

    respx.post("https://app.example.test/login").mock(side_effect=capture)
    await CaptchaSolveRate(json_profile, ScriptedSolver(["A8R36"] * 3), samples=3).run(
        TARGET, client
    )

    assert seen == ["ch-1", "ch-2", "ch-3"], "each attempt must carry its own challenge id"


@respx.mock
@pytest.mark.asyncio
async def test_gate_clean_against_a_correct_json_api(json_profile, client):
    mount(JsonCaptchaApp())
    findings = await CaptchaGate(json_profile, ScriptedSolver(["A8R36"] * 4)).run(TARGET, client)
    assert findings == []


@respx.mock
@pytest.mark.asyncio
async def test_gate_flags_replayable_challenge_id(json_profile, client):
    """A (id, answer) pair the server does not burn is replayable."""
    mount(JsonCaptchaApp(single_use=False))
    findings = await CaptchaGate(json_profile, ScriptedSolver(["A8R36"] * 4)).run(TARGET, client)
    assert any("can be replayed" in f.title for f in findings)


@respx.mock
@pytest.mark.asyncio
async def test_misconfigured_profile_reports_what_to_fix(client):
    """Pointing at the wrong JSON key must not look like a hard CAPTCHA."""
    mount(JsonCaptchaApp())
    profile = LoginProfile(
        login_url="https://app.example.test/login",
        captcha_url="https://app.example.test/captcha.png",
        captcha_response="json",
        captcha_image_key="wrong_key",
        criteria=SuccessCriteria(
            captcha_failure=["invalid captcha"], auth_failure=["invalid username or password"]
        ),
    )
    findings = await CaptchaSolveRate(profile, ScriptedSolver(["A8R36"]), samples=3).run(
        TARGET, client
    )
    assert findings[0].title == "cannot read the CAPTCHA endpoint"
    assert "wrong_key" in findings[0].description


# --------------------------------------------------------------------------
# multi-identity credential audit
# --------------------------------------------------------------------------


def wordlists(tmp_path, users, passwords):
    u = tmp_path / "users.txt"
    p = tmp_path / "pass.txt"
    u.write_text("\n".join(users), encoding="utf-8")
    p.write_text("\n".join(passwords), encoding="utf-8")
    return u, p


@respx.mock
@pytest.mark.asyncio
async def test_spray_order_tries_every_identity_before_the_next_password(profile, client, tmp_path):
    app = FakeApp(valid_password=None)
    mount(app)
    users, passwords = wordlists(tmp_path, ["alice", "bob", "carol"], ["pw1", "pw2"])
    seen: list[tuple[str, str]] = []

    def capture(request):
        form = {
            k: v[0] for k, v in parse_qs(request.content.decode(), keep_blank_values=True).items()
        }
        seen.append((form["username"], form["password"]))
        return app.login(request)

    respx.post("https://app.example.test/login").mock(side_effect=capture)
    module = CredentialAudit(
        profile, ScriptedSolver(["A8R36"] * 20), wordlist=passwords, users=users
    )
    await module.run(TARGET, client)

    assert seen == [
        ("alice", "pw1"),
        ("bob", "pw1"),
        ("carol", "pw1"),
        ("alice", "pw2"),
        ("bob", "pw2"),
        ("carol", "pw2"),
    ]


@respx.mock
@pytest.mark.asyncio
async def test_brute_order_exhausts_one_identity_first(profile, client, tmp_path):
    app = FakeApp(valid_password=None)
    mount(app)
    users, passwords = wordlists(tmp_path, ["alice", "bob"], ["pw1", "pw2"])
    seen: list[str] = []

    def capture(request):
        form = {
            k: v[0] for k, v in parse_qs(request.content.decode(), keep_blank_values=True).items()
        }
        seen.append(form["username"])
        return app.login(request)

    respx.post("https://app.example.test/login").mock(side_effect=capture)
    module = CredentialAudit(
        profile,
        ScriptedSolver(["A8R36"] * 20),
        wordlist=passwords,
        users=users,
        order="brute",
    )
    await module.run(TARGET, client)

    assert seen == ["alice", "alice", "bob", "bob"]


@respx.mock
@pytest.mark.asyncio
async def test_lockout_is_tracked_per_identity_not_globally(profile, client, tmp_path):
    """One account hitting its limit must not end the whole audit."""
    app = FakeApp(valid_password=None)
    mount(app)
    users, passwords = wordlists(tmp_path, ["alice", "bob"], [f"pw{i}" for i in range(6)])

    module = CredentialAudit(
        profile,
        ScriptedSolver(["A8R36"] * 40),
        wordlist=passwords,
        users=users,
        lockout_threshold=2,
    )
    findings = await module.run(TARGET, client)
    summary = findings[-1]

    # Each identity gets its own budget of 2, so 4 attempts total, not 2.
    assert summary.evidence["attempts"] == 4
    assert sorted(summary.evidence["stopped_for_lockout"]) == ["alice", "bob"]


@respx.mock
@pytest.mark.asyncio
async def test_a_compromised_identity_stops_being_tried(profile, client, tmp_path):
    mount(FakeApp(valid_password="pw1"))
    users, passwords = wordlists(tmp_path, ["alice", "bob"], ["pw1", "pw2", "pw3"])

    module = CredentialAudit(
        profile, ScriptedSolver(["A8R36"] * 40), wordlist=passwords, users=users
    )
    findings = await module.run(TARGET, client)

    criticals = [f for f in findings if f.severity is Severity.CRITICAL]
    assert len(criticals) == 2, "both accounts share the weak password"
    summary = findings[-1]
    assert sorted(summary.evidence["compromised"]) == ["alice", "bob"]
    # Found on the first password, so nothing else is attempted.
    assert summary.evidence["attempts"] == 2
    assert {f.evidence["password"] for f in criticals} == {"pw1"}


@respx.mock
@pytest.mark.asyncio
async def test_max_attempts_caps_the_run(profile, client, tmp_path):
    mount(FakeApp(valid_password=None))
    users, passwords = wordlists(tmp_path, ["a", "b", "c"], [f"pw{i}" for i in range(10)])

    module = CredentialAudit(
        profile,
        ScriptedSolver(["A8R36"] * 60),
        wordlist=passwords,
        users=users,
        lockout_threshold=99,
        max_attempts=5,
    )
    findings = await module.run(TARGET, client)
    assert findings[-1].evidence["attempts"] == 5


@respx.mock
@pytest.mark.asyncio
async def test_single_identity_still_works_without_a_user_list(profile, client, tmp_path):
    mount(FakeApp(valid_password="hunter2"))
    wordlist = tmp_path / "w.txt"
    wordlist.write_text("letmein\nhunter2\n", encoding="utf-8")

    findings = await CredentialAudit(
        profile, ScriptedSolver(["A8R36"] * 10), wordlist=wordlist
    ).run(TARGET, client)

    assert findings[0].evidence["username"] == "auditee"
    assert findings[0].evidence["wordlist_line"] == 2


def test_audit_needs_an_identity_from_somewhere(profile):
    profile.username = ""
    with pytest.raises(ValueError, match="username list"):
        CredentialAudit(profile, ScriptedSolver([]), wordlist="x")


def test_unknown_order_is_rejected(profile):
    with pytest.raises(ValueError, match="order must be one of"):
        CredentialAudit(profile, ScriptedSolver([]), wordlist="x", order="sideways")


@respx.mock
@pytest.mark.asyncio
async def test_unclassifiable_responses_are_flagged_not_ignored(profile, client, tmp_path):
    """A success the criteria miss looks exactly like a clean run otherwise."""
    app = FakeApp(valid_password="pw1")
    mount(app)
    # The app signals success with a phrase the profile does not know about.
    profile.criteria.success = Matcher(body=["a phrase this app never sends"])
    wordlist = tmp_path / "w.txt"
    wordlist.write_text("pw1\n", encoding="utf-8")

    findings = await CredentialAudit(profile, ScriptedSolver(["A8R36"] * 4), wordlist=wordlist).run(
        TARGET, client
    )

    summary = findings[-1]
    assert summary.evidence["unclassified"] == 1
    assert summary.severity is Severity.LOW
    assert "WARNING" in summary.description
    assert not [f for f in findings if f.severity is Severity.CRITICAL]


@respx.mock
@pytest.mark.asyncio
async def test_gate_reports_an_unreadable_rejection_as_inconclusive(profile, client):
    """An app with its own wording for a missing answer is not a broken gate.

    "CAPTCHA is required" matches neither criterion. Read as "not rejected for
    a missing CAPTCHA" it becomes a CRITICAL finding about a control that is
    in fact working - the one mistake this tool must never make in a client
    report.
    """
    respx.get("https://app.example.test/login").mock(
        return_value=httpx.Response(200, text=LOGIN_PAGE)
    )
    respx.get("https://app.example.test/captcha.png").mock(side_effect=FakeApp().captcha)
    respx.post("https://app.example.test/login").mock(
        return_value=httpx.Response(400, text="CAPTCHA is required")
    )

    findings = await CaptchaGate(profile, ScriptedSolver(["A8R36"] * 12)).run(TARGET, client)

    assert not [f for f in findings if f.severity >= Severity.MEDIUM]
    inconclusive = [f for f in findings if "inconclusive" in f.title]
    # Three: the two enforcement checks, plus replay - which cannot get a
    # confirmed-wrong login out of this app either, and says so rather than
    # returning nothing and reading as "the answer is single-use".
    assert len(inconclusive) == 3
    assert any("replay check inconclusive" in f.title for f in inconclusive)
    gate_checks = [f for f in inconclusive if "replay" not in f.title]
    assert gate_checks[0].evidence["outcome"] == "unknown"
    assert gate_checks[0].evidence["status_code"] == 400


@respx.mock
@pytest.mark.asyncio
async def test_gate_still_flags_a_gate_that_really_is_open(profile, client):
    """A recognised auth failure means the request got past the CAPTCHA."""
    mount(FakeApp(require_captcha=False, allow_empty=True))
    findings = await CaptchaGate(profile, ScriptedSolver(["A8R36"] * 4)).run(TARGET, client)

    assert any(f.severity is Severity.CRITICAL and "omitted" in f.title for f in findings)
    assert any("empty CAPTCHA value accepted" in f.title for f in findings)
    assert not [f for f in findings if "inconclusive" in f.title]


@respx.mock
@pytest.mark.asyncio
async def test_a_zero_solve_rate_is_reported_as_a_fact_about_the_engine(profile, client):
    """A zero says the engine could not read the images. Nothing more.

    The stock finding argues that a CAPTCHA is a cost multiplier rather than a
    control - true, but a run that solved nothing did not show it, and
    printing that argument under a zero claims a result the evidence does not
    contain.
    """
    mount(FakeApp(answer="A8R36"))
    module = CaptchaSolveRate(profile, ScriptedSolver(["WRONG"] * 5), samples=5)
    findings = await module.run(TARGET, client)

    finding = findings[0]
    assert finding.severity is Severity.INFO
    assert "no CAPTCHA solved by" in finding.title
    assert "not of how well the CAPTCHA resists automation" in finding.description
    assert "cost multiplier" not in finding.description
    # The operator is pointed at their own configuration, not at the target's.
    assert "--charset" in finding.remediation
    assert finding.evidence["solve_rate"] == 0.0
    assert finding.evidence["wrong_answers"] == ["WRONG"] * 5


@respx.mock
@pytest.mark.asyncio
async def test_a_solved_run_still_makes_the_argument(profile, client):
    mount(FakeApp(answer="A8R36"))
    module = CaptchaSolveRate(profile, ScriptedSolver(["A8R36"] * 5), samples=5)
    findings = await module.run(TARGET, client)

    finding = findings[0]
    assert "solved automatically in 100%" in finding.title
    assert "cost multiplier" in finding.description
    assert finding.severity is Severity.HIGH
    # Both shapes carry the same evidence keys, so two solver runs compare.
    assert finding.evidence["wrong_answers"] == []
    assert finding.evidence["solve_rate"] == 1.0


@respx.mock
@pytest.mark.asyncio
async def test_a_throttled_run_stops_and_says_so(profile, client):
    """A 429 is not an unclassifiable response, and not a CAPTCHA result.

    Counting throttles as "unknown" reads as a broken profile while quietly
    shrinking the sample the percentage is computed from - a run can lose half
    its attempts and still print a confident number.
    """
    app = FakeApp(answer="A8R36")
    mount(app)
    calls = {"n": 0}

    def limited(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] > 3:
            return httpx.Response(
                429,
                json={"message": "Too many requests. Please wait and try again."},
                headers={"Retry-After": "30"},
            )
        return app.login(request)

    respx.post("https://app.example.test/login").mock(side_effect=limited)
    module = CaptchaSolveRate(profile, ScriptedSolver(["A8R36"] * 20), samples=20)
    findings = await module.run(TARGET, client)

    limit = findings[0]
    assert "rate-limited the run after 3 attempts" in limit.title
    assert limit.severity is Severity.INFO
    assert limit.evidence["status_code"] == 429
    assert limit.evidence["retry_after_seconds"] == 30.0
    assert limit.evidence["samples_requested"] == 20
    # The measurement so far is still reported, from the attempts it did get.
    rate = findings[1]
    assert rate.evidence["solve_rate"] == 1.0
    assert rate.evidence["unknown"] == 0


@respx.mock
@pytest.mark.asyncio
async def test_a_throttle_without_the_status_is_still_recognised(profile, client):
    """Some applications answer 200 with a message instead of a 429."""
    app = FakeApp(answer="A8R36")
    mount(app)
    calls = {"n": 0}

    def limited(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] > 2:
            return httpx.Response(200, json={"message": "Too many attempts, slow down"})
        return app.login(request)

    respx.post("https://app.example.test/login").mock(side_effect=limited)
    findings = await CaptchaSolveRate(profile, ScriptedSolver(["A8R36"] * 9), samples=9).run(
        TARGET, client
    )
    assert "rate-limited" in findings[0].title


@respx.mock
@pytest.mark.asyncio
async def test_a_page_that_merely_mentions_rate_limiting_is_not_a_throttle(profile, client):
    """Ending a working run on a word in the page copy would be worse."""
    app = FakeApp(answer="A8R36")
    mount(app)
    page = "Invalid username or password. " + ("Our rate limit policy is described here. " * 20)
    respx.post("https://app.example.test/login").mock(return_value=httpx.Response(200, text=page))

    findings = await CaptchaSolveRate(profile, ScriptedSolver(["A8R36"] * 4), samples=4).run(
        TARGET, client
    )
    assert "rate-limited" not in findings[0].title
    assert findings[0].evidence["solved"] == 4


@respx.mock
@pytest.mark.asyncio
async def test_the_credential_audit_stops_when_throttled(profile, client, tmp_path):
    app = FakeApp(answer="A8R36", valid_password=None)
    mount(app)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("\n".join(f"pw{i}" for i in range(20)), encoding="utf-8")
    calls = {"n": 0}

    def limited(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] > 2:
            return httpx.Response(429, json={"message": "Too many requests"})
        return app.login(request)

    respx.post("https://app.example.test/login").mock(side_effect=limited)
    module = CredentialAudit(profile, ScriptedSolver(["A8R36"] * 40), wordlist=wordlist)
    summary = (await module.run(TARGET, client))[-1]

    assert summary.evidence["rate_limited_after"] == 3
    assert summary.evidence["attempts"] == 3, "the wordlist must not keep running"
    assert "began rate limiting" in summary.description
    assert summary.severity is Severity.LOW


@respx.mock
@pytest.mark.asyncio
async def test_a_replay_check_that_never_solved_is_not_reported_as_clean(profile, client):
    """The inverse of the usual failure: a check that could not run at all used
    to return nothing, and "no findings" reads as "the answer is single-use".
    A target whose answer reuse was never tested must not be credited for it."""
    mount(FakeApp(single_use=False))
    findings = await CaptchaGate(profile, ScriptedSolver(["NEVER"] * 20)).run(TARGET, client)

    assert findings, "a check that could not run must still be reported"
    assert any("replay check inconclusive" in f.title for f in findings)
    assert not any("can be replayed" in f.title for f in findings)
    assert all(f.severity is Severity.INFO for f in findings)
