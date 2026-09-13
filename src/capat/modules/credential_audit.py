from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from capat import trace
from capat.core.profile import LoginProfile, Outcome
from capat.core.result import Finding, Severity
from capat.core.target import Target
from capat.core.throttle import Throttled, rate_limit_finding
from capat.http.client import HttpClient
from capat.modules.base import Module
from capat.modules.login_flow import LoginFlow
from capat.solvers.base import Solver, SolverUnavailable

ORDERS = ("spray", "brute")


def human_duration(seconds: float) -> str:
    """`1m 47s` rather than `107.3` - a run length is read, not calculated."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, rest = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {rest:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m {rest:02d}s"


def stream_wordlist(path: str | Path) -> Iterator[tuple[int, str]]:
    """Yield (line number, value) lazily.

    Streamed rather than read whole: engagement wordlists run to hundreds of
    megabytes and the line number is what the report refers to, so the secret
    itself never has to be stored or logged.
    """
    seen: set[str] = set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, start=1):
            candidate = line.rstrip("\r\n")
            if not candidate or candidate.lstrip().startswith("#"):
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            yield lineno, candidate


def load_wordlist(path: str | Path) -> list[tuple[int, str]]:
    return list(stream_wordlist(path))


@dataclass(slots=True)
class Identity:
    """Per-account state. Lockout budgets are per identity, never global."""

    username: str
    failures: int = 0
    attempts: int = 0
    found_at_line: int | None = None
    found_password: str = ""
    locked: bool = False

    @property
    def done(self) -> bool:
        return self.locked or self.found_at_line is not None


@dataclass(slots=True)
class AuditState:
    identities: dict[str, Identity] = field(default_factory=dict)
    attempts: int = 0
    captcha_failures: int = 0
    started: float = field(default_factory=time.monotonic)
    elapsed: float = 0.0
    throttled_after: int | None = None
    """Attempts completed when the target started rate limiting, if it did."""

    captcha_skipped: int = 0
    """Passwords never tested because the CAPTCHA was never solved for them."""

    unknown: int = 0

    def active(self) -> list[Identity]:
        return [i for i in self.identities.values() if not i.done]


class CredentialAudit(Module):
    """Demonstrates the consequence: the CAPTCHA does not stop the attempt.

    This is the end-to-end part of the proof. It takes a password list and,
    optionally, a username list - the pairing a real credential test uses. It
    is opt-in, lockout-aware per identity, and deliberately slow. It exists to
    show that solving the challenge feeds straight back into the login flow,
    not to be an efficient cracker.

    Ordering matters for safety, so it is a deliberate choice:

    - `spray` (default) walks passwords on the outside and identities on the
      inside. Every account accrues at most one failure per password, so the
      run stays far from any lockout policy for as long as possible and a
      single account hitting its limit does not end the audit.
    - `brute` exhausts one identity before moving on, the classic ordering. It
      reaches a lockout threshold in the fewest possible attempts, so it is
      only sensible when the policy is known to be permissive.

    A discovered password is reported in full, with the wordlist line it came
    from. It is the finding: an operator has to verify it, and a report that
    withholds it makes the reader take the tool's word for the one claim that
    matters most. The consequence is that a findings file holds a live
    credential - handle and store it accordingly.
    """

    name = "credential-audit"
    description = "Runs a credential test straight through the CAPTCHA (opt-in)."
    requires_solver = True
    opt_in = True

    def __init__(
        self,
        profile: LoginProfile,
        solver: Solver,
        wordlist: str | Path,
        users: str | Path | None = None,
        lockout_threshold: int = 4,
        ignore_lockout: bool = False,
        max_attempts: int | None = None,
        order: str = "spray",
        captcha_retries: int = 3,
    ) -> None:
        if users is None and not profile.username:
            raise ValueError(
                "credential audit needs either 'username' in the profile or a username list"
            )
        if order not in ORDERS:
            raise ValueError(f"order must be one of: {', '.join(ORDERS)}")
        self._profile = profile
        self._solver = solver
        self._wordlist = wordlist
        self._users = users
        self._lockout_threshold = lockout_threshold
        self._ignore_lockout = ignore_lockout
        self._max_attempts = max_attempts
        self._order = order
        self._captcha_retries = max(0, captcha_retries)
        self._flow = LoginFlow(profile, solver)

    def _usernames(self) -> list[str]:
        if self._users is None:
            return [self._profile.username]
        names = [name for _, name in load_wordlist(self._users)]
        if not names:
            raise ValueError(f"username list {self._users} is empty")
        return names

    async def run(self, target: Target, client: HttpClient) -> list[Finding]:
        try:
            state = AuditState(identities={name: Identity(name) for name in self._usernames()})
        except OSError as exc:
            return [self._info(target, "username list could not be read", str(exc))]

        try:
            if self._order == "spray":
                await self._spray(client, state)
            else:
                await self._brute(client, state)
        except Throttled as exc:
            return [
                rate_limit_finding(
                    self.name,
                    target.url,
                    exc.status,
                    state.attempts,
                    seconds=exc.retry_after,
                    where=exc.url,
                )
            ]
        except SolverUnavailable as exc:
            return [self._info(target, "solver unavailable", str(exc))]
        except OSError as exc:
            return [self._info(target, "wordlist could not be read", str(exc))]
        except httpx.HTTPError as exc:
            return [
                self._info(
                    target,
                    "audit aborted: request failed",
                    str(exc),
                    {"attempts": state.attempts},
                )
            ]

        state.elapsed = time.monotonic() - state.started
        return self._report(target, state)

    # -- ordering ----------------------------------------------------------

    async def _spray(self, client: HttpClient, state: AuditState) -> None:
        """One password across every live identity, then the next password."""
        for lineno, password in stream_wordlist(self._wordlist):
            if self._exhausted(state):
                return
            for identity in state.active():
                if self._exhausted(state):
                    return
                await self._try(client, state, identity, password, lineno)

    async def _brute(self, client: HttpClient, state: AuditState) -> None:
        """One identity to exhaustion, then the next."""
        for identity in list(state.identities.values()):
            if self._exhausted(state):
                return
            for lineno, password in stream_wordlist(self._wordlist):
                if identity.done or self._exhausted(state):
                    break
                await self._try(client, state, identity, password, lineno)

    def _exhausted(self, state: AuditState) -> bool:
        if state.throttled_after is not None:
            return True
        if self._max_attempts is not None and state.attempts >= self._max_attempts:
            return True
        return not state.active()

    async def _try(
        self,
        client: HttpClient,
        state: AuditState,
        identity: Identity,
        password: str,
        lineno: int,
    ) -> None:
        # A password whose CAPTCHA was misread has not been tested. Dropping it
        # would silently shrink the wordlist - at a 25% solve rate, three
        # quarters of an engagement's passwords would never reach the
        # application, and the run would report a clean result for words it
        # never tried. Retry the same password until the challenge is passed.
        for remaining in range(self._captcha_retries, -1, -1):
            attempt = await self._flow.attempt(client, identity.username, password)
            state.attempts += 1
            identity.attempts += 1
            if attempt.throttled:
                state.throttled_after = state.attempts
                trace.note(
                    f"target is rate limiting (HTTP {attempt.status_code}) - stopping",
                    "[?]",
                    "bold magenta",
                )
                return
            if attempt.outcome is not Outcome.CAPTCHA_FAILURE:
                break
            state.captcha_failures += 1
            if remaining:
                trace.note(
                    f"captcha misread, retrying {password!r} ({remaining} left)", "[!]", "red"
                )
        else:
            state.captcha_skipped += 1
            trace.note(
                f"gave up on {password!r}: the CAPTCHA was never solved, password NOT tested",
                "[?]",
                "bold magenta",
            )
            return

        if attempt.outcome is Outcome.SUCCESS:
            identity.found_at_line = lineno
            identity.found_password = password
            return
        if attempt.outcome is Outcome.AUTH_FAILURE:
            identity.failures += 1
            if not self._ignore_lockout and identity.failures >= self._lockout_threshold:
                identity.locked = True
            return
        # Unclassifiable. This matters more here than anywhere else: a success
        # the criteria failed to recognise is indistinguishable from a clean
        # run, so it is counted and reported rather than passed over.
        state.unknown += 1

    # -- reporting ---------------------------------------------------------

    def _report(self, target: Target, state: AuditState) -> list[Finding]:
        findings = [
            self._credentials_found(target, identity, state.attempts)
            for identity in state.identities.values()
            if identity.found_at_line is not None
        ]
        findings.append(self._summary(target, state))
        return findings

    def _credentials_found(
        self, target: Target, identity: Identity, total_attempts: int
    ) -> Finding:
        return Finding(
            module=self.name,
            title=(f"valid credentials found: {identity.username}:{identity.found_password}"),
            target=target.url,
            severity=Severity.CRITICAL,
            description=(
                f"An authenticated session was obtained after {identity.attempts} automated "
                f"attempts against this account ({total_attempts} across the run), each of "
                "which solved the CAPTCHA on the way through. The challenge did not raise the "
                "cost of the attack in any way that mattered."
            ),
            remediation=(
                "Enforce per-account and per-source rate limits with backoff, require a second "
                "factor, and alert on repeated failures. Do not count the CAPTCHA as the "
                "control that prevents credential guessing."
            ),
            evidence={
                "username": identity.username,
                "password": identity.found_password,
                "wordlist_line": identity.found_at_line,
                "attempts_for_identity": identity.attempts,
            },
        )

    def _summary(self, target: Target, state: AuditState) -> Finding:
        found = [i for i in state.identities.values() if i.found_at_line is not None]
        locked = [i for i in state.identities.values() if i.locked]
        # Every attempt not rejected at the CAPTCHA got past it, whatever the
        # application then made of the credentials.
        passed_captcha = state.attempts - state.captcha_failures
        rate = passed_captcha / state.attempts if state.attempts else 0.0
        per_attempt = state.elapsed / state.attempts if state.attempts else 0.0

        parts = [
            f"{state.attempts} automated attempts across {len(state.identities)} "
            f"{'identity' if len(state.identities) == 1 else 'identities'}, "
            f"in {human_duration(state.elapsed)} ({per_attempt:.1f}s each)",
            f"the CAPTCHA was solved on {passed_captcha} of {state.attempts} "
            f"({rate:.1%}), and those reached credential evaluation; "
            f"{state.captcha_failures} were rejected at the CAPTCHA",
        ]
        if locked:
            parts.append(
                f"{len(locked)} {'identity' if len(locked) == 1 else 'identities'} stopped "
                f"at the lockout threshold ({self._lockout_threshold}) and "
                f"{'was' if len(locked) == 1 else 'were'} not tested further"
            )
        if state.throttled_after is not None:
            parts.append(
                f"STOPPED: the target began rate limiting after {state.throttled_after} "
                "attempts and the audit went no further. The wordlist was not exhausted, so "
                "this is not a clean result - but a working rate limit is the control that "
                "matters here, and it belongs in the report"
            )
        if not found:
            parts.append("no valid credentials were found")
        if state.captcha_skipped:
            parts.append(
                f"WARNING: {state.captcha_skipped} password(s) were never tested - the CAPTCHA "
                f"was misread {self._captcha_retries + 1} times running for each, so they "
                "never reached the application. Raise --captcha-retries, or tune the solver "
                "with 'bench' first; a clean result does not cover them"
            )
        if state.unknown:
            parts.append(
                f"WARNING: {state.unknown} responses matched none of the criteria. A valid "
                "login the profile does not recognise would look exactly like this - check "
                "the success matcher before trusting the result"
            )

        return Finding(
            module=self.name,
            title=(
                f"credential audit complete: {len(found)} of {len(state.identities)} "
                f"{'identity' if len(state.identities) == 1 else 'identities'} compromised"
            ),
            target=target.url,
            # An unclassifiable response may be an unrecognised success, so the
            # run stops being a clean "nothing found" result.
            severity=(
                Severity.LOW
                if state.unknown or state.captcha_skipped or state.throttled_after is not None
                else Severity.INFO
            ),
            # Each clause is written to stand alone, so the joiner capitalises
            # rather than the clauses carrying leading capitals a mid-sentence
            # use would not want. WARNING: and STOPPED: prefixes survive it.
            description=". ".join(p[0].upper() + p[1:] if p else p for p in parts) + ".",
            evidence={
                "order": self._order,
                "attempts": state.attempts,
                "identities": len(state.identities),
                "compromised": [i.username for i in found],
                "stopped_for_lockout": [i.username for i in locked],
                "passed_captcha": passed_captcha,
                "failed_captcha": state.captcha_failures,
                "captcha_solve_rate": round(rate, 4),
                "duration_seconds": round(state.elapsed, 1),
                "seconds_per_attempt": round(per_attempt, 2),
                "passwords_never_tested": state.captcha_skipped,
                "rate_limited_after": state.throttled_after,
                "unclassified": state.unknown,
            },
        )

    def _info(
        self,
        target: Target,
        title: str,
        description: str,
        evidence: dict[str, object] | None = None,
    ) -> Finding:
        return Finding(
            module=self.name,
            title=title,
            target=target.url,
            severity=Severity.INFO,
            description=description,
            evidence=evidence or {},
        )
