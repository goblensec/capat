from __future__ import annotations

import secrets

import httpx

from capat.core.discovery import find_captcha_image
from capat.core.profile import LoginProfile, Outcome
from capat.core.result import Finding, Severity
from capat.core.target import Target
from capat.core.template import placeholders
from capat.core.throttle import (
    Throttled,
    rate_limit_finding,
)
from capat.http.client import HttpClient, Session
from capat.modules.base import Module
from capat.modules.login_flow import Attempt, LoginFlow
from capat.solvers.base import Solver, SolverUnavailable

REPLAY_TRIES = 5
"""Challenges to try to solve before calling the replay check inconclusive.

Five rather than three because an engine reading 70% of a target's images fails
three in a row about once in forty runs, and an inconclusive result that is
really just bad luck trains an operator to ignore the word."""


class CaptchaGate(Module):
    """Tests whether the CAPTCHA is enforced at all.

    Recognition accuracy is only interesting if the gate is real. In practice
    a large share of deployments fail before OCR ever matters: the field is
    validated only when present, the answer stays valid after use, or the same
    image is served every time. Each of these turns the CAPTCHA into a
    formality, and each is cheap to fix, so they belong in the report ahead of
    any solve-rate number.

    Every check here uses a random non-existent identity and a random
    password, so no real account is touched.
    """

    name = "captcha-gate"
    description = "Checks whether the CAPTCHA is required, single-use, and rotating."

    def __init__(
        self, profile: LoginProfile, solver: Solver | None = None, rotation_samples: int = 5
    ) -> None:
        self._profile = profile
        self._solver = solver
        self._rotation_samples = rotation_samples
        self._flow = LoginFlow(profile, solver)

    async def run(self, target: Target, client: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        try:
            # Every enforcement check below reads "the CAPTCHA was accepted" off
            # the absence of a CAPTCHA_FAILURE. With no captcha-failure criteria
            # that outcome is unreachable, so a rejection the operator's
            # auth-failure marker happens to match is read as an acceptance and
            # a correct target earns a CRITICAL. Rotation compares image bytes
            # and needs no criteria, so it still runs.
            enforcement_testable = not self._profile.criteria.captcha_failure.is_empty()
            if enforcement_testable:
                findings += await self._check_omitted(target, client)
                findings += await self._check_empty(target, client)
            else:
                findings.append(self._unconfigured(target))
            findings += await self._check_rotation(target, client)
            if self._solver is not None and enforcement_testable:
                findings += await self._check_replay(target, client)
        except Throttled as exc:
            findings.append(
                rate_limit_finding(
                    self.name,
                    target.url,
                    exc.status,
                    len(findings),
                    seconds=exc.retry_after,
                    where=exc.url,
                )
            )
        except SolverUnavailable as exc:
            findings.append(
                Finding(
                    module=self.name,
                    title="replay check skipped: solver unavailable",
                    target=target.url,
                    severity=Severity.INFO,
                    description=str(exc),
                )
            )
        except httpx.HTTPError as exc:
            findings.append(
                Finding(
                    module=self.name,
                    title="checks incomplete: request failed",
                    target=target.url,
                    severity=Severity.INFO,
                    description=str(exc),
                )
            )
        return findings

    def _throwaway(self) -> tuple[str, str]:
        return self._profile.probe_username, f"cb-{secrets.token_hex(16)}"

    def _inconclusive(self, target: Target, check: str, attempt: Attempt) -> Finding:
        """The application answered in a way the criteria do not describe.

        This is a gap in the profile, not a fact about the target. An
        application that rejects a missing answer with its own wording -
        "CAPTCHA is required", a 400 from a validation layer - looks exactly
        like one that never checked, unless the criteria say otherwise.
        Reporting that as a missing control would put a CRITICAL finding in
        front of a client on the strength of a phrase nobody configured.
        """
        return Finding(
            module=self.name,
            title=f"{check}: inconclusive, response not recognised",
            target=target.url,
            severity=Severity.INFO,
            description=(
                "The response matched neither the captcha-failure nor the auth-failure "
                "criteria, so it does not say whether the CAPTCHA was enforced. Until the "
                "criteria cover it, this check reports nothing about the target."
            ),
            remediation=(
                "Send the same request by hand, read the response, and add its wording to "
                "--captcha-fail (or --auth-fail, if the CAPTCHA was in fact accepted). "
                "Then re-run."
            ),
            evidence={"outcome": attempt.outcome.value, "status_code": attempt.status_code},
        )

    def _unconfigured(self, target: Target) -> Finding:
        """No captcha-failure criteria, so enforcement cannot be tested at all.

        Distinct from `_inconclusive`, which is one response the criteria did
        not describe. Here the criteria could never have described it: with
        `captcha_failure` unset, `classify` cannot return CAPTCHA_FAILURE, so
        "the CAPTCHA was rejected" and "the credentials were rejected" are the
        same answer. A broad --auth-fail such as "Invalid" then matches the
        CAPTCHA rejection and the omitted/empty checks report a missing
        control on a target that has one. Saying nothing instead would be the
        same defect pointing the other way, so it is said out loud.
        """
        return Finding(
            module=self.name,
            title="enforcement checks not run: no captcha-failure criteria",
            target=target.url,
            severity=Severity.INFO,
            description=(
                "Deciding whether a CAPTCHA is enforced means telling a rejected CAPTCHA "
                "apart from rejected credentials, and --captcha-fail is what draws that "
                "line. Without it every rejection looks alike, so whether the answer is "
                "required, and whether a used one can be replayed, are untested here. "
                "This is a gap in the run, not a result about the target."
            ),
            remediation=(
                "Submit a login with a deliberately wrong CAPTCHA by hand, read how the "
                "application rejects it, and pass that to --captcha-fail (-cf): a body "
                "substring, or status:/json: when the wording is shared. Then re-run."
            ),
        )

    async def _check_omitted(self, target: Target, client: HttpClient) -> list[Finding]:
        """Submit with the CAPTCHA field absent entirely."""
        username, password = self._throwaway()
        # A challenge is still requested, so any identifier the API expects is
        # present and correct. Only the answer is missing - that isolates
        # "the answer is not validated" from "the request was malformed".
        attempt = await self._flow.attempt(client, username, password, answer="", omit_captcha=True)
        if attempt.outcome is Outcome.CAPTCHA_FAILURE:
            return []
        if attempt.outcome is Outcome.UNKNOWN:
            return [self._inconclusive(target, "CAPTCHA-required check", attempt)]
        return [
            Finding(
                module=self.name,
                title="CAPTCHA not required when the field is omitted",
                target=target.url,
                severity=Severity.CRITICAL,
                description=(
                    "A login submitted with no CAPTCHA parameter at all was not rejected "
                    "for a missing CAPTCHA. The challenge is validated only when the client "
                    "chooses to send it, so any automated client can skip it outright. No "
                    "recognition is needed to defeat this."
                ),
                remediation=(
                    "Validate on the server that a CAPTCHA answer is present and bound to "
                    "the session before evaluating credentials. Treat a missing parameter "
                    "as a failed challenge, not as an absent one."
                ),
                evidence={
                    "outcome": attempt.outcome.value,
                    "status_code": attempt.status_code,
                },
            )
        ]

    async def _check_empty(self, target: Target, client: HttpClient) -> list[Finding]:
        """Submit with the CAPTCHA field present but empty."""
        username, password = self._throwaway()
        attempt = await self._flow.attempt(client, username, password, answer="")
        if attempt.outcome is Outcome.CAPTCHA_FAILURE:
            return []
        if attempt.outcome is Outcome.UNKNOWN:
            return [self._inconclusive(target, "empty-answer check", attempt)]
        return [
            Finding(
                module=self.name,
                title="empty CAPTCHA value accepted",
                target=target.url,
                severity=Severity.HIGH,
                description=(
                    "A login carrying an empty CAPTCHA value was not rejected for a bad "
                    "CAPTCHA. An empty answer is commonly compared against an unset "
                    "server-side value and matches it."
                ),
                remediation=(
                    "Reject empty and whitespace-only answers explicitly, and clear the "
                    "expected value from the session once it has been consumed."
                ),
                evidence={
                    "outcome": attempt.outcome.value,
                    "status_code": attempt.status_code,
                },
            )
        ]

    async def _check_rotation(self, target: Target, client: HttpClient) -> list[Finding]:
        """Fetch the CAPTCHA repeatedly in one session and compare the images.

        Comparison is on image bytes, not the identifier: an API that issues a
        fresh id every time while drawing from a small pool of images is still
        solvable once and replayable forever.

        What counts as "again" depends on the target. Where the URL is fixed,
        it is another request to it. Where the challenge is named in the URL,
        re-requesting one nonce is *supposed* to return the same image, so a
        sample is a fresh page load - otherwise this check would report every
        such application as static.
        """
        # An inline challenge and a per-load URL are both re-issued by loading
        # the page, so a sample has to be a page load rather than a repeat
        # request - see the docstring.
        per_load = (
            self._profile.discovers_captcha_url
            or self._profile.reads_inline_captcha
            or bool(placeholders(self._profile.captcha_url))
        )
        digests: list[str] = []
        urls: list[str] = []
        async with client.session() as session:
            context = await self._flow.fetch_form(session)
            for _ in range(self._rotation_samples):
                if per_load and digests:
                    context = await self._flow.fetch_form(session)
                urls.append(self._flow.captcha_url_for(context))
                challenge = await self._flow.fetch_captcha(session, context)
                digests.append(challenge.sha256)
            unique = len(set(digests))
            requested = urls[0]
            reissued = (
                await self._reissued_url(session, requested)
                if unique == 1 and not per_load
                else None
            )

        if unique == 1 and reissued:
            # We asked for one URL n times; of course the bytes matched. The
            # target rotates and we measured our own request, so this is the
            # operator's configuration, not a finding against the target.
            return [
                Finding(
                    module=self.name,
                    title="CAPTCHA rotation not measured: the challenge URL is per page load",
                    target=target.url,
                    severity=Severity.INFO,
                    description=(
                        f"Every request went to the same URL, {requested}, and returned the same "
                        "image - but the login page issues a different URL each time it is "
                        f"loaded (now {reissued}). A fixed URL cannot reach a fresh challenge "
                        "here, so this run says nothing about whether the target rotates."
                    ),
                    remediation=(
                        'Re-run with "captcha_url": "auto" (-c auto) to read the URL off '
                        "each login page, or name the varying part with a placeholder, e.g. "
                        "-c 'https://host/captcha?n={{nonce}}' "
                        "--extract 'nonce=regex:captcha[?]n=([^\"]+)'."
                    ),
                    evidence={
                        "samples": self._rotation_samples,
                        "unique_images": unique,
                        "requested_url": requested,
                        "page_now_offers": reissued,
                    },
                )
            ]
        if unique == 1:
            return [
                Finding(
                    module=self.name,
                    title="CAPTCHA image never changes",
                    target=target.url,
                    severity=Severity.HIGH,
                    description=(
                        (
                            f"{self._rotation_samples} fresh page loads returned byte-identical "
                            "images"
                            if per_load
                            else f"{self._rotation_samples} consecutive requests to {requested} "
                            "returned byte-identical images"
                        )
                        + ". A static challenge only has to be solved once, by hand, and the "
                        "answer can then be replayed indefinitely."
                    ),
                    remediation=(
                        "Generate a fresh challenge per request, bind it to the session, and "
                        "serve it with no-store cache headers."
                    ),
                    evidence={
                        "samples": self._rotation_samples,
                        "unique_images": unique,
                        "unique_urls": len(set(urls)),
                        "requested_url": requested,
                    },
                )
            ]
        if unique < self._rotation_samples:
            return [
                Finding(
                    module=self.name,
                    title="CAPTCHA images repeat within a session",
                    target=target.url,
                    severity=Severity.MEDIUM,
                    description=(
                        f"{self._rotation_samples} requests produced only {unique} distinct "
                        "images. A small challenge pool can be enumerated and solved once, "
                        "after which recognition is unnecessary."
                    ),
                    remediation=(
                        "Generate challenges on demand rather than serving from a fixed pool, "
                        "and check the cache headers on the image endpoint."
                    ),
                    evidence={"samples": self._rotation_samples, "unique_images": unique},
                )
            ]
        return []

    async def _reissued_url(self, session: Session, requested: str) -> str | None:
        """The image URL the login page advertises now, if it is a different one.

        Costs one extra GET and only runs when every sampled image matched,
        which is exactly when the answer decides whether that is a finding
        about the target or about how the run was configured.
        """
        resp = await session.get(
            self._profile.page_url, headers=self._profile.static_headers() or None
        )
        found = find_captcha_image(resp.text, str(resp.url))
        return found if found and found != requested else None

    async def _check_replay(self, target: Target, client: HttpClient) -> list[Finding]:
        """Solve once, then submit the same answer twice in one session.

        If the second submission is not rejected for a bad CAPTCHA, the answer
        survives use and one solve can be amortised across many attempts. Where
        the API issues an identifier, the same identifier is replayed with it -
        that pair is what the server is supposed to burn after one check.
        """
        # A misread costs the whole check, so try a few challenges before
        # giving up - and report that it was given up on. Returning [] here
        # put "no findings" in a report for a target whose answer reuse was
        # never actually tested.
        if self._profile.criteria.auth_failure.is_empty():
            # _replay_once discards any attempt whose control submission is not
            # AUTH_FAILURE. With no auth-failure criteria that is every attempt,
            # and the loop below would blame the solver for a missing marker.
            return [
                Finding(
                    module=self.name,
                    title="replay check not run: no auth-failure criteria",
                    target=target.url,
                    severity=Severity.INFO,
                    description=(
                        "Replay submits a correct answer twice and needs the first "
                        "submission to be recognised as a credential rejection, which is "
                        "what --auth-fail describes. Without it no attempt can be "
                        "confirmed, so answer reuse is untested here."
                    ),
                    remediation=(
                        "Set --auth-fail (-af) to the wording the application uses for a "
                        "wrong password, then re-run."
                    ),
                )
            ]
        for _ in range(REPLAY_TRIES):
            decided = await self._replay_once(target, client)
            if decided is not None:
                return decided
        return [
            Finding(
                module=self.name,
                title="replay check inconclusive: could not solve a CAPTCHA to test with",
                target=target.url,
                severity=Severity.INFO,
                description=(
                    f"Replay needs one correct answer to submit twice, and {REPLAY_TRIES} "
                    "attempts did not produce one. Whether a used answer stays valid is "
                    "therefore untested here - this is a limit of the run, not a result "
                    "about the target."
                ),
                remediation=(
                    "Raise the solve rate and re-run: set -l and --charset, tune preprocessing "
                    "with 'capat solve --save-processed', or point -s at a model trained on "
                    "this target's images."
                ),
                evidence={"tries": REPLAY_TRIES},
            )
        ]

    async def _replay_once(self, target: Target, client: HttpClient) -> list[Finding] | None:
        """One replay attempt. None means it proved nothing and can be retried."""
        username, password = self._throwaway()
        async with client.session() as session:
            context = await self._flow.fetch_form(session)
            challenge = await self._flow.fetch_captcha(session, context)
            result = await self._flow.solve(challenge.image)
            if not result.text:
                return None

            first = await self._flow.submit(
                session,
                username,
                f"cb-{secrets.token_hex(16)}",
                result.text,
                context,
                challenge_id=challenge.challenge_id,
            )
            if self._flow.classify(first) is not Outcome.AUTH_FAILURE:
                # The solve was wrong (or unclassifiable); this run proves nothing.
                return None

            second = await self._flow.submit(
                session,
                username,
                password,
                result.text,
                context,
                challenge_id=challenge.challenge_id,
            )
            outcome = self._flow.classify(second)

        if outcome is not Outcome.CAPTCHA_FAILURE:
            return [
                Finding(
                    module=self.name,
                    title="solved CAPTCHA can be replayed",
                    target=target.url,
                    severity=Severity.HIGH,
                    description=(
                        "The same CAPTCHA answer was accepted twice in one session. The answer "
                        "is not invalidated once consumed, so the cost of one solve is spread "
                        "across every subsequent attempt and the challenge stops being a "
                        "per-request control."
                    ),
                    remediation=(
                        "Delete the expected answer from the session as soon as it is checked, "
                        "regardless of whether the login succeeded, and issue a new challenge "
                        "for the next attempt."
                    ),
                    evidence={"second_attempt_outcome": outcome.value},
                )
            ]
        return []
        return []
