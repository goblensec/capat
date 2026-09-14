from __future__ import annotations

import secrets
import statistics

import httpx

from capat.core.profile import LoginProfile, Outcome
from capat.core.result import Finding, Severity
from capat.core.target import Target
from capat.core.throttle import Throttled, rate_limit_finding
from capat.http.client import HttpClient
from capat.modules.base import Module
from capat.modules.login_flow import LoginFlow
from capat.solvers.base import Solver, SolverUnavailable


class CaptchaSolveRate(Module):
    """Measures how often the deployed CAPTCHA is defeated automatically.

    The method needs no labeled data and no valid credentials. Each attempt
    submits a solved CAPTCHA together with a random, non-existent username and
    a random password, then reads which way the application rejected it:

        "invalid captcha"  -> the solve was wrong
        "invalid login"    -> the solve was RIGHT; the CAPTCHA was passed

    Because the identity does not exist nothing can be locked out, and because
    the password is random nothing can accidentally succeed.
    """

    name = "captcha-solve-rate"
    description = "Measures the automated solve rate of the live CAPTCHA."
    requires_solver = True

    def __init__(self, profile: LoginProfile, solver: Solver, samples: int = 25) -> None:
        self._profile = profile
        self._solver = solver
        self._samples = samples
        self._flow = LoginFlow(profile, solver)

    async def run(self, target: Target, client: HttpClient) -> list[Finding]:
        if not self._profile.criteria.is_usable():
            return [
                Finding(
                    module=self.name,
                    title="cannot measure: response markers incomplete",
                    target=target.url,
                    severity=Severity.INFO,
                    description=(
                        "Measuring a live CAPTCHA requires telling a rejected CAPTCHA apart "
                        "from rejected credentials. Set both captcha_failure and auth_failure "
                        "markers in the profile, or run the offline bench command against a "
                        "labeled corpus instead."
                    ),
                )
            ]

        try:
            # Keep model loading out of the first measured solve.
            await self._solver.warmup()
        except SolverUnavailable as exc:
            return [
                Finding(
                    module=self.name,
                    title="solver unavailable",
                    target=target.url,
                    severity=Severity.INFO,
                    description=str(exc),
                )
            ]

        solved = wrong = unknown = 0
        latencies: list[float] = []
        confidences: list[float] = []
        samples: list[dict[str, object]] = []

        for _ in range(self._samples):
            try:
                attempt = await self._flow.attempt(
                    client,
                    username=self._profile.probe_username,
                    password=f"cb-{secrets.token_hex(16)}",
                )
            except Throttled as exc:
                # Reached before the login response could carry the flag, so
                # the run stops here with the same finding it would have made.
                return [
                    rate_limit_finding(
                        self.name,
                        target.url,
                        exc.status,
                        solved + wrong,
                        asked=self._samples,
                        seconds=exc.retry_after,
                        where=exc.url,
                    )
                ]
            except SolverUnavailable as exc:
                return [
                    Finding(
                        module=self.name,
                        title="solver unavailable",
                        target=target.url,
                        severity=Severity.INFO,
                        description=str(exc),
                    )
                ]
            except httpx.HTTPError as exc:
                return self._network_finding(target, exc, solved + wrong)
            except ValueError as exc:
                # The CAPTCHA endpoint did not look the way the profile says.
                return [
                    Finding(
                        module=self.name,
                        title="cannot read the CAPTCHA endpoint",
                        target=target.url,
                        severity=Severity.INFO,
                        description=str(exc),
                    )
                ]

            if attempt.throttled:
                # Everything after this point would measure the limiter.
                return [
                    rate_limit_finding(
                        self.name,
                        target.url,
                        attempt.status_code,
                        solved + wrong,
                        asked=self._samples,
                        seconds=attempt.retry_after,
                    ),
                    *self._report(target, solved, wrong, unknown, latencies, confidences, samples),
                ]

            if attempt.solve_seconds:
                latencies.append(attempt.solve_seconds)
            confidences.append(attempt.confidence)

            if attempt.outcome is Outcome.AUTH_FAILURE:
                solved += 1
            elif attempt.outcome is Outcome.CAPTCHA_FAILURE:
                wrong += 1
            elif attempt.outcome is Outcome.SUCCESS:
                return [self._random_password_accepted(target, attempt.final_url)]
            else:
                unknown += 1

            samples.append({"outcome": attempt.outcome.value, "guess": attempt.solved})

        return self._report(target, solved, wrong, unknown, latencies, confidences, samples)

    def _report(
        self,
        target: Target,
        solved: int,
        wrong: int,
        unknown: int,
        latencies: list[float],
        confidences: list[float],
        samples: list[dict[str, object]],
    ) -> list[Finding]:
        conclusive = solved + wrong
        if not conclusive:
            return [
                Finding(
                    module=self.name,
                    title="no conclusive attempts",
                    target=target.url,
                    severity=Severity.INFO,
                    description=(
                        f"All {unknown} attempts were unclassifiable. The response markers in "
                        "the profile most likely do not match what this application returns."
                    ),
                    evidence={"unknown": unknown, "samples": samples[:5]},
                )
            ]

        rate = solved / conclusive
        mean_latency = statistics.fmean(latencies) if latencies else 0.0
        # Below a millisecond the figure is measuring the harness, not the
        # engine, and a throughput extrapolated from it would be fiction.
        per_hour = (3600.0 / mean_latency * rate) if mean_latency >= 0.001 else None

        severity = (
            Severity.HIGH
            if rate >= 0.30
            else Severity.MEDIUM
            if rate >= 0.10
            else Severity.LOW
            if rate > 0
            else Severity.INFO
        )

        throughput = (
            f" at {mean_latency:.2f}s per solve, so one unoptimised process would clear "
            f"roughly {per_hour:,.0f} CAPTCHAs per hour on recognition cost alone"
            if per_hour is not None
            else ""
        )

        if not solved:
            # Nothing was read, so there is nothing to say about the target.
            # The stock description argues that a CAPTCHA is only a cost
            # multiplier - true, but this run did not show it, and printing
            # that argument under a zero would be claiming a result the
            # evidence does not contain. What a zero measures is the engine.
            return [
                Finding(
                    module=self.name,
                    title=f"no CAPTCHA solved by {self._solver.name} in {conclusive} attempts",
                    target=target.url,
                    severity=Severity.INFO,
                    description=(
                        f"{self._solver.name} read none of {conclusive} challenges "
                        f"correctly, at {mean_latency:.2f}s per attempt. "
                        "That is a measurement of this engine on these images, not of how well "
                        "the CAPTCHA resists automation: another engine, or preprocessing tuned "
                        "for this target, may read the same images. Do not report a zero as "
                        "evidence that the challenge holds."
                    ),
                    remediation=(
                        # Recommending the engine that just scored zero reads as
                        # boilerplate and costs the rest of the advice its
                        # credibility, so it is only offered to someone not on it.
                        (
                            ""
                            if self._solver.name == "ddddocr"
                            else "Try -s ddddocr (CAPTCHA-trained, and far less affected by "
                            "touching glyphs than a general scene-text engine). "
                        )
                        + "Set -l and --charset to the shape of the code, and tune "
                        "--min-saturation, --threshold and --dilate with "
                        "'capat solve --save-processed' to see what the engine is actually "
                        "being given. A model trained on this target's own images loads with "
                        "-s model.onnx."
                    ),
                    evidence=self._evidence(
                        rate, solved, wrong, unknown, mean_latency, confidences, per_hour, samples
                    ),
                )
            ]

        return [
            Finding(
                module=self.name,
                title=f"CAPTCHA solved automatically in {rate:.0%} of attempts",
                target=target.url,
                severity=severity,
                description=(
                    f"{solved} of {conclusive} conclusive attempts passed the CAPTCHA using "
                    f"off-the-shelf OCR ({self._solver.name}){throughput}. An image CAPTCHA is a "
                    "cost multiplier, not an access control: it does not have to fail every time "
                    "to be defeated, only often enough."
                ),
                remediation=(
                    "Do not rely on image recognition difficulty as the control. Rate-limit and "
                    "lock out per account and per source address, add exponential backoff on "
                    "repeated failures, and base the bot decision on signals a client cannot "
                    "replay. Where a challenge is still wanted, prefer an attested or "
                    "privacy-preserving one over distorted text."
                ),
                evidence=self._evidence(
                    rate, solved, wrong, unknown, mean_latency, confidences, per_hour, samples
                ),
            )
        ]

    def _evidence(
        self,
        rate: float,
        solved: int,
        wrong: int,
        unknown: int,
        mean_latency: float,
        confidences: list[float],
        per_hour: float | None,
        samples: list[dict[str, object]],
    ) -> dict[str, object]:
        """The same shape whatever the rate, so two solver runs compare directly."""
        return {
            "solver": self._solver.name,
            "solve_rate": round(rate, 4),
            "solved": solved,
            "wrong": wrong,
            "unknown": unknown,
            "attempts": self._samples,
            "mean_solve_seconds": round(mean_latency, 3),
            "mean_confidence": round(statistics.fmean(confidences) if confidences else 0.0, 3),
            # Recognition cost only. Real-world throughput is bounded by the
            # network and by whatever rate limiting the target applies - which
            # is exactly the control this measurement argues should be doing
            # the work.
            "recognition_solves_per_hour": (round(per_hour, 1) if per_hour is not None else None),
            # What the engine actually produced when it was wrong. Reading a
            # handful of those is the fastest way to see whether the fix is a
            # charset, a length, or different preprocessing entirely.
            "wrong_answers": [
                record.get("guess")
                for record in samples
                if record.get("outcome") == Outcome.CAPTCHA_FAILURE.value
            ][:8],
        }

    def _random_password_accepted(self, target: Target, final_url: str) -> Finding:
        return Finding(
            module=self.name,
            title="random credentials were accepted",
            target=target.url,
            severity=Severity.CRITICAL,
            description=(
                "A non-existent username with a random password produced a success response. "
                "The measurement was stopped. Either authentication is broken, or the success "
                "markers in the profile match a page that is not an authenticated session."
            ),
            remediation="Verify the success markers in the profile, then investigate the endpoint.",
            evidence={"final_url": final_url},
        )

    def _network_finding(
        self, target: Target, exc: httpx.HTTPError, completed: int
    ) -> list[Finding]:
        return [
            Finding(
                module=self.name,
                title="measurement aborted: request failed",
                target=target.url,
                severity=Severity.INFO,
                description=str(exc),
                evidence={"completed": completed},
            )
        ]
