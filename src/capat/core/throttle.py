"""Recognising that the target has started rate limiting.

A throttled response is not an unclassifiable one. It says nothing about the
CAPTCHA, and counting it as "unknown" reads as a broken profile while quietly
shrinking the sample the measurement is computed from - a run can lose half
its attempts and still print a confident percentage.

It is also the single most useful thing this tool can find. Rate limiting per
account and per source is exactly the control the report recommends; a target
that already has one deserves to be told so, not to have the finding buried.

So a throttle stops the run. Carrying on would measure the limiter, and the
honest response to being asked to slow down is to slow down.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from capat.core.result import Finding

__all__ = ["RATE_LIMIT_STATUS", "Throttled", "rate_limit_finding", "retry_after", "throttled"]

RATE_LIMIT_STATUS = 429

# Applications that answer 200 with a message rather than the status.
PHRASES = re.compile(
    r"too many (requests|attempts|tries)|rate.?limit|slow down|try again (later|in a)",
    re.IGNORECASE,
)


class Throttled(Exception):
    """Raised when any request in an attempt is answered with a throttle.

    An exception rather than a return value because it has to interrupt the
    attempt wherever it happens: the login page, the CAPTCHA endpoint, or the
    login itself. Every module catches it and reports the same finding.
    """

    def __init__(self, url: str, status: int, retry_after: float | None = None) -> None:
        super().__init__(f"{url} answered HTTP {status} (rate limited)")
        self.url = url
        self.status = status
        self.retry_after = retry_after


def raise_for_throttle(resp: httpx.Response) -> None:
    if throttled(resp):
        raise Throttled(str(resp.url), resp.status_code, retry_after(resp))


def rate_limit_finding(
    module: str,
    target_url: str,
    status: int,
    done: int,
    asked: int | None = None,
    seconds: float | None = None,
    where: str = "",
) -> Finding:
    """The one finding every module reports when a run is throttled.

    Shared so the wording cannot drift: this is the control the report asks
    for, and a target that already has one should be told so in the same terms
    wherever it is found.
    """
    from capat.core.result import Finding, Severity

    wait = f" It asked for {seconds:.0f}s before the next request." if seconds else ""
    at = f" while fetching {where}" if where else ""
    # A limiter that trips early is the interesting case, so the counts that
    # say so have to read as English: "after 1 attempts" undercuts the rest of
    # the page, and a check throttled before it finished anything reported
    # "after 0 attempts", which reads as the tool having done nothing rather
    # than as the strongest result the check can return.
    if done == 0:
        tries = "on the first request"
        progress = " before any attempt completed"
    else:
        tries = f"after {'1 attempt' if done == 1 else f'{done} attempts'}"
        # "... 3 of 25 samples in" when a sample count is known, "... 3
        # attempts in" when it is not; the two used to share one template and
        # the second came out as "... 3 in".
        if asked:
            progress = f", {done} of {asked} samples in"
        else:
            progress = f", {done} attempt{'' if done == 1 else 's'} in"
    return Finding(
        module=module,
        title=f"target rate-limited the run {tries}",
        target=target_url,
        severity=Severity.INFO,
        description=(
            f"The application returned HTTP {status} and stopped answering{at}"
            f"{progress}.{wait} The measurement stopped there rather than continue against "
            "a limiter. This is a control working: rate limiting per account and per source "
            "is what actually raises the cost of automated guessing, and any rate reported "
            "here is a smaller sample because of it - report both together."
        ),
        remediation=(
            "Nothing to fix on the target. Lower -r and re-run for a larger sample; note in "
            "the report where the limit began, since that threshold is the real measure of "
            "how much automation this login tolerates."
        ),
        evidence={
            "status_code": status,
            "attempts_before_limit": done,
            "samples_requested": asked,
            "retry_after_seconds": seconds,
            "limited_at": where or target_url,
        },
    )


def throttled(resp: httpx.Response) -> bool:
    if resp.status_code == RATE_LIMIT_STATUS:
        return True
    # Only look at short bodies: a full HTML page mentioning "rate limit" in
    # copy is not a throttle, and mistaking one for a throttle would end a run
    # that was working.
    return len(resp.content) <= 512 and bool(PHRASES.search(resp.text))


def retry_after(resp: httpx.Response) -> float | None:
    """Seconds the server asked us to wait, if it said."""
    value = resp.headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value.strip()))
    except ValueError:
        return None  # An HTTP-date form; the operator is told to back off anyway.
