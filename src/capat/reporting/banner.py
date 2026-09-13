"""The banner and configuration block printed when a run starts.

Borrowed from ffuf, and for the same reason: a run against a login page is
minutes of live requests, and the operator should be able to read back what is
about to happen before it does. Most of the flags in this tool describe *the
target*, not the tool, and getting one wrong produces a confident number about
something that was never measured. Printing the assembled configuration turns
"I think I passed the right matcher" into something visible.

It goes to stderr, so `-f json` on stdout stays machine-readable.
"""

from __future__ import annotations

from capat.core.config import DEFAULT_USER_AGENT, Config
from capat.core.matching import Matcher, SuccessCriteria
from capat.core.profile import (
    AUTO_CAPTCHA_URL,
    BASE64_CAPTCHA_URL,
    LoginProfile,
    SolverSettings,
)

__all__ = [
    "AUTHOR",
    "audit_rows",
    "bench_rows",
    "collect_rows",
    "describe_matcher",
    "render",
    "render_config",
    "solve_rows",
]

ART = r"""
                          __
  _________ _____  ____ _/ /_
 / ___/ __ `/ __ \/ __ `/ __/
/ /__/ /_/ / /_/ / /_/ / /_
\___/\__,_/ .___/\__,_/\__/
         /_/
"""

AUTHOR = "goblensec"
"""Shown under the version, the way ffuf and nuclei name their maintainer."""

RULE = "_" * 64

NOT_SET = "(not set)"


def describe_matcher(matcher: Matcher) -> str:
    """One line for a matcher, in the syntax the operator would have typed.

    Round-tripping the CLI spelling rather than dumping the dataclass means a
    line can be copied straight back onto the command line to reproduce a run.
    """
    parts: list[str] = []
    parts += [f'"{body}"' for body in matcher.body]
    parts += [f"re:{pattern}" for pattern in matcher.regex]
    parts += [f"status:{code}" for code in matcher.status]
    parts += [f"json:{path}={value}" for path, value in matcher.json.items()]
    parts += [f"header:{name}={value}" for name, value in matcher.header.items()]
    parts += [f"url:{fragment}" for fragment in matcher.url]
    return ", ".join(parts) if parts else NOT_SET


def _captcha_source(profile: LoginProfile) -> str:
    if profile.captcha_url.lower() == AUTO_CAPTCHA_URL:
        return "auto - re-read from every login page"
    if profile.captcha_url.lower() == BASE64_CAPTCHA_URL:
        return "base64 - read inline from the login page"
    return profile.captcha_url


def _solver_line(tuning: SolverSettings) -> str:
    extra: list[str] = []
    if tuning.length:
        extra.append(f"length {tuning.length}")
    if tuning.charset:
        # Long charsets are common and would push the block off-screen.
        charset = tuning.charset if len(tuning.charset) <= 24 else tuning.charset[:21] + "..."
        extra.append(f"charset {charset}")
    if tuning.min_saturation:
        extra.append(f"min-saturation {tuning.min_saturation}")
    if tuning.dilate:
        extra.append(f"dilate {tuning.dilate}")
    if tuning.invert:
        extra.append("inverted")
    return f"{tuning.name} ({', '.join(extra)})" if extra else tuning.name


def audit_rows(
    profile: LoginProfile,
    config: Config,
    modules: list[str],
    *,
    wordlist: str | None = None,
    users: str | None = None,
    order: str = "spray",
    output: str | None = None,
    fmt: str = "table",
) -> list[tuple[str, str]]:
    """The key/value pairs describing one audit run.

    Rows that only restate a default are left out - the block is meant to be
    read in a glance, so everything in it should be something the operator
    either chose or needs to check.
    """
    criteria: SuccessCriteria = profile.criteria
    rows: list[tuple[str, str]] = [("Login URL", profile.login_url)]
    if profile.form_url and profile.form_url != profile.login_url:
        rows.append(("Form URL", profile.form_url))
    rows.append(("CAPTCHA URL", _captcha_source(profile)))
    rows.append(("Method", f"{profile.method} ({profile.encoding})"))
    if profile.captcha_response != "image":
        rows.append(("CAPTCHA reply", f"{profile.captcha_response} at {profile.captcha_image_key}"))
    rows.append(("Checks", ", ".join(modules)))
    rows.append(("Solver", _solver_line(profile.solver)))
    if "solve-rate" in modules:
        rows.append(("Samples", str(config.samples)))

    if wordlist:
        rows.append(("Passwords", wordlist))
        rows.append(("Users", users or f"{profile.username or NOT_SET} (single account)"))
        rows.append(
            (
                "Credentials",
                f"SUBMITS REAL LOGINS - {order}, lockout at {config.lockout_threshold}"
                + (" - LOCKOUT PROTECTION OFF" if config.ignore_lockout else ""),
            )
        )

    rows.append(("Rate", f"{config.requests_per_second:g}/s, {config.concurrency} in flight"))
    rows.append(("Timeout", f"{config.timeout:g}s"))
    if config.proxy:
        rows.append(("Proxy", config.proxy))
    if not config.verify_tls:
        rows.append(("TLS", "verification DISABLED"))
    if config.user_agent != DEFAULT_USER_AGENT:
        # Worth confirming: the default identifies the tool honestly, and an
        # override is usually deliberate impersonation of a browser.
        rows.append(("User-Agent", config.user_agent))
    if profile.headers:
        rows.append(("Headers", ", ".join(sorted(profile.headers))))

    # The matchers last, and always shown even when empty: telling a CAPTCHA
    # rejection from a credential rejection IS the measurement, and a missing
    # one is the single most common reason a run reports nothing useful.
    rows.append(("CAPTCHA fail", describe_matcher(criteria.captcha_failure)))
    rows.append(("Auth fail", describe_matcher(criteria.auth_failure)))
    rows.append(("Success", describe_matcher(criteria.success)))

    if output:
        rows.append(("Report", f"{output} ({fmt})"))
    return rows


def bench_rows(
    corpus: str,
    images: int,
    tuning: SolverSettings,
    *,
    case_sensitive: bool,
    output: str | None = None,
    fmt: str = "table",
) -> list[tuple[str, str]]:
    """Config for an offline corpus benchmark.

    No rate, proxy or target rows: `bench` touches no network at all, and
    showing that it has none is part of the point.
    """
    rows = [
        ("Corpus", corpus),
        ("Images", str(images)),
        ("Solver", _solver_line(tuning)),
        ("Compare", "case-sensitive" if case_sensitive else "case-insensitive"),
    ]
    if output:
        rows.append(("Report", f"{output} ({fmt})"))
    return rows


def collect_rows(
    profile: LoginProfile, config: Config, count: int, output: str
) -> list[tuple[str, str]]:
    """Config for a corpus download.

    Only the CAPTCHA endpoint is touched - `collect` never submits a login -
    so there are no matcher or credential rows to show.
    """
    rows: list[tuple[str, str]] = []
    if profile.discovers_captcha_url or profile.reads_inline_captcha:
        rows.append(("Source", f"the login page at {profile.page_url}"))
    else:
        rows.append(("CAPTCHA URL", profile.captcha_url))
    rows += [
        ("Images", str(count)),
        ("Output", output),
        ("Rate", f"{config.requests_per_second:g}/s"),
        ("Timeout", f"{config.timeout:g}s"),
    ]
    if config.proxy:
        rows.append(("Proxy", config.proxy))
    if not config.verify_tls:
        rows.append(("TLS", "verification DISABLED"))
    if config.user_agent != DEFAULT_USER_AGENT:
        rows.append(("User-Agent", config.user_agent))
    return rows


def solve_rows(
    image: str, tuning: SolverSettings, *, save_processed: str | None = None
) -> list[tuple[str, str]]:
    """Config for a single offline solve.

    The preprocessing row is the reason this command exists: `solve` is how a
    recipe gets tuned, so the recipe in force belongs on screen next to the
    answer it produced.
    """
    rows = [("Image", image), ("Solver", _solver_line(tuning))]
    rows.append(
        (
            "Preprocess",
            f"scale {tuning.scale:g}, threshold {tuning.threshold}, median {tuning.median}",
        )
    )
    if save_processed:
        rows.append(("Processed", save_processed))
    return rows


def render_config(rows: list[tuple[str, str]]) -> str:
    """`:: Key : value`, with the keys aligned into one column."""
    width = max((len(key) for key, _ in rows), default=0)
    return "\n".join(f" :: {key.ljust(width)} : {value}" for key, value in rows)


def render(version: str, rows: list[tuple[str, str]] | None = None) -> str:
    """The whole start-of-run block: art, version, rule, config, rule.

    With no rows - `setup`, which has not asked its questions yet - the
    configuration section is dropped rather than printed empty.
    """
    block = [ART.strip("\n"), "", f"       v{version}", f"       by {AUTHOR}", RULE]
    if rows:
        block += ["", render_config(rows), "", RULE]
    return "\n".join([*block, ""])
