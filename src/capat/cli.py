from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any, TextIO

import httpx

from capat import __version__, trace
from capat.collector import CollectionReport, CorpusCollector
from capat.core.config import Config
from capat.core.discovery import find_captcha_image, find_inline_captcha
from capat.core.engine import Engine
from capat.core.inline import add_target_flags, profile_data, save_profile
from capat.core.profile import (
    AUTO_CAPTCHA_URL,
    BASE64_CAPTCHA_URL,
    LoginProfile,
    SolverSettings,
)
from capat.core.result import Severity
from capat.corpus import CorpusBenchmark, load_corpus
from capat.http.client import HttpClient
from capat.modules.base import Module
from capat.modules.credential_audit import CredentialAudit, human_duration
from capat.modules.gate_enforcement import CaptchaGate
from capat.modules.solve_rate import CaptchaSolveRate
from capat.reporting import banner
from capat.reporting.reporter import FORMATS, BenchReporter, Reporter
from capat.solvers import available_solvers, build_solver
from capat.solvers.base import SolverUnavailable
from capat.solvers.preprocess import Preprocessor
from capat.wizard import Prompter, command_line, run_wizard

BANNER = (
    "capat - evidence that image CAPTCHAs are not a bot control.\n"
    "Use only against systems you are authorized to test."
)


MATCH_SYNTAX = """MATCH SYNTAX (-cf / -af / -ok):
  invalid captcha        a substring of the response body
  re:PATTERN             regular expression against the body
  status:422             HTTP status code
  url:/dashboard         substring of the final URL, after redirects
  json:code=4001         dotted JSON path equals a value
  header:location=/home  response header equals a value
  Each flag repeats; its conditions are OR-ed."""

EXTRACT_SYNTAX = """EXTRACT SYNTAX (-E name=source:key):
  token=hidden:_token                 a hidden form input
  nonce=regex:captcha[?]n=([^"]+)     one capture group
  sid=json:data.id@captcha            dotted JSON path, from the CAPTCHA reply
  xsrf=cookie:XSRF-TOKEN              a cookie the app expects echoed back
  Names become {{placeholders}} usable in -c, -u, -H and the body."""

MODULES = """MODULES (-M, all run by default):
  gate         is the CAPTCHA required, single-use and rotating at all
  solve-rate   how often OCR reads it, using a throwaway identity - needs -cf and -af
  credential   password test straight through the CAPTCHA - needs -w"""

EXAMPLES = """EXAMPLE USAGE:
  Tune the engine offline first; a live run spends attempts the target rate limits.
    capat collect -c https://example.org/captcha -o corpus   # then name each file its answer
    capat bench corpus -s ddddocr

  Measure a plain HTML login form. The two phrases are the measurement.
    capat audit -u https://example.org/login \\
      -cf "invalid captcha" -af "invalid username or password"

  A page that mints a fresh CAPTCHA URL on every load.
    capat audit -u https://example.org/login -c auto \\
      -cf "invalid captcha" -af "invalid username or password"

  A JSON API returning a base64 image and an id, matched on response codes.
    capat audit -u https://example.org/api/login -e json \\
      -c https://example.org/api/captcha -cr json -ci data.image \\
      -cd data.id -cn captchaId \\
      -cf json:code=4001 -af json:code=4002 -ok json:code=0 -P app.json

  Replay a saved profile through Burp, enforcement checks only, no OCR.
    capat audit -p app.json -M gate -x http://127.0.0.1:8080

  Only the findings worth acting on, written to a file.
    capat audit -p app.json -m medium -f markdown -o report.md"""

EPILOG = "\n\n".join([MATCH_SYNTAX, EXTRACT_SYNTAX, MODULES, EXAMPLES])


class CompactHelp(argparse.RawDescriptionHelpFormatter):
    """ffuf-shaped help: one line per flag, and the epilog printed verbatim.

    argparse wraps a flag onto its own line as soon as the invocation passes
    ~24 columns, which turns a thirty-flag tool into three screens. Widening
    the help column keeps every option on one line.
    """

    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=34, width=100)


def _add_banner_flag(parser: argparse._ActionsContainer) -> None:
    """Every command prints the banner, so every command can turn it off.

    No short form: it is typed once in a CI job, never in an interactive
    run, and the readable letters are reserved for what gets typed daily.

    Takes an `_ActionsContainer` because audit puts the flag in its OUTPUT
    group while the smaller commands have no groups to put it in; that is the
    base class argparse gives both a parser and a group.
    """
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="skip the start-of-run banner and configuration",
    )


def _add_solver_flags(parser: argparse.ArgumentParser, *, compares: bool = False) -> None:
    """Tuning flags shared by audit, bench and solve.

    `compares` gates --case-sensitive, which only bench can act on: it is the
    one command that holds an expected answer to judge against. audit hands
    the answer to the target and lets it judge; solve prints the answer and
    stops. Offering the flag there would be a switch with nothing behind it.

    -l/--length stays on all three by contrast, because whether it does
    anything depends on the engine chosen at runtime by -s, not on the
    subcommand - that one the help string has to carry.
    """
    p = parser.add_argument_group("SOLVER OPTIONS (tuning; save with -P and reuse)")
    p.add_argument(
        "-s",
        "--solver",
        metavar="NAME|PATH",
        help=f"engine: {', '.join(available_solvers())} (default ddddocr), "
        "or the path to a custom .onnx model",
    )
    # No short form: -C belongs to --captcha-fail, which is typed every run,
    # while a charset is worked out once and saved into the profile.
    p.add_argument("--charset", metavar="CHARS", help="characters the CAPTCHA can contain")
    p.add_argument(
        "--charset-file",
        metavar="PATH",
        help="labels for a custom -s model.onnx (default: the model path with .json)",
    )
    p.add_argument(
        "-l",
        "--length",
        type=int,
        metavar="N",
        help="how many characters the answer has. Used by easyocr, tesseract and "
        "ensemble only - ddddocr and -s model.onnx read the image as one sequence "
        "and ignore it, so train the length in instead",
    )
    p.add_argument("--scale", type=float, metavar="N", help="upscale factor (default 3.0)")
    p.add_argument(
        "--threshold",
        type=int,
        metavar="N",
        help="binarization cut-off 0-255, -1 keeps grayscale (default 140)",
    )
    p.add_argument(
        "--median", type=int, metavar="N", help="median denoise kernel, 0 disables (default 3)"
    )
    p.add_argument(
        "--min-saturation",
        type=int,
        metavar="N",
        help="drop pixels below this saturation 0-255, killing grey noise (try 60)",
    )
    p.add_argument(
        "--dilate",
        type=int,
        metavar="N",
        help="thicken strokes, odd kernel (default 0, try 3)",
    )
    p.add_argument("--invert", action="store_true", default=None, help="invert after thresholding")
    if compares:
        p.add_argument(
            "--case-sensitive",
            action="store_true",
            default=None,
            help="a prediction must match the label's case to count (default: case-insensitive, "
            "which is how most CAPTCHA implementations compare)",
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="capat", description=BANNER, epilog=EXAMPLES, formatter_class=CompactHelp
    )
    p.add_argument("--version", action="version", version=f"capat {__version__}")
    p.add_argument("-v", "--verbose", action="count", default=0)
    sub = p.add_subparsers(dest="command", required=True)

    # ---- audit -------------------------------------------------------------
    audit = sub.add_parser(
        "audit",
        help="measure a live login CAPTCHA (needs authorization)",
        description=BANNER,
        epilog=EPILOG,
        formatter_class=CompactHelp,
    )
    general = audit.add_argument_group("GENERAL OPTIONS")
    http = audit.add_argument_group("HTTP OPTIONS")
    cred = audit.add_argument_group("CREDENTIAL TEST OPTIONS (only run when -w is given)")
    out = audit.add_argument_group("OUTPUT OPTIONS")

    general.add_argument(
        "-p",
        "--profile",
        help="JSON file describing the login form (optional; -u alone also works)",
    )
    general.add_argument(
        "-n",
        "--samples",
        type=int,
        default=25,
        metavar="N",
        help="CAPTCHAs to measure (default 25)",
    )
    general.add_argument(
        "--skip-solve-rate", action="store_true", help="only run the enforcement checks (no OCR)"
    )
    general.add_argument(
        "-M",
        "--only",
        action="append",
        default=[],
        choices=["gate", "solve-rate", "credential"],
        metavar="MODULE",
        help="run only these checks. Repeatable. See MODULES",
    )
    general.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="print every request, including live credentials. Keep it on a terminal",
    )

    http.add_argument(
        "-r", "--rps", type=float, default=2.0, metavar="N", help="max requests/second (default 2)"
    )
    http.add_argument(
        "-t",
        "--threads",
        type=int,
        default=5,
        metavar="N",
        help="parallel checks in flight (default 5)",
    )
    http.add_argument(
        "-T",
        "--timeout",
        type=float,
        default=15.0,
        metavar="SEC",
        help="request timeout (default 15s)",
    )
    http.add_argument(
        "-x", "--proxy", metavar="URL", help="proxy, e.g. http://127.0.0.1:8080 for Burp/ZAP"
    )
    http.add_argument(
        "-k", "--insecure", action="store_true", help="disable TLS verification (warns)"
    )
    http.add_argument("-A", "--user-agent", metavar="UA", help="override the User-Agent header")

    cred.add_argument(
        "-w",
        "--passwords",
        metavar="WORDLIST",
        help="password list. Giving one ALSO submits real logins - off unless given",
    )
    cred.add_argument(
        "-U",
        "--users",
        metavar="WORDLIST",
        help="file of real accounts to guess against, one per line. Overrides "
        "--username. Without either, -w has nothing to run against",
    )
    cred.add_argument(
        "--order",
        choices=["spray", "brute"],
        default="spray",
        help="spray: every identity per password, safest (default). brute: one at a time",
    )
    cred.add_argument(
        "--max-attempts",
        type=int,
        metavar="N",
        help="cap credential-test attempts (default: the whole wordlist)",
    )
    cred.add_argument(
        "--captcha-retries",
        type=int,
        default=3,
        metavar="N",
        help="retries when a CAPTCHA was misread, so no password goes untested (default 3)",
    )
    cred.add_argument(
        "--lockout-threshold",
        type=int,
        default=4,
        metavar="N",
        help="wrong-password budget PER ACCOUNT, not for the whole run "
        "(default 4). CAPTCHA misreads do not count against it",
    )
    # One flag, not a --stop-if-lockout/--no- pair: stopping is the default, so
    # the positive half would have been a switch that does nothing. What the
    # pair was there to fix - a flag that never said what happens when it is
    # absent - is fixed in the help text instead.
    cred.add_argument(
        "--ignore-lockout",
        action="store_true",
        help="keep guessing at an account after it spends its budget. OFF by "
        "default: capat drops that account and carries on with the rest. "
        "Turning it on CAN LOCK A REAL PERSON OUT",
    )

    out.add_argument(
        "-f",
        "--format",
        choices=FORMATS,
        default="table",
        metavar="FMT",
        help="report format: table (default), json, markdown",
    )
    out.add_argument("-o", "--output", metavar="FILE", help="write the report to a file")
    _add_banner_flag(out)
    out.add_argument(
        "-m",
        "--min-severity",
        choices=[str(s) for s in Severity],
        default="info",
        metavar="LEVEL",
        help="hide findings below this level, e.g. -m medium (default info)",
    )
    _add_solver_flags(audit)
    add_target_flags(audit)

    # ---- bench -------------------------------------------------------------
    bench = sub.add_parser(
        "bench",
        help="measure solver accuracy against a labeled corpus (offline, no network)",
        formatter_class=CompactHelp,
    )
    bench.add_argument(
        "corpus", help="directory of images named after their answer, e.g. A8R36.png"
    )
    bench.add_argument("-f", "--format", choices=FORMATS, default="table")
    bench.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    bench.add_argument("--show-all", action="store_true", help="list correct solves too")
    _add_banner_flag(bench)
    _add_solver_flags(bench, compares=True)

    # ---- collect -----------------------------------------------------------
    collect = sub.add_parser(
        "collect",
        help="download CAPTCHA images for a labelled corpus (no login attempts)",
        description=BANNER,
        epilog=EXTRACT_SYNTAX,
        formatter_class=CompactHelp,
    )
    collect.add_argument(
        "-p",
        "--profile",
        help="JSON file describing the login form (optional; -c alone also works)",
    )
    collect.add_argument("-n", "--count", type=int, default=20, help="images to fetch (default 20)")
    collect.add_argument(
        "-o", "--output", default="corpus", help="directory to write into (default ./corpus)"
    )
    collect.add_argument(
        "-r", "--rps", type=float, default=1.0, help="max requests/second (default 1)"
    )
    collect.add_argument("-T", "--timeout", type=float, default=15.0)
    collect.add_argument("-x", "--proxy", help="upstream proxy")
    collect.add_argument("-k", "--insecure", action="store_true", help="disable TLS verification")
    collect.add_argument("-A", "--user-agent", help="override the User-Agent header")
    _add_banner_flag(collect)
    add_target_flags(collect, criteria=False)

    # ---- setup -------------------------------------------------------------
    setup = sub.add_parser(
        "setup",
        help="answer a few questions, then run the audit (writes a profile you can reuse)",
        description=BANNER,
    )
    setup.add_argument(
        "--dry-run", action="store_true", help="write the profile and print the command, don't run"
    )
    _add_banner_flag(setup)

    # ---- solve -------------------------------------------------------------
    solve = sub.add_parser("solve", help="solve one image (offline, for tuning preprocessing)")
    solve.add_argument("image", help="path to a CAPTCHA image")
    solve.add_argument("--save-processed", help="write the preprocessed image here to inspect it")
    _add_banner_flag(solve)
    _add_solver_flags(solve)

    return p


SOLVER_FLAGS = (
    "solver",
    "charset",
    # Omitted here once, which meant `bench` and `solve` built a custom model
    # with no labels: CTC output is indices, so the answer came back in the
    # wrong alphabet rather than failing. `audit` was unaffected - it layers
    # its tuning through core/inline.py, which had the key.
    "charset_file",
    "length",
    "scale",
    "threshold",
    "median",
    "min_saturation",
    "dilate",
    "invert",
    "case_sensitive",
)


def solver_settings(args: argparse.Namespace, base: SolverSettings | None = None) -> SolverSettings:
    """The tuning to use: what the profile stored, with the flags on top."""
    settings = replace(base or SolverSettings())
    for flag in SOLVER_FLAGS:
        value = getattr(args, flag, None)
        if value is not None:
            setattr(settings, "name" if flag == "solver" else flag, value)
    return settings


def build_preprocessor(settings: SolverSettings) -> Preprocessor:
    return Preprocessor(
        scale=settings.scale,
        min_saturation=settings.min_saturation,
        median=settings.median,
        threshold=None if settings.threshold < 0 else settings.threshold,
        dilate=settings.dilate,
        invert=settings.invert,
    )


def _open_output(path: str | None) -> tuple[TextIO, bool]:
    if path is None:
        return sys.stdout, False
    return open(path, "w", encoding="utf-8"), True


def build_config(args: argparse.Namespace, **overrides: Any) -> Config:
    kwargs: dict[str, Any] = {
        "requests_per_second": args.rps,
        "timeout": args.timeout,
        "verify_tls": not args.insecure,
        "proxy": args.proxy,
        **overrides,
    }
    if args.user_agent:
        kwargs["user_agent"] = args.user_agent
    return Config(**kwargs)


def discover_captcha_url(
    config: Config, page_url: str, headers: dict[str, str] | None = None
) -> str:
    """Read the login page and find the CAPTCHA image, for runs given only -u.

    The operator's headers come too. A target that needs a cookie or an
    API key to serve its login page would otherwise fail here with "no CAPTCHA
    image found" - which reads as "this page has none" rather than "you were
    not let in", and sends the operator to devtools for a URL they already
    described how to reach.
    """

    async def fetch() -> tuple[str, str]:
        async with HttpClient(config) as client:
            resp = await client.get(page_url, headers=headers or None)
            return resp.text, str(resp.url)

    print(f"looking for the CAPTCHA image on {page_url}...", file=sys.stderr)
    html, final_url = asyncio.run(fetch())
    found = find_captcha_image(html, final_url)
    if not found:
        if find_inline_captcha(html):
            # The page has the challenge, just not as an endpoint. Sending the
            # operator to the network tab for a URL that does not exist is the
            # one answer guaranteed to waste their time, and `-c base64` is
            # already built for exactly this page.
            raise ValueError(
                f"{page_url} draws its CAPTCHA inline, as a base64 data: URI with no "
                "endpoint behind it. Re-run with -c base64 to read the image out of "
                "each login page."
            )
        raise ValueError(
            f"no CAPTCHA image found on {page_url}. Pass the endpoint explicitly with "
            "--captcha-url (or --profile), and if the page builds it in JavaScript, "
            "take the URL from the browser's network tab."
        )
    print(f"using --captcha-url {found}", file=sys.stderr)
    return found


def resolve_profile(args: argparse.Namespace, config: Config) -> LoginProfile:
    """Assemble the profile from `--profile`, the flags, and the page itself.

    Discovery happens here rather than at parse time because it is a request
    to the target, and the banner has to describe what will actually be asked
    for - a discovered CAPTCHA URL is not known until it has been.
    """
    data = profile_data(args)
    keyword = str(data.get("captcha_url", "")).lower()
    if keyword in (AUTO_CAPTCHA_URL, BASE64_CAPTCHA_URL) and not data.get("login_url"):
        raise ValueError(f"-c {keyword} reads the challenge off a page, so it needs -u/--url too")
    if not data.get("login_url") and data.get("captcha_url"):
        # `collect` only ever touches the CAPTCHA endpoint, so an operator who
        # has only that URL should not have to invent a login one.
        data["login_url"] = data["captcha_url"]
    if not data.get("login_url"):
        raise ValueError("give a target: -u https://host/login (or --profile file.json)")
    if not data.get("captcha_url"):
        # Only headers with no placeholders: nothing has been extracted yet.
        static = {k: v for k, v in (data.get("headers") or {}).items() if "{{" not in str(v)}
        data["captcha_url"] = discover_captcha_url(
            config, data.get("form_url") or data["login_url"], static
        )
    if args.save_profile:
        save_profile(data, args.save_profile)
        print(f"profile written to {args.save_profile}", file=sys.stderr)
    return LoginProfile.from_dict(data)


def cmd_audit(args: argparse.Namespace) -> int:
    if args.debug:
        trace.enable()
    if args.insecure:
        print("warning: TLS verification disabled", file=sys.stderr)
    if args.ignore_lockout:
        print(
            "warning: lockout protection disabled; this can lock out a real account",
            file=sys.stderr,
        )

    config = build_config(
        args,
        concurrency=args.threads,
        samples=args.samples,
        lockout_threshold=args.lockout_threshold,
        ignore_lockout=args.ignore_lockout,
    )
    profile = resolve_profile(args, config)

    tuning = profile.solver
    solver = build_solver(
        tuning.name,
        preprocessor=build_preprocessor(tuning),
        charset=tuning.charset,
        expected_length=tuning.length,
        charset_file=tuning.charset_file,
    )

    wanted = set(args.only) or {"gate", "solve-rate", "credential"}
    modules: list[Module] = []
    # The -M keywords, not the module names: this is what the banner shows and
    # what the operator would type to run the same subset again.
    enabled: list[str] = []
    if "gate" in wanted:
        modules.append(CaptchaGate(profile, solver))
        enabled.append("gate")
    if "solve-rate" in wanted and not args.skip_solve_rate:
        modules.append(CaptchaSolveRate(profile, solver, samples=config.samples))
        enabled.append("solve-rate")
    if "credential" in wanted and args.passwords:
        enabled.append("credential")
        modules.append(
            CredentialAudit(
                profile,
                solver,
                wordlist=args.passwords,
                users=args.users,
                lockout_threshold=config.lockout_threshold,
                ignore_lockout=config.ignore_lockout,
                max_attempts=args.max_attempts,
                order=args.order,
                captcha_retries=args.captcha_retries,
            )
        )
    if not modules:
        raise ValueError(
            "nothing to run: --only credential needs -w/--passwords to give it a wordlist"
        )

    if not args.no_banner:
        # After resolve_profile, so what is printed is what will actually be
        # requested - a discovered CAPTCHA URL and a profile's stored solver
        # tuning are both invisible at parse time.
        print(
            banner.render(
                __version__,
                banner.audit_rows(
                    profile,
                    config,
                    enabled,
                    wordlist=args.passwords,
                    users=args.users,
                    order=args.order,
                    captcha_retries=args.captcha_retries,
                    output=args.output,
                    fmt=args.format,
                ),
            ),
            file=sys.stderr,
        )

    engine = Engine(config, modules)
    started = time.monotonic()
    findings = asyncio.run(engine.run([profile.login_url]))
    elapsed = time.monotonic() - started

    threshold = Severity[args.min_severity.upper()]
    shown = [f for f in findings if f.severity >= threshold]

    stream, close = _open_output(args.output)
    try:
        Reporter(stream).render(shown, fmt=args.format)
    finally:
        if close:
            stream.close()
            print(f"report written to {args.output}", file=sys.stderr)

    print(
        f"\n{len(modules)} check(s) against {profile.login_url} in {human_duration(elapsed)}",
        file=sys.stderr,
    )
    return 1 if any(f.severity >= Severity.MEDIUM for f in shown) else 0


def cmd_collect(args: argparse.Namespace) -> int:
    if args.insecure:
        print("warning: TLS verification disabled", file=sys.stderr)
    config = build_config(args, concurrency=1)
    profile = resolve_profile(args, config)

    async def run() -> CollectionReport:
        async with HttpClient(config) as client:
            return await CorpusCollector(profile, args.output).collect(client, args.count)

    if not args.no_banner:
        print(
            banner.render(
                __version__, banner.collect_rows(profile, config, args.count, args.output)
            ),
            file=sys.stderr,
        )
    print(f"fetching {args.count} CAPTCHAs...", file=sys.stderr)
    report = asyncio.run(run())

    print(f"\nsaved {len(report.saved)} image(s) to {report.output_dir}", file=sys.stderr)
    if report.duplicates:
        print(
            f"note: {report.duplicates} fetch(es) returned an image already seen - "
            "a repeating challenge is a finding in itself",
            file=sys.stderr,
        )
    if report.throttled_after is not None:
        print(
            f"note: the target began rate limiting after {report.throttled_after} image(s); "
            "collection stopped there. Lower -r and re-run for a bigger corpus",
            file=sys.stderr,
        )
    if report.failed:
        print(f"note: {report.failed} fetch(es) failed", file=sys.stderr)
        for reason in report.failures:
            print(f"  {reason}", file=sys.stderr)
        if any("certificate" in reason.lower() for reason in report.failures):
            # Naming the flag is the difference between a dead end and a
            # working run, and a staging box on a self-signed certificate is
            # the commonest place `collect` gets pointed.
            print(
                "  the certificate could not be verified - re-run with -k if that is "
                "expected for this host",
                file=sys.stderr,
            )
    if not report.saved:
        # Nothing to label, so the labelling instructions would be noise on top
        # of a failure the operator still has to diagnose.
        return 1
    print(
        "\nNext: rename each file to the answer it shows (e.g. A8R36.png), then\n"
        f"  capat bench {report.output_dir} --solver ensemble",
        file=sys.stderr,
    )
    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    if not args.no_banner:
        # Art and version only: the wizard has not asked its questions yet,
        # so there is no configuration to show. The audit it hands off to
        # prints the full block once there is.
        print(banner.render(__version__), file=sys.stderr)
    profile, flags, path = run_wizard(Prompter())
    LoginProfile.from_dict(profile)  # fail here, not three questions later
    save_profile(profile, path)

    print(f"\nprofile written to {path}", file=sys.stderr)
    print(f"  {command_line(path, flags)}\n", file=sys.stderr)
    if args.dry_run:
        return 0
    return main(["audit", "--profile", path, *flags])


def cmd_bench(args: argparse.Namespace) -> int:
    images = load_corpus(args.corpus)
    tuning = solver_settings(args)
    solver = build_solver(
        tuning.name,
        preprocessor=build_preprocessor(tuning),
        charset=tuning.charset,
        expected_length=tuning.length,
        charset_file=tuning.charset_file,
    )
    if not args.no_banner:
        print(
            banner.render(
                __version__,
                banner.bench_rows(
                    args.corpus,
                    len(images),
                    tuning,
                    case_sensitive=tuning.case_sensitive,
                    output=args.output,
                    fmt=args.format,
                ),
            ),
            file=sys.stderr,
        )
    print(f"solving {len(images)} labeled images with {solver.name}...", file=sys.stderr)
    report = asyncio.run(CorpusBenchmark(solver, tuning.case_sensitive).run(images))

    stream, close = _open_output(args.output)
    try:
        BenchReporter(stream).render(report, fmt=args.format, show_all=args.show_all)
    finally:
        if close:
            stream.close()
            print(f"report written to {args.output}", file=sys.stderr)
    return 0


def cmd_solve(args: argparse.Namespace) -> int:
    data = Path(args.image).read_bytes()
    tuning = solver_settings(args)
    preprocessor = build_preprocessor(tuning)
    if not args.no_banner:
        print(
            banner.render(
                __version__,
                banner.solve_rows(
                    args.image,
                    tuning,
                    save_processed=args.save_processed,
                ),
            ),
            file=sys.stderr,
        )
    if args.save_processed:
        Path(args.save_processed).write_bytes(preprocessor.apply(data))
        print(f"preprocessed image written to {args.save_processed}", file=sys.stderr)

    solver = build_solver(
        tuning.name,
        preprocessor=preprocessor,
        charset=tuning.charset,
        expected_length=tuning.length,
        charset_file=tuning.charset_file,
    )
    result = asyncio.run(solver.solve(data))
    print(f"{result.text}")
    print(
        f"engine={result.engine} confidence={result.confidence:.2f} elapsed={result.elapsed:.2f}s",
        file=sys.stderr,
    )
    return 0 if result.text else 1


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.WARNING - 10 * min(args.verbose, 2),
        format="%(levelname)s %(name)s: %(message)s",
    )

    handlers = {
        "audit": cmd_audit,
        "bench": cmd_bench,
        "collect": cmd_collect,
        "setup": cmd_setup,
        "solve": cmd_solve,
    }
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        # A run is minutes of live requests; stopping one is routine, not a
        # crash, and a traceback here buries whatever it had already printed.
        print("\ninterrupted.", file=sys.stderr)
        return 130
    except SolverUnavailable as exc:
        print(f"solver error: {exc}", file=sys.stderr)
        return 2
    except httpx.HTTPError as exc:
        # The most common first run: a typo in -u, or a target that is not up.
        # httpx.ConnectError is neither ValueError nor OSError, so without this
        # the tool answered the commonest mistake with a stack trace.
        print(f"error: cannot reach the target: {exc}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
