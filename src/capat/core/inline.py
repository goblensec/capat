"""Describing a target with flags instead of a JSON file.

A profile file is the right way to record an engagement: it is reviewable, it
diffs, and it survives the person who wrote it. It is the wrong way to run one
command against one login page, which is usually four facts long. These
helpers build the same `LoginProfile` from command-line flags - ffuf's shape,
where the URL is an argument and the rest are switches.

Flags and files compose rather than compete: anything given on the command
line overrides the same key in `--profile`, so a saved engagement file can be
pointed at staging, or given a different account, without being edited.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from capat.core.template import Extractor

__all__ = [
    "add_target_flags",
    "apply_cli_overrides",
    "parse_extract",
    "parse_field",
    "parse_header",
    "parse_matcher",
    "profile_data",
    "save_profile",
]

# CLI flag (argparse dest) -> profile key. Only flags that map one-to-one onto
# a profile field belong here; anything needing shaping is handled below.
SIMPLE_FLAGS = {
    "url": "login_url",
    "form_url": "form_url",
    "captcha_url": "captcha_url",
    "method": "method",
    "encoding": "encoding",
    "username": "username",
    "username_field": "username_field",
    "password_field": "password_field",
    "captcha_field": "captcha_field",
    "csrf_field": "csrf_field",
    "captcha_response": "captcha_response",
    "captcha_method": "captcha_method",
    "captcha_image_key": "captcha_image_key",
    "captcha_id_key": "captcha_id_key",
    "captcha_id_field": "captcha_id_field",
}

MATCH_HELP = (
    "a substring of the response, or a typed prefix: 're:PATTERN', "
    "'status:422', 'url:/dashboard', 'json:code=4001', 'header:location=/home'. "
    "Repeatable; conditions are OR-ed"
)


def parse_header(spec: str) -> tuple[str, str]:
    """`-H 'X-Requested-With: XMLHttpRequest'` -> ('X-Requested-With', ...)."""
    name, sep, value = spec.partition(":")
    if not sep or not name.strip():
        raise ValueError(f"header must be 'Name: value', got {spec!r}")
    return name.strip(), value.strip()


def parse_field(spec: str) -> tuple[str, str]:
    """`-F remember=1` -> ('remember', '1')."""
    name, sep, value = spec.partition("=")
    if not sep or not name.strip():
        raise ValueError(f"field must be 'name=value', got {spec!r}")
    return name.strip(), value


def parse_extract(spec: str) -> dict[str, Any]:
    """`--extract 'token=regex:name="csrf" value="([^"]+)"'`.

    Returns the JSON form rather than an `Extractor`, so a profile assembled
    from flags stays serializable for `--save-profile`. The value is validated
    here all the same: a bad source or an uncapturing regex should fail before
    a single request is sent.
    """
    name, sep, rest = spec.partition("=")
    if not sep or not name.strip():
        raise ValueError(f"extractor must be 'name=source:key', got {spec!r}")

    origin = "form"
    for suffix in ("@form", "@captcha"):
        if rest.endswith(suffix):
            rest, origin = rest[: -len(suffix)], suffix[1:]
            break

    source, sep, key = rest.partition(":")
    if not sep:
        source, key = "hidden", rest
    data = {"name": name.strip(), "source": source.strip(), "key": key, "from": origin}
    Extractor.parse(data)
    return data


def parse_matcher(values: list[str]) -> dict[str, Any]:
    """Turn `--captcha-fail` style values into a `Matcher` object.

    An untyped value is a body substring, which is what most applications
    need. The typed prefixes exist because a JSON API answers with a code and
    a status rather than a phrase, and reading such a response as "unknown"
    would drop the attempt out of the measurement entirely.
    """
    body: list[str] = []
    regex: list[str] = []
    status: list[int] = []
    url: list[str] = []
    as_json: dict[str, str] = {}
    header: dict[str, str] = {}

    for raw in values:
        kind, sep, rest = raw.partition(":")
        kind = kind.lower() if sep else ""
        if kind in ("re", "regex"):
            regex.append(rest)
        elif kind == "status":
            try:
                status.append(int(rest))
            except ValueError:
                raise ValueError(f"status match must be a number, got {rest!r}") from None
        elif kind == "url":
            url.append(rest)
        elif kind in ("json", "header"):
            path, sep, value = rest.partition("=")
            if not sep:
                raise ValueError(f"{kind} match must be '{kind}:path=value', got {raw!r}")
            (as_json if kind == "json" else header)[path.strip()] = value
        else:
            # Not a known prefix, so a plain substring - which may itself
            # contain a colon ("Error: invalid captcha").
            body.append(raw)

    matcher = {
        "body": body,
        "regex": regex,
        "json": as_json,
        "status": status,
        "url": url,
        "header": header,
    }
    return {key: value for key, value in matcher.items() if value}


def add_target_flags(p: argparse.ArgumentParser, *, criteria: bool = True) -> None:
    """The ffuf-shaped half of `audit` and `collect`.

    `--profile` stays available and stays authoritative for anything complex;
    every flag here overrides the matching key in it. Short names follow ffuf:
    one or two letters, grouped by prefix, so a family is guessable once one
    member is known - every CAPTCHA endpoint flag starts `-c`.
    """
    target = p.add_argument_group("TARGET (instead of, or on top of, --profile)")
    target.add_argument("-u", "--url", metavar="URL", help="login URL the form posts to")
    target.add_argument(
        "-c",
        "--captcha-url",
        metavar="URL",
        help="CAPTCHA endpoint. Discovered if omitted; 'auto' re-reads it every "
        "attempt; 'base64' takes it from a data: URI in the page; {{placeholders}} "
        "are filled by -E",
    )
    target.add_argument(
        "-fu", "--form-url", metavar="URL", help="page holding the form, if it differs from -u"
    )
    target.add_argument("-X", "--method", metavar="M", help="login request method (default POST)")
    target.add_argument(
        "-e",
        "--encoding",
        metavar="ENC",
        choices=["form", "json", "multipart"],
        help="login body encoding: form (default), json, multipart",
    )
    target.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="'Name: Value'",
        help="header on every request. Repeatable",
    )
    target.add_argument(
        "-b",
        "--cookie",
        metavar="'N=V; N2=V2'",
        help="cookie data, for copy-as-curl. Same as -H 'Cookie: ...'",
    )
    target.add_argument(
        "-F",
        "--field",
        action="append",
        default=[],
        metavar="name=value",
        help="extra login form field. Repeatable",
    )
    target.add_argument(
        "-E",
        "--extract",
        action="append",
        default=[],
        metavar="name=src:key",
        help="pull a per-request value out of the page first, e.g. 'token=hidden:_token'. "
        "Repeatable. See EXTRACT SYNTAX",
    )
    target.add_argument(
        "--username",
        metavar="NAME",
        help="the ONE real account -w guesses against. Ignored when -U is given; "
        "the other checks never use it, they invent a throwaway name",
    )
    target.add_argument(
        "--username-field", metavar="NAME", help="form field for the username (default username)"
    )
    target.add_argument(
        "--password-field", metavar="NAME", help="form field for the password (default password)"
    )
    target.add_argument(
        "--csrf-field", metavar="NAME", help="hidden field to carry over, e.g. _token"
    )

    endpoint = p.add_argument_group("CAPTCHA ENDPOINT")
    endpoint.add_argument(
        "-cr",
        "--captcha-response",
        metavar="KIND",
        choices=["image", "json"],
        help="'image' for a raw image body (default), 'json' for a base64 payload",
    )
    endpoint.add_argument(
        "-cm", "--captcha-method", metavar="M", help="method for the CAPTCHA request (default GET)"
    )
    endpoint.add_argument(
        "-ci", "--captcha-image-key", metavar="PATH", help="dotted path to the base64 image"
    )
    endpoint.add_argument(
        "-cd", "--captcha-id-key", metavar="PATH", help="dotted path to the challenge id"
    )
    endpoint.add_argument(
        "-cn",
        "--captcha-id-field",
        metavar="NAME",
        help="field the challenge id is submitted back in",
    )
    endpoint.add_argument(
        "-cv", "--captcha-field", metavar="NAME", help="form field for the answer (default captcha)"
    )
    endpoint.add_argument(
        "-cH",
        "--captcha-header",
        action="append",
        default=[],
        metavar="'Name: Value'",
        help="header on the CAPTCHA request only. Repeatable",
    )

    if criteria:
        match = p.add_argument_group("MATCHER OPTIONS (telling these apart IS the measurement)")
        match.add_argument(
            "-cf",
            "--captcha-fail",
            action="append",
            default=[],
            metavar="MATCH",
            help="how the app rejects a wrong CAPTCHA. Repeatable, OR-ed. Without it a "
            "CAPTCHA rejection cannot be told from a credential one, so the gate checks "
            "report inconclusive rather than guess",
        )
        match.add_argument(
            "-af",
            "--auth-fail",
            action="append",
            default=[],
            metavar="MATCH",
            help="how the app rejects wrong credentials. Repeatable, OR-ed. Keep it "
            "narrow: a substring that also matches the CAPTCHA rejection makes the two "
            "indistinguishable",
        )
        match.add_argument(
            "-ok",
            "--success",
            action="append",
            default=[],
            metavar="MATCH",
            help="how the app answers a successful login. Repeatable, OR-ed",
        )
        match.add_argument(
            "-ou", "--success-url", metavar="FRAGMENT", help="shorthand for -ok 'url:FRAGMENT'"
        )

    target.add_argument(
        "-P",
        "--save-profile",
        metavar="PATH",
        help="write the assembled profile as JSON and carry on, so a run that worked repeats",
    )


def apply_cli_overrides(data: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    """Layer the flags in `args` over profile data. Flags win."""
    merged = dict(data)

    for dest, key in SIMPLE_FLAGS.items():
        value = getattr(args, dest, None)
        if value is not None:
            merged[key] = value

    # A cookie is a header. Given as its own flag because that is how curl,
    # ffuf and Burp's "copy as" all spell it, and it is the one header an
    # operator pastes verbatim.
    if getattr(args, "cookie", None):
        merged["headers"] = {**(merged.get("headers") or {}), "Cookie": args.cookie}

    for dest, key, parse in (
        ("header", "headers", parse_header),
        ("captcha_header", "captcha_headers", parse_header),
        ("field", "extra_fields", parse_field),
    ):
        specs = getattr(args, dest, None) or []
        if specs:
            existing = dict(merged.get(key) or {})
            existing.update(parse(spec) for spec in specs)
            merged[key] = existing

    # Tuning that worked is worth keeping: the point of --save-profile is
    # that a run which produced a good number can be repeated exactly.
    tuning = dict(merged.get("solver") or {})
    for flag, key in (
        ("solver", "name"),
        ("charset", "charset"),
        ("charset_file", "charset_file"),
        ("length", "length"),
        ("scale", "scale"),
        ("threshold", "threshold"),
        ("median", "median"),
        ("min_saturation", "min_saturation"),
        ("dilate", "dilate"),
        ("invert", "invert"),
        ("case_sensitive", "case_sensitive"),
    ):
        value = getattr(args, flag, None)
        if value is not None:
            tuning[key] = value
    if tuning:
        merged["solver"] = tuning

    if getattr(args, "extract", None):
        merged["extract"] = [*(merged.get("extract") or []), *map(parse_extract, args.extract)]

    criteria = dict(merged.get("criteria") or merged.get("markers") or {})
    for dest, key in (
        ("captcha_fail", "captcha_failure"),
        ("auth_fail", "auth_failure"),
        ("success", "success"),
    ):
        values = getattr(args, dest, None) or []
        if values:
            criteria[key] = parse_matcher(values)
    if getattr(args, "success_url", None):
        criteria["success_url_contains"] = args.success_url
    if criteria:
        merged.pop("markers", None)
        merged["criteria"] = criteria

    return merged


def profile_data(args: argparse.Namespace) -> dict[str, Any]:
    """The profile as data: the file if there is one, then the flags on top."""
    data: dict[str, Any] = {}
    path = getattr(args, "profile", None)
    if path:
        with open(path, encoding="utf-8") as fh:
            try:
                loaded = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path} is not valid JSON: {exc}") from None
        if not isinstance(loaded, dict):
            raise ValueError(f"{path} must contain a JSON object")
        data = loaded
    return apply_cli_overrides(data, args)


def save_profile(data: dict[str, Any], path: str) -> None:
    Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
