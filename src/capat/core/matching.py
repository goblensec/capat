"""Deciding what an application's answer means.

Every application says "wrong CAPTCHA" differently: a phrase in HTML, a numeric
code in JSON, a status, a redirect, a header. The whole measurement rests on
telling that apart from "wrong credentials", so the rules are data the operator
writes, never conditionals in a module.
"""

from __future__ import annotations

import enum
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import httpx


class Outcome(enum.Enum):
    """How the application answered one login attempt.

    The distinction between CAPTCHA_FAILURE and AUTH_FAILURE is the entire
    measurement: an attempt rejected for bad credentials is an attempt whose
    CAPTCHA was solved correctly.
    """

    SUCCESS = "success"
    AUTH_FAILURE = "auth_failure"
    CAPTCHA_FAILURE = "captcha_failure"
    UNKNOWN = "unknown"


def dig(data: Any, path: str) -> Any:
    """Follow a dotted path into decoded JSON, e.g. 'data.captcha.image'.

    Returns None if any step is missing, so a profile pointing at the wrong
    key produces a clear "not found" rather than a KeyError mid-run.
    """
    current = data
    for part in path.split("."):
        if isinstance(current, list):
            try:
                current = current[int(part)]
                continue
            except (ValueError, IndexError):
                return None
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


@dataclass(slots=True)
class ResponseView:
    """A response with the derived forms matchers need, computed once."""

    status_code: int
    url: str
    text: str
    headers: dict[str, str]
    cookies: dict[str, str] = field(default_factory=dict)
    _json: Any = None
    _json_parsed: bool = False

    @classmethod
    def of(cls, resp: httpx.Response) -> ResponseView:
        return cls(
            status_code=resp.status_code,
            url=str(resp.url),
            text=resp.text,
            headers={k.lower(): v for k, v in resp.headers.items()},
            cookies=dict(resp.cookies),
        )

    @property
    def json_body(self) -> Any:
        if not self._json_parsed:
            self._json_parsed = True
            try:
                self._json = json.loads(self.text)
            except (ValueError, TypeError):
                self._json = None
        return self._json


def _same_value(found: Any, expected: Any) -> bool:
    """Compare a JSON value against what the operator wrote, as strings.

    Values are compared as text so `4001` and `"4001"` match - a profile
    should not have to mirror the application's typing. Booleans are the one
    case where that is not enough: JSON spells them `true`, Python prints them
    `True`, and a matcher written the way the response reads would silently
    never fire, turning a successful login into an unclassifiable one.
    """
    if isinstance(found, bool) or str(expected).lower() in ("true", "false"):
        return str(found).lower() == str(expected).lower()
    return str(found) == str(expected)


@dataclass(slots=True)
class Matcher:
    """A set of conditions describing one kind of response.

    Written either as a bare list of substrings for the common case:

        "captcha_failure": ["invalid captcha"]

    or as an object when the application is less obliging:

        "captcha_failure": {
          "json": {"code": 4001},
          "regex": ["captcha.{0,20}(invalid|expired)"],
          "status": [422]
        }

    Conditions are OR-ed by default - list every phrasing the app uses. Set
    `"mode": "all"` when a single signal is ambiguous and only the combination
    identifies the case.
    """

    body: list[str] = field(default_factory=list)
    """Case-insensitive substrings of the response body."""

    regex: list[str] = field(default_factory=list)
    """Patterns searched in the body, case-insensitive."""

    json: dict[str, Any] = field(default_factory=dict)
    """Dotted path -> expected value, compared as strings so 4001 == "4001"."""

    status: list[int] = field(default_factory=list)
    header: dict[str, str] = field(default_factory=dict)
    """Header name -> substring it must contain ("" means present at all)."""

    url: list[str] = field(default_factory=list)
    """Substrings of the final URL, after redirects."""

    mode: str = "any"

    def __post_init__(self) -> None:
        if self.mode not in ("any", "all"):
            raise ValueError("matcher mode must be 'any' or 'all'")
        for pattern in self.regex:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid regex {pattern!r}: {exc}") from None

    @classmethod
    def parse(cls, spec: Any) -> Matcher:
        """Accept a list of substrings, a single string, or a full object.

        Idempotent: parsing an already-built Matcher returns it unchanged, so
        a profile can be constructed either from JSON or in code.
        """
        if isinstance(spec, Matcher):
            return spec
        if spec is None:
            return cls()
        if isinstance(spec, str):
            return cls(body=[spec])
        if isinstance(spec, list):
            return cls(body=[str(s) for s in spec])
        if isinstance(spec, dict):
            unknown = set(spec) - set(cls.__dataclass_fields__)
            if unknown:
                raise ValueError(f"unknown matcher keys: {', '.join(sorted(unknown))}")
            return cls(**spec)
        raise ValueError(f"cannot read matcher from {type(spec).__name__}")

    def is_empty(self) -> bool:
        return not any((self.body, self.regex, self.json, self.status, self.header, self.url))

    def matches(self, view: ResponseView) -> bool:
        if self.is_empty():
            return False
        results = list(self._evaluate(view))
        return all(results) if self.mode == "all" else any(results)

    def _evaluate(self, view: ResponseView) -> Iterator[bool]:
        lowered = view.text.lower()
        for needle in self.body:
            yield needle.lower() in lowered
        for pattern in self.regex:
            yield re.search(pattern, view.text, re.IGNORECASE | re.DOTALL) is not None
        for path, expected in self.json.items():
            found = dig(view.json_body, path)
            yield found is not None and _same_value(found, expected)
        for code in self.status:
            yield view.status_code == code
        for name, substring in self.header.items():
            value = view.headers.get(name.lower())
            yield value is not None and substring.lower() in value.lower()
        for fragment in self.url:
            yield fragment.lower() in view.url.lower()


@dataclass(slots=True)
class SuccessCriteria:
    """Classifies a login response into one of the four outcomes.

    Order matters and is deliberate: a CAPTCHA rejection is checked before a
    credential rejection, because an application that reports both will report
    the CAPTCHA one first, and reading it the other way round would silently
    inflate the measured solve rate.
    """

    captcha_failure: Matcher = field(default_factory=Matcher)
    auth_failure: Matcher = field(default_factory=Matcher)
    success: Matcher = field(default_factory=Matcher)

    # Legacy shorthands, kept because they read well for simple targets.
    success_status: int | None = None
    success_url_contains: str | None = None

    def __post_init__(self) -> None:
        self.captcha_failure = Matcher.parse(self.captcha_failure)
        self.auth_failure = Matcher.parse(self.auth_failure)
        self.success = Matcher.parse(self.success)
        if self.success_status is not None:
            self.success.status = [*self.success.status, self.success_status]
        if self.success_url_contains:
            self.success.url = [*self.success.url, self.success_url_contains]

    def classify(self, resp: httpx.Response) -> Outcome:
        view = ResponseView.of(resp)
        # A landing URL is the least ambiguous signal there is, so it wins.
        if self.success.url and any(u.lower() in view.url.lower() for u in self.success.url):
            return Outcome.SUCCESS
        if self.captcha_failure.matches(view):
            return Outcome.CAPTCHA_FAILURE
        if self.auth_failure.matches(view):
            return Outcome.AUTH_FAILURE
        if self.success.matches(view):
            return Outcome.SUCCESS
        return Outcome.UNKNOWN

    def is_usable(self) -> bool:
        """A solve-rate measurement needs to tell the two failures apart."""
        return not self.captcha_failure.is_empty() and not self.auth_failure.is_empty()
