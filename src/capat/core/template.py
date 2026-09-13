"""Placeholders and value extraction - the parts an operator customizes.

ffuf gives you `FUZZ` anywhere in a request; Hydra gives you `^USER^` and
`^PASS^`. The same idea applies here: rather than guessing at every way an
application can be shaped, let the operator write the request and say where
the values go.
"""

from __future__ import annotations

import json as jsonlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from capat.core.matching import ResponseView, dig

PLACEHOLDER = re.compile(r"\{\{\s*(\w+)\s*(?:\|\s*(\w+)\s*)?\}\}")

_FILTERS: dict[str, Callable[[str], str]] = {
    "raw": lambda v: v,
    "json": jsonlib.dumps,
    "url": lambda v: quote(v, safe=""),
}


def render(template: str, values: Mapping[str, str]) -> str:
    """Substitute `{{name}}` placeholders.

    `{{name|json}}` emits a quoted, escaped JSON string - use it in a JSON body
    template so an answer containing a quote cannot break the request.
    `{{name|url}}` percent-encodes for query strings.
    """

    def replace(match: re.Match[str]) -> str:
        name, filter_name = match.group(1), match.group(2) or "raw"
        if name not in values:
            available = ", ".join(sorted(values)) or "none"
            raise ValueError(f"unknown placeholder {{{{{name}}}}}; available: {available}")
        if filter_name not in _FILTERS:
            raise ValueError(
                f"unknown filter {filter_name!r}; available: {', '.join(sorted(_FILTERS))}"
            )
        return _FILTERS[filter_name](values[name])

    return PLACEHOLDER.sub(replace, template)


def placeholders(template: str) -> set[str]:
    return {m.group(1) for m in PLACEHOLDER.finditer(template)}


@dataclass(slots=True)
class Extractor:
    """Pulls one value out of a response so later requests can use it.

    Covers where applications actually keep anti-CSRF tokens and similar
    per-request values: a hidden input, a meta tag or inline script (regex), a
    JSON field, a response header, or a cookie the framework expects echoed
    back in a header.
    """

    name: str
    source: str = "hidden"
    key: str = ""
    """Meaning depends on `source`: input name, regex with one capture group,
    dotted JSON path, header name, or cookie name."""

    required: bool = True
    default: str = ""
    from_: str = "form"
    """Which response to read: 'form' (the login page) or 'captcha'."""

    SOURCES = ("hidden", "regex", "json", "header", "cookie")

    def __post_init__(self) -> None:
        if self.source not in self.SOURCES:
            raise ValueError(
                f"unknown extractor source {self.source!r}; available: {', '.join(self.SOURCES)}"
            )
        if not self.name:
            raise ValueError("extractor needs a name")
        if not self.key:
            raise ValueError(f"extractor {self.name!r} needs a key")
        if self.from_ not in ("form", "captcha"):
            raise ValueError(f"extractor {self.name!r}: from must be 'form' or 'captcha'")
        if self.source == "regex":
            try:
                compiled = re.compile(self.key)
            except re.error as exc:
                raise ValueError(f"extractor {self.name!r}: invalid regex: {exc}") from None
            if compiled.groups < 1:
                raise ValueError(
                    f"extractor {self.name!r}: regex needs a capture group around the value"
                )

    @classmethod
    def parse(cls, spec: dict[str, Any]) -> Extractor:
        data = dict(spec)
        if "from" in data:
            data["from_"] = data.pop("from")
        unknown = set(data) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown extractor keys: {', '.join(sorted(unknown))}")
        return cls(**data)

    def apply(self, resp: httpx.Response, hidden: Mapping[str, str]) -> str | None:
        view = ResponseView.of(resp)
        found: str | None = None

        if self.source == "hidden":
            found = hidden.get(self.key)
        elif self.source == "regex":
            match = re.search(self.key, view.text, re.IGNORECASE | re.DOTALL)
            found = match.group(1) if match else None
        elif self.source == "json":
            value = dig(view.json_body, self.key)
            found = None if value is None else str(value)
        elif self.source == "header":
            found = view.headers.get(self.key.lower())
        elif self.source == "cookie":
            found = view.cookies.get(self.key)

        if found is None:
            if self.required:
                raise ValueError(
                    f"extractor {self.name!r} found nothing at {self.source}:{self.key!r} "
                    f"in the {self.from_} response"
                )
            return self.default or None
        return found
