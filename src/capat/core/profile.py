from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from capat.core.matching import Matcher, Outcome, ResponseView, SuccessCriteria, dig
from capat.core.template import Extractor, render

__all__ = [
    "CaptchaChallenge",
    "Extractor",
    "LoginProfile",
    "Matcher",
    "Outcome",
    "ResponseView",
    "SolverSettings",
    "SuccessCriteria",
    "decode_image_payload",
    "excerpt",
    "dig",
    "extract_hidden_fields",
    "render",
]

ENCODINGS = ("form", "json", "multipart")

AUTO_CAPTCHA_URL = "auto"
"""`"captcha_url": "auto"` - read the image URL off the login page on every
attempt instead of naming it once. For applications that mint an unguessable
per-load URL, where neither a fixed URL nor a `{{placeholder}}` can name it."""

BASE64_CAPTCHA_URL = "base64"
"""`"captcha_url": "base64"` - the challenge is a `data:` URI drawn into the
login page, so there is no endpoint at all. The bytes come from the page, and
the next page load is the next challenge."""


@dataclass(frozen=True, slots=True)
class CaptchaChallenge:
    """One issued challenge: the image, and the handle that identifies it.

    Two deployment styles are covered. The classic one serves a raw image and
    remembers the answer against the session cookie, so `challenge_id` is
    None. The stateless one returns JSON carrying a base64 image and an id,
    and expects that id back with the login - there the id *is* the binding,
    and submitting an answer without it is meaningless.
    """

    image: bytes
    challenge_id: str | None = None

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.image).hexdigest()


def excerpt(body: bytes, limit: int = 160) -> str:
    """A short, single-line quote of a response, for an error message."""
    text = " ".join(body.decode("utf-8", "replace").split())
    return repr(text[:limit] + ("..." if len(text) > limit else "")) if text else "an empty body"


def decode_image_payload(value: str) -> bytes:
    """Decode a base64 image field.

    Tolerates what APIs actually return: a `data:image/png;base64,` prefix,
    embedded whitespace or newlines, the URL-safe alphabet, and missing
    padding.
    """
    text = value.strip()
    if text.startswith("data:"):
        _, _, text = text.partition(",")
    text = "".join(text.split())
    if not text:
        raise ValueError("captcha image field is empty")
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, validate=False)
    except (binascii.Error, ValueError):
        return base64.urlsafe_b64decode(text)


class _HiddenInputParser(HTMLParser):
    """Pulls hidden form inputs out of a login page (CSRF tokens, nonces)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "input":
            return
        attr = {k.lower(): (v or "") for k, v in attrs}
        if attr.get("type", "").lower() != "hidden":
            return
        name = attr.get("name")
        if name:
            self.fields[name] = attr.get("value", "")


def extract_hidden_fields(html: str) -> dict[str, str]:
    parser = _HiddenInputParser()
    # Malformed markup must not abort a run; missing tokens surface as a
    # failed attempt, which is information in itself.
    with contextlib.suppress(Exception):
        parser.feed(html)
    return parser.fields


def nest(flat: dict[str, str]) -> dict[str, Any]:
    """Expand dotted keys into nested objects for JSON bodies.

    `{"user.name": "x"}` becomes `{"user": {"name": "x"}}`. Form bodies keep
    dotted names verbatim, since some frameworks use them literally.
    """
    result: dict[str, Any] = {}
    for key, value in flat.items():
        parts = key.split(".")
        cursor = result
        for part in parts[:-1]:
            existing = cursor.get(part)
            if not isinstance(existing, dict):
                existing = {}
                cursor[part] = existing
            cursor = existing
        cursor[parts[-1]] = value
    return result


@dataclass(slots=True)
class SolverSettings:
    """How to read this application's images.

    Tuning is per-target: the threshold and denoise kernel that clear one
    application's CAPTCHA say nothing about another's. So the recipe lives in
    the profile beside the URLs, and a run that was tuned once does not have
    to be re-tuned from the command line every time.

    Command-line flags override whatever is stored here.
    """

    name: str = "ddddocr"
    """A registered engine, or the path to a `.onnx` model to load instead."""

    charset_file: str | None = None
    """Labels for a custom model. Defaults to the model path with `.json`."""

    charset: str | None = None
    length: int | None = None
    scale: float = 3.0
    threshold: int = 140
    """Binarization cut-off 0-255, or -1 to keep grayscale."""

    median: int = 3
    min_saturation: int = 0
    dilate: int = 0
    invert: bool = False
    case_sensitive: bool = False

    @classmethod
    def parse(cls, spec: Any) -> SolverSettings:
        if isinstance(spec, SolverSettings):
            return spec
        if spec is None:
            return cls()
        if isinstance(spec, str):
            return cls(name=spec)
        if not isinstance(spec, dict):
            raise ValueError(f"cannot read solver settings from {type(spec).__name__}")
        unknown = set(spec) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(
                f"unknown solver keys: {', '.join(sorted(unknown))}. "
                f"Known keys: {', '.join(sorted(cls.__dataclass_fields__))}"
            )
        return cls(**spec)

    def to_dict(self) -> dict[str, Any]:
        """Only what differs from the defaults, so a saved profile stays short."""
        base = SolverSettings()
        return {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if getattr(self, name) != getattr(base, name)
        }


@dataclass(slots=True)
class LoginProfile:
    """Describes one application's login flow, as data rather than code.

    The structured fields cover the common form-post case in a few lines. When
    an application needs something they cannot express - a nested JSON body, a
    GraphQL mutation, a signed envelope - set `body_template` and write the
    request yourself with `{{username}}`, `{{password}}`, `{{captcha}}`,
    `{{captcha_id}}` and any extractor names as placeholders.
    """

    login_url: str
    """Where the form posts. May carry `{{placeholders}}`, which are filled from
    everything extracted during the attempt."""

    captcha_url: str
    """The challenge endpoint. May carry `{{placeholders}}` filled from `@form`
    extractors, or be the literal `"auto"` to re-read it from each login page."""

    username_field: str = "username"
    password_field: str = "password"
    captcha_field: str = "captcha"
    method: str = "POST"
    form_url: str | None = None
    """Page holding the form, if it differs from the submit URL. Fetched first
    so hidden fields, tokens, and the session cookie are picked up. Being the
    first request of an attempt, it can carry no placeholders."""

    csrf_field: str | None = None
    extra_fields: dict[str, str] = field(default_factory=dict)
    username: str = ""
    """The account the credential audit targets. Not used for measurement."""

    probe_username: str = ""
    """Identity used for solve-rate probing. Defaults to a random, non-existent
    username so that measuring a CAPTCHA can never lock out a real account."""

    captcha_length: int | None = None
    captcha_charset: str | None = None

    solver: SolverSettings = field(default_factory=SolverSettings)
    """Engine and preprocessing tuned for this target's images."""

    # -- how the login request is shaped ----------------------------------
    encoding: str = "form"
    """'form' (urlencoded), 'json', or 'multipart'."""

    headers: dict[str, str] = field(default_factory=dict)
    """Extra headers on every request. Values may use placeholders, so a token
    extracted from the login page can be echoed back in a header."""

    body_template: str | None = None
    """Raw request body with `{{placeholders}}`. Overrides the structured
    fields entirely. Use `{{captcha|json}}` inside JSON to stay well-formed."""

    extract: list[Extractor] = field(default_factory=list)
    """Values to pull out of the login page or CAPTCHA response first."""

    # -- how the CAPTCHA endpoint answers ---------------------------------
    captcha_response: str = "image"
    """'image' for a raw image body, 'json' for an API returning a base64
    image and an identifier."""

    captcha_method: str = "GET"
    captcha_headers: dict[str, str] = field(default_factory=dict)
    captcha_image_key: str = "image"
    """Dotted path to the base64 image in the JSON body, e.g. 'data.image'."""

    captcha_id_key: str | None = None
    """Dotted path to the challenge identifier in the JSON body."""

    captcha_id_field: str | None = None
    """Form field the identifier is submitted back in, e.g. 'captcha_id'.
    Required whenever `captcha_id_key` is set - an id that is read but never
    sent would silently break every attempt."""

    criteria: SuccessCriteria = field(default_factory=SuccessCriteria)

    def __post_init__(self) -> None:
        if not self.login_url or not self.captcha_url:
            raise ValueError("profile requires both 'login_url' and 'captcha_url'")
        self.method = self.method.upper()
        self.captcha_method = self.captcha_method.upper()
        if self.encoding not in ENCODINGS:
            raise ValueError(f"encoding must be one of: {', '.join(ENCODINGS)}")
        if self.captcha_response not in ("image", "json"):
            raise ValueError("captcha_response must be 'image' or 'json'")
        # Before the generic endpoint checks: under base64 there is no endpoint,
        # and "captcha_id_key needs captcha_response='json'" would send an
        # operator to configure a response that is never going to happen.
        self._check_inline_mode()
        if self.captcha_response == "image" and self.captcha_id_key:
            raise ValueError("captcha_id_key needs captcha_response='json'")
        if bool(self.captcha_id_key) != bool(self.captcha_id_field):
            raise ValueError(
                "captcha_id_key and captcha_id_field must be set together: the identifier "
                "has to be read from the response and submitted back with the login"
            )
        self.extract = [e if isinstance(e, Extractor) else Extractor.parse(e) for e in self.extract]
        self.solver = SolverSettings.parse(self.solver)
        # The CAPTCHA's shape was describable at the top level before the
        # solver section existed, and reads more naturally there. Keep it as
        # the fallback rather than making operators write it twice.
        if self.solver.charset is None:
            self.solver.charset = self.captcha_charset
        if self.solver.length is None:
            self.solver.length = self.captcha_length
        if not self.probe_username:
            self.probe_username = f"cb-probe-{secrets.token_hex(6)}"
        self._check_placeholders()

    def _check_inline_mode(self) -> None:
        """Reject settings that describe a CAPTCHA response that never happens.

        Under `base64` the image is read from the login page, so there is no
        second response to carry an id, a JSON body, or its own headers.
        Accepting these silently would leave an operator waiting on a challenge
        id that can never arrive.
        """
        if not self.reads_inline_captcha:
            return
        for label, value in (
            ("captcha_id_key", self.captcha_id_key),
            ("captcha_headers", self.captcha_headers or None),
        ):
            if value:
                raise ValueError(
                    f"{label} needs a CAPTCHA endpoint, but captcha_url is "
                    f"{BASE64_CAPTCHA_URL!r}: the image is read from the login page, "
                    "so there is no CAPTCHA response to read it from"
                )
        from_captcha = [
            e.name if isinstance(e, Extractor) else str(e.get("name", "?"))
            for e in self.extract
            if (e.from_ if isinstance(e, Extractor) else e.get("from")) == "captcha"
        ]
        if from_captcha:
            raise ValueError(
                f"extractor(s) {', '.join(sorted(from_captcha))} read the CAPTCHA response, "
                f"but captcha_url is {BASE64_CAPTCHA_URL!r} and no such request is made. "
                "Read them from the login page instead (drop the '@captcha' suffix)"
            )

    def _check_placeholders(self) -> None:
        """Fail at load time, not on every attempt, if a name cannot resolve.

        The URLs are checked against the values that exist *by the time each
        one is requested*, not against every name in the profile. An attempt
        fetches the form page, then the CAPTCHA, then posts the login, so a
        `{{token}}` read from the CAPTCHA response cannot appear in the URL
        that fetches it. Before URLs were rendered at all, a placeholder in one
        passed this check and was then sent to the target as literal text.
        """
        from capat.core.template import placeholders

        known = {"username", "password", "captcha", "captcha_id"}
        known |= {e.name for e in self.extract}
        from_form = {e.name for e in self.extract if e.from_ == "form"}

        checks: list[tuple[str, str, set[str], str]] = [
            ("body_template", self.body_template or "", known, ""),
            *[(f"header {k!r}", v, known, "") for k, v in self.headers.items()],
            (
                "form_url",
                self.form_url or "",
                set(),
                "the form page is the first request of an attempt, so nothing "
                "has been read from the target yet",
            ),
            (
                "captcha_url",
                ""
                if not self.has_captcha_endpoint or self.discovers_captcha_url
                else self.captcha_url,
                from_form,
                "the CAPTCHA is fetched straight after the form page, so only "
                "extractors reading the form (the default, or '@form') are available",
            ),
            ("login_url", self.login_url, known, ""),
        ]
        for label, text, available, why in checks:
            unknown = placeholders(text) - available
            if unknown:
                raise ValueError(
                    f"{label} uses unknown placeholder(s) "
                    f"{', '.join(sorted(unknown))}; available: "
                    f"{', '.join(sorted(available)) or 'none'}"
                    f"{f' - {why}' if why else ''}"
                )

    @property
    def page_url(self) -> str:
        return self.form_url or self.login_url

    @property
    def discovers_captcha_url(self) -> bool:
        """True for `"captcha_url": "auto"` - see `AUTO_CAPTCHA_URL`."""
        return self.captcha_url.strip().lower() == AUTO_CAPTCHA_URL

    @property
    def reads_inline_captcha(self) -> bool:
        """True for `"captcha_url": "base64"` - see `BASE64_CAPTCHA_URL`."""
        return self.captcha_url.strip().lower() == BASE64_CAPTCHA_URL

    @property
    def has_captcha_endpoint(self) -> bool:
        """False when the challenge never comes from a request of its own."""
        return not self.reads_inline_captcha

    def render_captcha_url(self, values: Mapping[str, str]) -> str:
        """The challenge URL for one attempt.

        Rendered per attempt rather than resolved once at startup: an app that
        mints a fresh nonce into the URL on every page load would otherwise be
        re-asked for the same stale challenge, and reported as static.
        """
        return render(self.captcha_url, values)

    def render_login_url(self, values: Mapping[str, str]) -> str:
        return render(self.login_url, values)

    def static_headers(self) -> dict[str, str]:
        """Headers safe to send before anything has been extracted.

        A header carrying a placeholder depends on a value that does not exist
        until the form or CAPTCHA response has been read, so sending it on
        those requests would transmit the literal `{{name}}`.
        """
        from capat.core.template import placeholders

        return {k: v for k, v in self.headers.items() if not placeholders(v)}

    @property
    def uses_challenge_id(self) -> bool:
        return bool(self.captcha_id_field)

    # -- CAPTCHA endpoint --------------------------------------------------

    def parse_captcha(
        self,
        body: bytes,
        content_type: str = "",
        status: int | None = None,
        url: str | None = None,
    ) -> CaptchaChallenge:
        """Turn a CAPTCHA endpoint response into an image and an identifier.

        Every failure here quotes what actually arrived. The endpoint is the
        one part of a run that can start answering differently mid-way - a
        gateway interposing a block page, a session expiring - and an operator
        told only "did not return valid JSON" has to reproduce the run to find
        out which. The excerpt is capped and comes from the CAPTCHA endpoint,
        which carries no credential.
        """
        # The rendered URL when the caller has one: quoting the template back
        # at an operator hides which challenge actually failed.
        where = f"{url or self.captcha_url}{f' (HTTP {status})' if status else ''}"
        if self.captcha_response == "image":
            if not body:
                raise ValueError(f"{where} returned an empty body")
            if body.lstrip()[:1] in (b"{", b"["):
                raise ValueError(
                    f"{where} returned JSON, not an image. Set "
                    '"captcha_response": "json" in the profile and point '
                    "captcha_image_key at the base64 field."
                )
            return CaptchaChallenge(image=body)

        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{where} did not return valid JSON ({exc}); content-type was "
                f"{content_type or 'unset'}. It answered: {excerpt(body)}"
            ) from None

        raw_image = dig(data, self.captcha_image_key)
        if not isinstance(raw_image, str):
            raise ValueError(
                f"no base64 image at {self.captcha_image_key!r} in the response from "
                f"{where}. Available top-level keys: "
                f"{', '.join(sorted(data)) if isinstance(data, dict) else type(data).__name__}"
            )
        image = decode_image_payload(raw_image)

        challenge_id: str | None = None
        if self.captcha_id_key:
            found = dig(data, self.captcha_id_key)
            if found is None:
                raise ValueError(
                    f"no challenge id at {self.captcha_id_key!r} in the response from {where}"
                )
            challenge_id = str(found)
        return CaptchaChallenge(image=image, challenge_id=challenge_id)

    # -- login request -----------------------------------------------------

    def build_fields(
        self,
        username: str,
        password: str,
        captcha: str,
        hidden: dict[str, str] | None = None,
        challenge_id: str | None = None,
    ) -> dict[str, str]:
        """The structured payload, before encoding."""
        payload: dict[str, str] = dict(self.extra_fields)
        if hidden:
            if self.csrf_field and self.csrf_field in hidden:
                payload[self.csrf_field] = hidden[self.csrf_field]
            elif not self.csrf_field:
                payload.update(hidden)
        payload[self.username_field] = username
        payload[self.password_field] = password
        payload[self.captcha_field] = captcha
        if self.captcha_id_field and challenge_id is not None:
            payload[self.captcha_id_field] = challenge_id
        return payload

    # Retained under the old name; several tests and plugins call it.
    build_payload = build_fields

    def build_request(
        self,
        values: dict[str, str],
        hidden: dict[str, str] | None = None,
        omit_captcha: bool = False,
    ) -> dict[str, Any]:
        """Assemble kwargs for the login request.

        `values` carries username, password, captcha, captcha_id and every
        extracted name, so both the template and the headers can use them.
        """
        headers = {k: render(v, values) for k, v in self.headers.items()}

        if self.body_template is not None:
            body = render(self.body_template, values)
            headers.setdefault("Content-Type", self._template_content_type())
            return {"content": body.encode(), "headers": headers}

        fields = self.build_fields(
            values.get("username", ""),
            values.get("password", ""),
            values.get("captcha", ""),
            hidden,
            values.get("captcha_id") or None,
        )
        if omit_captcha:
            fields.pop(self.captcha_field, None)

        if self.encoding == "json":
            return {"json": nest(fields), "headers": headers}
        if self.encoding == "multipart":
            # (None, value) makes httpx emit a plain multipart field, not a file.
            return {"files": {k: (None, v) for k, v in fields.items()}, "headers": headers}
        return {"data": fields, "headers": headers}

    def _template_content_type(self) -> str:
        return {
            "json": "application/json",
            "form": "application/x-www-form-urlencoded",
            "multipart": "application/octet-stream",
        }[self.encoding]

    # -- loading -----------------------------------------------------------

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LoginProfile:
        raw = dict(data)
        criteria_data = raw.pop("criteria", None) or raw.pop("markers", None) or {}
        known = {f for f in cls.__dataclass_fields__ if f != "criteria"}
        unknown = set(raw) - known
        if unknown:
            raise ValueError(
                f"unknown profile keys: {', '.join(sorted(unknown))}. "
                f"Known keys: {', '.join(sorted(known))}"
            )
        if not isinstance(criteria_data, dict):
            raise ValueError("'criteria' must be an object")
        return cls(criteria=SuccessCriteria(**criteria_data), **raw)

    @classmethod
    def from_file(cls, path: str | Path) -> LoginProfile:
        with open(path, encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path} is not valid JSON: {exc}") from None
        return cls.from_dict(data)
