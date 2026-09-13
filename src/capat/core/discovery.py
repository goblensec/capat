"""Finding the CAPTCHA endpoint on a login page.

Asking the operator for the image URL is asking them to open devtools before
they can run the tool once. The page almost always says where it is: an `<img>`
whose src, id, class or alt names the thing.

Deliberately conservative. A guess that silently picks the site logo would
produce a solve rate for an image that is not the challenge - a wrong number
presented as a measurement, which is worse than no number. So only a named
candidate counts, and what was chosen is always printed; when nothing matches,
the answer is an error telling the operator to pass --captcha-url.
"""

from __future__ import annotations

import contextlib
import re
from html.parser import HTMLParser
from urllib.parse import urljoin

__all__ = ["find_captcha_image", "find_inline_captcha"]

# Deliberately a constant and not a flag. An operator who has to write a regex
# to find their own login page's image has already lost the time the tool was
# meant to save, so the fix for an unusual name is to widen this list - not to
# push the problem back onto the command line. Every alternative here is
# specific enough that it will not match a logo, a spinner, or an avatar.
NAMED = re.compile(
    r"""
      captcha | kaptcha | capcha | captcah          # and the usual misspellings
    | securimage | sec[-_ ]?code
    | security[-_ ]?code
    | capture                                       # real: id="capture_qw23"
    | auth[-_ ]?(?:img|image|code)
    | verif(?:y|ication)[-_ ]?(?:code|img|image)
    | valid(?:ate|ation)?[-_ ]?code
    | check[-_ ]?code | rand[-_ ]?code | pic[-_ ]?code
    | img[-_ ]?code | code[-_ ]?img
    | vcode | yzm | yanzhengma                      # common in Chinese stacks
    | كابتشا | التحقق  # captcha / verification, Arabic
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Attributes worth reading: the path itself, plus the names a developer gives
# the element. `src` last would be enough for most sites, but plenty serve the
# image from an opaque path and only the id says what it is.
ATTRS = ("src", "data-src", "id", "class", "alt", "name", "title")


class _ImageCollector(HTMLParser):
    """Splits named CAPTCHA images by how they are delivered.

    A `data:` URI has no endpoint to re-fetch, so a run that samples URLs
    cannot use it - but the bytes are right there in the page, and re-reading
    the page yields the next challenge. The two are kept apart rather than one
    discarded, so the caller picks the strategy it can actually run.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.named: list[str] = []
        self.inline: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "img":
            return
        attr = {k.lower(): (v or "") for k, v in attrs}
        src = (attr.get("src") or attr.get("data-src") or "").strip()
        if not src:
            return
        if not NAMED.search(" ".join(attr.get(name, "") for name in ATTRS)):
            return
        (self.inline if src.lower().startswith("data:") else self.named).append(src)


def _collect(html: str) -> _ImageCollector:
    parser = _ImageCollector()
    # Malformed markup must not abort a run; a page we cannot parse simply
    # yields no candidate, and the caller asks for --captcha-url.
    with contextlib.suppress(Exception):
        parser.feed(html)
    return parser


def find_captcha_image(html: str, page_url: str) -> str | None:
    """The absolute URL of the CAPTCHA image on `page_url`, or None."""
    for src in _collect(html).named:
        return urljoin(page_url, src)
    return None


def find_inline_captcha(html: str) -> str | None:
    """The `data:` URI of a CAPTCHA drawn into the page itself, or None.

    Returned whole, prefix included: `decode_image_payload` already strips it,
    and quoting it back in an error is more use than a bare blob.
    """
    for src in _collect(html).inline:
        return src
    return None
