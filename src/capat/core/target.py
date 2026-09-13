from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class Target:
    """A raw user-supplied target, normalized on access."""

    raw: str

    @property
    def url(self) -> str:
        candidate = self.raw if "://" in self.raw else f"https://{self.raw}"
        parsed = urlparse(candidate)
        if not parsed.hostname:
            raise ValueError(f"cannot parse target: {self.raw!r}")
        if not parsed.path:
            parsed = parsed._replace(path="/")
        return parsed.geturl()

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""
