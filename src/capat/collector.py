"""Collect CAPTCHA images for a labelled corpus.

Tuning needs ground truth, and ground truth means a human reading the images.
This fetches challenges and saves them *unlabelled*, so the operator renames
each file to its answer afterwards - the filename is the label that `bench`
reads back.

Only the CAPTCHA endpoint is touched. No login attempt is made, so nothing
here can fail an authentication or approach a lockout threshold.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from capat.core.profile import LoginProfile
from capat.core.throttle import Throttled
from capat.http.client import HttpClient
from capat.modules.login_flow import LoginFlow

SUFFIX_BY_MAGIC = {
    b"\x89PNG": ".png",
    b"\xff\xd8\xff": ".jpg",
    b"GIF8": ".gif",
    b"RIFF": ".webp",
}


MAX_REASONS = 5
"""Distinct failure reasons kept per run. Enough to tell causes apart."""


def image_suffix(data: bytes) -> str:
    for magic, suffix in SUFFIX_BY_MAGIC.items():
        if data.startswith(magic):
            return suffix
    return ".png"


@dataclass(slots=True)
class CollectionReport:
    saved: list[Path] = field(default_factory=list)
    duplicates: int = 0
    failed: int = 0

    failures: list[str] = field(default_factory=list)
    """Distinct reasons fetches failed, first seen first.

    A bare count makes every cause look the same: a typo in -c, a certificate
    the client would not verify and a 404 all read as "1 fetch(es) failed",
    and the operator is then told to go and label an empty directory."""

    output_dir: Path = Path()
    throttled_after: int | None = None
    """Images collected before the target began rate limiting, if it did."""


class CorpusCollector:
    """Fetches challenges and writes them out for manual labelling."""

    def __init__(self, profile: LoginProfile, output_dir: str | Path) -> None:
        self._profile = profile
        self._flow = LoginFlow(profile, solver=None)
        self._dir = Path(output_dir)

    async def collect(self, client: HttpClient, count: int) -> CollectionReport:
        self._dir.mkdir(parents=True, exist_ok=True)
        report = CollectionReport(output_dir=self._dir)
        seen: set[str] = set()

        for index in range(count):
            try:
                # A fresh session per fetch: some endpoints only issue a new
                # challenge once the previous one has been consumed.
                async with client.session() as session:
                    context = await self._flow.fetch_form(session)
                    challenge = await self._flow.fetch_captcha(session, context)
            except Throttled:
                # Collecting past a limiter would be rude and would fill the
                # corpus with error pages. Stop and say how far it got.
                report.throttled_after = len(report.saved)
                break
            except (httpx.HTTPError, ValueError) as exc:
                report.failed += 1
                reason = f"{type(exc).__name__}: {exc}"
                # Distinct reasons only, and a handful of them: a 500-image run
                # against a flaky endpoint should not print 500 identical lines.
                if reason not in report.failures and len(report.failures) < MAX_REASONS:
                    report.failures.append(reason)
                continue

            digest = hashlib.sha256(challenge.image).hexdigest()
            if digest in seen:
                # Worth knowing on its own: a CAPTCHA that repeats within a
                # collection run is one an attacker can solve once and reuse.
                report.duplicates += 1
                continue
            seen.add(digest)

            name = f"unlabelled-{index + 1:03d}-{digest[:8]}{image_suffix(challenge.image)}"
            path = self._dir / name
            path.write_bytes(challenge.image)
            report.saved.append(path)

        return report
