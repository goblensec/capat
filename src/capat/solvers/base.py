from __future__ import annotations

import abc
import asyncio
import contextlib
import time
from dataclasses import dataclass, field

from capat.solvers.preprocess import Preprocessor


class SolverUnavailable(RuntimeError):
    """The engine's optional dependency is not installed."""


class _Default:
    """Sentinel distinguishing "use the default preprocessor" from "none"."""


DEFAULT_PREPROCESSING = _Default()


@dataclass(frozen=True, slots=True)
class Fragment:
    """One recognized run of characters and where it sits horizontally."""

    text: str
    confidence: float
    x_center: float


@dataclass(frozen=True, slots=True)
class SolveResult:
    text: str
    confidence: float
    engine: str
    elapsed: float = 0.0
    fragments: list[Fragment] = field(default_factory=list)

    def matches(self, expected: str, case_sensitive: bool = False) -> bool:
        if case_sensitive:
            return self.text == expected
        return self.text.casefold() == expected.casefold()


class Solver(abc.ABC):
    """Base class for a recognition engine.

    Contract:
      - set `name`
      - implement `recognize`, returning raw Fragments; do no ordering,
        filtering, or timing there - the base class owns that so every engine
        is compared on equal terms

    Recognition is CPU-bound and the underlying models are not reentrant, so
    `solve` serializes calls and runs them off the event loop. HTTP keeps
    flowing while a solve is in progress; solves themselves are one at a time.
    """

    name: str = "unnamed"

    def __init__(
        self,
        preprocessor: Preprocessor | None | _Default = DEFAULT_PREPROCESSING,
        charset: str | None = None,
        expected_length: int | None = None,
    ) -> None:
        # An explicit None disables preprocessing; omitting it takes the default.
        self.preprocessor: Preprocessor | None = (
            Preprocessor() if isinstance(preprocessor, _Default) else preprocessor
        )
        self.charset = charset
        self.expected_length = expected_length
        self._lock = asyncio.Lock()

    @abc.abstractmethod
    def recognize(self, image: bytes) -> list[Fragment]:
        raise NotImplementedError

    def solve_sync(self, image: bytes) -> SolveResult:
        started = time.perf_counter()
        prepared = self.preprocessor.apply(image) if self.preprocessor else image
        fragments = self.recognize(prepared)
        text, confidence, kept = self._assemble(fragments)
        return SolveResult(
            text=text,
            confidence=confidence,
            engine=self.name,
            elapsed=time.perf_counter() - started,
            fragments=kept,
        )

    async def solve(self, image: bytes) -> SolveResult:
        async with self._lock:
            return await asyncio.to_thread(self.solve_sync, image)

    async def warmup(self) -> None:
        """Load the model before anything is timed.

        Engines load lazily, so without this the first solve carries several
        seconds of model initialisation. Averaged into a small run that
        inflates the reported cost per solve by an order of magnitude - and
        since this tool exists to show how cheap solving is, an inflated
        figure understates the very thing it is measuring.
        """
        import io

        from PIL import Image

        buffer = io.BytesIO()
        Image.new("RGB", (32, 16), "white").save(buffer, format="PNG")
        with contextlib.suppress(Exception):
            await self.solve(buffer.getvalue())

    def _assemble(self, fragments: list[Fragment]) -> tuple[str, float, list[Fragment]]:
        """Order fragments left-to-right and apply the known shape of the code.

        Engines return fragments in detection order, which for skewed or
        overlapping glyphs is not reading order. Sorting by horizontal centre
        recovers the sequence. When the code length is known, the
        lowest-confidence fragments are dropped until the length fits - noise
        that survived preprocessing is usually what the engine was least sure
        about.
        """
        kept = [f for f in fragments if f.text.strip()]
        if self.charset:
            # Both cases of every letter are allowed regardless of how the
            # charset was written. Engines disagree on case constantly, and a
            # case-sensitive filter silently deletes a correct answer rather
            # than reporting a wrong one - which reads as an unsolvable
            # CAPTCHA instead of a configuration mistake.
            allowed = set(self.charset) | set(self.charset.lower()) | set(self.charset.upper())
            kept = [
                Fragment("".join(c for c in f.text if c in allowed), f.confidence, f.x_center)
                for f in kept
            ]
            kept = [f for f in kept if f.text]

        kept.sort(key=lambda f: f.x_center)

        if self.expected_length is not None:
            total = sum(len(f.text) for f in kept)
            while len(kept) > 1 and total > self.expected_length:
                weakest = min(kept, key=lambda f: f.confidence)
                kept.remove(weakest)
                total -= len(weakest.text)

        text = "".join(f.text for f in kept).strip()
        confidence = sum(f.confidence for f in kept) / len(kept) if kept else 0.0
        return text, confidence, kept

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r}>"
