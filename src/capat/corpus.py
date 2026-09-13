from __future__ import annotations

import difflib
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from capat.solvers.base import Solver

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}


@dataclass(frozen=True, slots=True)
class LabeledImage:
    path: Path
    label: str

    @property
    def data(self) -> bytes:
        return self.path.read_bytes()


@dataclass(slots=True)
class Attempt:
    label: str
    predicted: str
    correct: bool
    similarity: float
    confidence: float
    elapsed: float
    path: str


@dataclass(slots=True)
class BenchReport:
    """Result of an offline run against a labeled corpus."""

    engine: str
    attempts: list[Attempt] = field(default_factory=list)
    preprocessor: dict[str, Any] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.attempts)

    @property
    def solved(self) -> int:
        return sum(1 for a in self.attempts if a.correct)

    @property
    def accuracy(self) -> float:
        return self.solved / self.total if self.total else 0.0

    @property
    def character_accuracy(self) -> float:
        if not self.attempts:
            return 0.0
        return statistics.fmean(a.similarity for a in self.attempts)

    @property
    def mean_latency(self) -> float:
        if not self.attempts:
            return 0.0
        return statistics.fmean(a.elapsed for a in self.attempts)

    @property
    def attempts_per_hour(self) -> float:
        """Correct solves per hour from recognition cost alone - the number
        that decides whether a CAPTCHA is an obstacle or a speed bump.

        Zero when the measurement is too fast to be meaningful (below a
        millisecond it reports the harness, not the engine).
        """
        if self.mean_latency < 0.001:
            return 0.0
        return 3600.0 / self.mean_latency * self.accuracy

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "total": self.total,
            "solved": self.solved,
            "accuracy": round(self.accuracy, 4),
            "character_accuracy": round(self.character_accuracy, 4),
            "mean_latency_seconds": round(self.mean_latency, 4),
            "solves_per_hour": round(self.attempts_per_hour, 1),
            "preprocessor": self.preprocessor,
            "attempts": [
                {
                    "label": a.label,
                    "predicted": a.predicted,
                    "correct": a.correct,
                    "similarity": round(a.similarity, 4),
                    "confidence": round(a.confidence, 4),
                    "elapsed": round(a.elapsed, 4),
                }
                for a in self.attempts
            ],
        }


def load_corpus(directory: str | Path) -> list[LabeledImage]:
    """Load labeled images. The label is the filename stem up to the first
    underscore, so `A8R36.png` and `A8R36_002.png` both label as `A8R36`."""
    root = Path(directory)
    if not root.is_dir():
        raise NotADirectoryError(f"corpus directory not found: {root}")
    images = [
        LabeledImage(path=p, label=p.stem.split("_", 1)[0])
        for p in sorted(root.iterdir())
        if p.is_file() and p.suffix.lower() in IMAGE_SUFFIXES
    ]
    if not images:
        raise ValueError(
            f"no labeled images in {root}; name each file after its answer, e.g. A8R36.png"
        )
    return images


class CorpusBenchmark:
    """Measures a solver against known answers. No network, fully repeatable.

    This is the honest version of the claim. A live measurement depends on the
    target's error messages; this one depends on nothing but the images.
    """

    def __init__(self, solver: Solver, case_sensitive: bool = False) -> None:
        self._solver = solver
        self._case_sensitive = case_sensitive

    async def run(self, images: list[LabeledImage]) -> BenchReport:
        # Model loading must not land inside the first measured solve.
        await self._solver.warmup()
        report = BenchReport(
            engine=self._solver.name,
            preprocessor=self._solver.preprocessor.describe() if self._solver.preprocessor else {},
        )
        for image in images:
            result = await self._solver.solve(image.data)
            predicted, label = result.text, image.label
            if not self._case_sensitive:
                predicted_cmp, label_cmp = predicted.casefold(), label.casefold()
            else:
                predicted_cmp, label_cmp = predicted, label
            report.attempts.append(
                Attempt(
                    label=label,
                    predicted=predicted,
                    correct=predicted_cmp == label_cmp,
                    similarity=difflib.SequenceMatcher(None, label_cmp, predicted_cmp).ratio(),
                    confidence=result.confidence,
                    elapsed=result.elapsed,
                    path=str(image.path),
                )
            )
        return report
