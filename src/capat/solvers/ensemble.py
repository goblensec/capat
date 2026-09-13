from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from capat.solvers.base import Fragment, Solver, SolveResult, SolverUnavailable

AGREEMENT_BONUS = 0.05
"""How much a second member agreeing is worth, in confidence points.

Deliberately small: agreement is evidence, but correlated members make it
weaker evidence than it looks."""


@dataclass(frozen=True, slots=True)
class Vote:
    text: str
    confidence: float
    engine: str


class EnsembleSolver(Solver):
    """Runs several configurations and picks the answer they agree on.

    Engines fail on different images, and their failures are close to
    independent: one model loses a glyph to overlap, another mangles a
    character the preprocessing thinned. Running three configurations costs
    tens of milliseconds and recovers most of what any single one drops.

    That is the uncomfortable part of the argument. A CAPTCHA that defeats one
    off-the-shelf engine has not bought much, because trying several is
    trivially cheap and needs no expertise - and if a defender's threat model
    assumes a single naive attacker tool, it is measuring the wrong thing.

    Selection is by mean confidence among candidates of the expected length,
    nudged by agreement - not by majority vote. Majority is the tempting rule
    and it loses: members sharing a preprocessing recipe fail identically, so
    a two-to-one majority is often one mistake counted twice.
    """

    name = "ensemble"

    def __init__(self, members: list[Solver], expected_length: int | None = None) -> None:
        if not members:
            raise ValueError("an ensemble needs at least one member solver")
        # Members own their own preprocessing; the ensemble adds none.
        super().__init__(preprocessor=None, expected_length=expected_length)
        self.members = members

    def recognize(self, image: bytes) -> list[Fragment]:  # pragma: no cover
        raise NotImplementedError("EnsembleSolver overrides solve_sync")

    def solve_sync(self, image: bytes) -> SolveResult:
        import time

        started = time.perf_counter()
        votes: list[Vote] = []
        unavailable: list[str] = []

        for member in self.members:
            try:
                result = member.solve_sync(image)
            except SolverUnavailable as exc:
                unavailable.append(str(exc))
                continue
            if result.text:
                votes.append(Vote(result.text, result.confidence, result.engine))

        if not votes:
            if unavailable and len(unavailable) == len(self.members):
                raise SolverUnavailable(unavailable[0])
            return SolveResult(
                text="", confidence=0.0, engine=self.name, elapsed=time.perf_counter() - started
            )

        text, confidence = self._choose(votes)
        return SolveResult(
            text=text,
            confidence=confidence,
            engine=self.name,
            elapsed=time.perf_counter() - started,
            fragments=[Fragment(v.text, v.confidence, 0.0) for v in votes],
        )

    def _choose(self, votes: list[Vote]) -> tuple[str, float]:
        eligible = votes
        if self.expected_length is not None:
            right_length = [v for v in votes if len(v.text) == self.expected_length]
            if right_length:
                eligible = right_length

        # Case-insensitive agreement: engines disagree on case constantly and
        # almost every CAPTCHA compares case-insensitively.
        tally = Counter(v.text.upper() for v in eligible)

        def mean_confidence(candidate: str) -> float:
            scores = [v.confidence for v in eligible if v.text.upper() == candidate]
            return sum(scores) / len(scores) if scores else 0.0

        def score(candidate: str) -> float:
            # Mean confidence leads, with a small bonus for agreement.
            #
            # Counting votes first is the obvious rule and it is wrong here:
            # members that share a preprocessing recipe fail the same way, so
            # a majority can be two copies of one mistake. Averaging confidence
            # lets a lone high-confidence answer outweigh a pair of hesitant
            # ones, and dilutes a candidate that only some members believe.
            return mean_confidence(candidate) + AGREEMENT_BONUS * (tally[candidate] - 1)

        winner = max(tally, key=score)
        # Return the original casing of the most confident vote for it.
        matching = [v for v in eligible if v.text.upper() == winner]
        chosen = max(matching, key=lambda v: v.confidence)
        return chosen.text, mean_confidence(winner)


def default_ensemble(
    charset: str | None = None,
    expected_length: int | None = None,
    preprocessor: object = None,
    include_slow: bool = True,
) -> EnsembleSolver:
    """The configurations that cover each other's blind spots.

    Chosen from measured behaviour, not intuition: the two ddddocr weights
    fail on different images, and one of them does better on the untouched
    image than on a cleaned one, because aggressive thresholding can erase a
    stroke the model would otherwise have used.
    """
    from capat.solvers.ddddocr_solver import DdddOcrSolver
    from capat.solvers.easyocr_solver import EasyOCRSolver
    from capat.solvers.preprocess import Preprocessor

    cleaned = (
        preprocessor
        if preprocessor is not None
        else Preprocessor(min_saturation=60, scale=3, median=0, threshold=200, dilate=3)
    )
    # A second, unrelated recipe. Saturation and median filtering fail on
    # different characters - on one measured image the saturation route read
    # the first glyph as R and the median route read it correctly as P - so
    # carrying both buys diversity that another model alone does not.
    denoised = Preprocessor(scale=3, median=3, threshold=140, dilate=3)

    def ddddocr(pre: object, beta: bool = False) -> Solver:
        return DdddOcrSolver(
            preprocessor=pre, charset=charset, expected_length=expected_length, beta=beta
        )

    members: list[Solver] = [
        ddddocr(cleaned),
        ddddocr(denoised),
        ddddocr(None, beta=True),
        ddddocr(None),
    ]
    if include_slow:
        # An order of magnitude slower than the rest combined, and weaker on
        # overlapping glyphs - but it fails differently, and a hesitant wrong
        # answer from it still drags a bad candidate's mean confidence down.
        members.append(
            EasyOCRSolver(preprocessor=cleaned, charset=charset, expected_length=expected_length)
        )
    return EnsembleSolver(members, expected_length=expected_length)
