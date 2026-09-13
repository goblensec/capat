"""Ensemble selection.

The rules here were derived from real measurements against a hardened CAPTCHA,
where the obvious rule (majority vote) picked the wrong answer.
"""

from __future__ import annotations

import pytest

from capat.solvers.base import Fragment, Solver, SolveResult, SolverUnavailable
from capat.solvers.ensemble import EnsembleSolver


class Fixed(Solver):
    """A member that always answers the same thing with a fixed confidence."""

    def __init__(self, answer: str, confidence: float, name: str = "fixed") -> None:
        super().__init__(preprocessor=None)
        self.name = name
        self._answer = answer
        self._confidence = confidence

    def recognize(self, image: bytes) -> list[Fragment]:
        if not self._answer:
            return []
        return [Fragment(self._answer, self._confidence, 0.0)]


class Broken(Solver):
    name = "broken"

    def __init__(self, message: str = "engine missing") -> None:
        super().__init__(preprocessor=None)
        self._message = message

    def recognize(self, image: bytes) -> list[Fragment]:
        raise SolverUnavailable(self._message)


def solve(members, expected_length=None) -> SolveResult:
    return EnsembleSolver(members, expected_length=expected_length).solve_sync(b"")


def test_a_confident_minority_beats_a_hesitant_majority():
    """The real case: two members share preprocessing and repeat one mistake.

    Measured against a live target - majority vote chose FJJ8S two-to-one
    while the correct FJ78S came from the single member reading the raw image.
    """
    result = solve(
        [
            Fixed("FJJ8s", 0.966, "ddddocr-cleaned"),
            Fixed("fj78s", 0.959, "ddddocr-beta-raw"),
            Fixed("FJJ8S", 0.507, "easyocr-cleaned"),
        ],
        expected_length=5,
    )
    assert result.text == "fj78s"


def test_agreement_still_breaks_a_near_tie():
    result = solve([Fixed("ABCDE", 0.90), Fixed("abcde", 0.90), Fixed("ABCDX", 0.92)])
    assert result.text.upper() == "ABCDE"


def test_expected_length_filters_candidates():
    """A confident short read must not beat a plausible full-length one."""
    result = solve(
        [Fixed("YWRK", 0.994, "easyocr"), Fixed("ywdRk", 0.944, "ddddocr")],
        expected_length=5,
    )
    assert result.text == "ywdRk"


def test_length_filter_is_ignored_when_nothing_matches():
    result = solve([Fixed("ABC", 0.9), Fixed("AB", 0.5)], expected_length=5)
    assert result.text == "ABC"


def test_original_casing_of_the_winning_vote_is_kept():
    result = solve([Fixed("abcde", 0.95), Fixed("ABCDE", 0.99)])
    assert result.text == "ABCDE"


def test_unavailable_members_are_skipped():
    result = solve([Broken(), Fixed("ABCDE", 0.9)])
    assert result.text == "ABCDE"


def test_all_members_unavailable_raises():
    with pytest.raises(SolverUnavailable, match="engine missing"):
        solve([Broken(), Broken()])


def test_empty_reads_yield_an_empty_answer():
    result = solve([Fixed("", 0.0), Fixed("", 0.0)])
    assert result.text == ""
    assert result.confidence == 0.0


def test_ensemble_needs_members():
    with pytest.raises(ValueError, match="at least one member"):
        EnsembleSolver([])


def test_result_reports_the_ensemble_and_keeps_every_vote():
    result = solve([Fixed("ABCDE", 0.9, "a"), Fixed("ABCDX", 0.8, "b")])
    assert result.engine == "ensemble"
    assert {f.text for f in result.fragments} == {"ABCDE", "ABCDX"}
