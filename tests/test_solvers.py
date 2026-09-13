import io

import pytest
from PIL import Image

from capat.solvers import available_solvers, build_solver
from capat.solvers.base import Fragment, Solver
from capat.solvers.preprocess import Preprocessor


class OutOfOrderSolver(Solver):
    """Emits fragments in detection order, not reading order."""

    name = "out-of-order"

    def __init__(self, fragments, **kwargs):
        super().__init__(preprocessor=None, **kwargs)
        self._fragments = fragments

    def recognize(self, image):
        return list(self._fragments)


@pytest.mark.asyncio
async def test_fragments_are_ordered_left_to_right():
    solver = OutOfOrderSolver(
        [
            Fragment("R", 0.9, 55.0),
            Fragment("A", 0.9, 10.0),
            Fragment("8", 0.9, 30.0),
        ]
    )
    assert (await solver.solve(b"")).text == "A8R"


@pytest.mark.asyncio
async def test_charset_filters_stray_characters():
    solver = OutOfOrderSolver(
        [Fragment("A-8*R", 0.9, 1.0)], charset="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
    assert (await solver.solve(b"")).text == "A8R"


@pytest.mark.asyncio
async def test_known_length_drops_the_least_confident_noise():
    solver = OutOfOrderSolver(
        [
            Fragment("A", 0.95, 10.0),
            Fragment("8", 0.93, 30.0),
            Fragment(".", 0.10, 50.0),
        ],
        expected_length=2,
    )
    assert (await solver.solve(b"")).text == "A8"


@pytest.mark.asyncio
async def test_confidence_is_the_mean_of_kept_fragments():
    solver = OutOfOrderSolver([Fragment("A", 1.0, 1.0), Fragment("B", 0.5, 2.0)])
    result = await solver.solve(b"")
    assert result.confidence == pytest.approx(0.75)
    assert result.engine == "out-of-order"


@pytest.mark.asyncio
async def test_empty_recognition_yields_empty_text():
    result = await OutOfOrderSolver([]).solve(b"")
    assert result.text == ""
    assert result.confidence == 0.0


def test_solve_result_matches_case_insensitively_by_default():
    solver = OutOfOrderSolver([Fragment("a8r", 0.9, 1.0)])
    result = solver.solve_sync(b"")
    assert result.matches("A8R")
    assert not result.matches("A8R", case_sensitive=True)


def test_preprocessor_returns_a_valid_png():
    src = io.BytesIO()
    Image.new("RGB", (60, 20), "white").save(src, format="PNG")
    out = Preprocessor(scale=2.0).apply(src.getvalue())
    img = Image.open(io.BytesIO(out))
    assert img.format == "PNG"
    # 60x20 upscaled 2x plus a 10px border on each side
    assert img.size == (140, 60)


def test_builtin_solvers_are_registered():
    assert {"easyocr", "tesseract"} <= set(available_solvers())


def test_unknown_solver_names_are_rejected():
    with pytest.raises(ValueError, match="unknown solver"):
        build_solver("nope")


def test_building_a_solver_does_not_load_its_model():
    # Constructing must stay cheap and dependency-free; only solving needs the engine.
    solver = build_solver("easyocr")
    assert solver.name == "easyocr"
