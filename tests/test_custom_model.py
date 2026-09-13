"""Loading a model off disk with `-s path/to/model.onnx`.

A model trained elsewhere is ddddocr-compatible CRNN+CTC exported to ONNX.
Requiring a plugin to be packaged and installed before one can be
tried against a target would make every experiment cost a release, so a model
is a file path here.

Nothing in this file runs inference: a real model is 13MB and the runtime is
ddddocr's. What is pinned is the wiring and the refusals, which is where this
feature can silently do the wrong thing - a model read with the wrong charset
does not fail, it answers in the wrong alphabet.
"""

from __future__ import annotations

import json

import pytest

from capat.cli import build_parser, solver_settings
from capat.core.profile import LoginProfile, SolverSettings
from capat.solvers import build_solver, is_model_path
from capat.solvers.base import SolverUnavailable
from capat.solvers.ddddocr_solver import DdddOcrSolver


def test_a_path_is_told_apart_from_an_engine_name():
    """No registered engine ends in .onnx and no model is named after one, so
    the two cannot collide."""
    assert is_model_path("model.onnx")
    assert is_model_path(r"C:\models\Target.ONNX")
    assert not is_model_path("ddddocr")
    assert not is_model_path("ensemble")


def test_a_model_path_builds_the_runtime_that_reads_that_format():
    solver = build_solver("some/model.onnx", charset_file="some/labels.json")
    assert isinstance(solver, DdddOcrSolver)
    assert "model.onnx" in repr(solver)


def test_an_unknown_engine_name_still_names_the_alternatives():
    with pytest.raises(ValueError, match=r"unknown solver.*\.onnx model"):
        build_solver("not-an-engine")


def test_a_missing_model_file_is_refused_before_any_image(tmp_path):
    solver = DdddOcrSolver(model_path=str(tmp_path / "absent.onnx"))
    with pytest.raises(SolverUnavailable, match="no model file at"):
        solver._custom_kwargs()


def test_a_model_without_its_charset_is_refused(tmp_path):
    """CTC output is indices. Without the labels the answer is not wrong in a
    way anyone would notice - it is a different alphabet, confidently."""
    model = tmp_path / "m.onnx"
    model.write_bytes(b"not really onnx, never loaded")
    solver = DdddOcrSolver(model_path=str(model))
    with pytest.raises(SolverUnavailable, match="needs its charset"):
        solver._custom_kwargs()


def test_a_charset_sitting_next_to_the_model_is_found_without_a_flag(tmp_path):
    model = tmp_path / "m.onnx"
    model.write_bytes(b"stub")
    (tmp_path / "m.json").write_text(json.dumps({"charset": ["a"]}), encoding="utf-8")

    kwargs = DdddOcrSolver(model_path=str(model))._custom_kwargs()
    assert kwargs["import_onnx_path"] == str(model)
    assert kwargs["charsets_path"] == str(tmp_path / "m.json")
    # det/ocr off is what tells ddddocr to use the supplied model, not its own.
    assert kwargs["det"] is False and kwargs["ocr"] is False


def test_an_explicit_charset_file_wins_over_the_sidecar(tmp_path):
    model = tmp_path / "m.onnx"
    model.write_bytes(b"stub")
    (tmp_path / "m.json").write_text("{}", encoding="utf-8")
    other = tmp_path / "labels.json"
    other.write_text("{}", encoding="utf-8")

    kwargs = DdddOcrSolver(model_path=str(model), charsets_path=str(other))._custom_kwargs()
    assert kwargs["charsets_path"] == str(other)


def test_the_stock_engine_is_untouched_by_any_of_this():
    kwargs = DdddOcrSolver()._custom_kwargs()
    assert kwargs == {"beta": False}
    assert "import_onnx_path" not in kwargs


def test_a_model_and_its_charset_survive_a_saved_profile():
    """`-P` exists so a run that worked can be repeated. A tuned model that is
    not written out would make the saved profile silently fall back to stock."""
    settings = SolverSettings.parse({"name": "m.onnx", "charset_file": "labels.json"})
    assert settings.to_dict() == {"name": "m.onnx", "charset_file": "labels.json"}

    profile = LoginProfile.from_dict(
        {
            "login_url": "https://app.example.test/login",
            "captcha_url": "https://app.example.test/captcha",
            "solver": {"name": "m.onnx", "charset_file": "labels.json"},
        }
    )
    assert profile.solver.name == "m.onnx"
    assert profile.solver.charset_file == "labels.json"


def test_the_charset_file_flag_reaches_bench_and_solve():
    """`--charset-file` was dropped by every command except `audit`.

    `solver_settings` layers the flags named in SOLVER_FLAGS over the profile,
    and `charset_file` was not one of them - so `bench corpus -s m.onnx
    --charset-file labels.json` built the model with no labels at all. CTC
    output is indices, so that does not fail: it answers in the wrong
    alphabet, and the corpus score blames the model.
    """
    args = build_parser().parse_args(
        ["bench", "corpus", "-s", "m.onnx", "--charset-file", "labels.json"]
    )
    assert solver_settings(args).charset_file == "labels.json"
