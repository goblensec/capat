from __future__ import annotations

import logging
from importlib.metadata import entry_points

from capat.solvers.base import Fragment, Solver, SolveResult, SolverUnavailable
from capat.solvers.ddddocr_solver import DdddOcrSolver
from capat.solvers.easyocr_solver import EasyOCRSolver
from capat.solvers.ensemble import EnsembleSolver, default_ensemble
from capat.solvers.preprocess import Preprocessor
from capat.solvers.tesseract_solver import TesseractSolver

__all__ = [
    "Fragment",
    "SolveResult",
    "Solver",
    "SolverUnavailable",
    "EasyOCRSolver",
    "DdddOcrSolver",
    "EnsembleSolver",
    "TesseractSolver",
    "Preprocessor",
    "build_solver",
    "available_solvers",
]

_BUILTINS: dict[str, type[Solver]] = {
    EasyOCRSolver.name: EasyOCRSolver,
    DdddOcrSolver.name: DdddOcrSolver,
    TesseractSolver.name: TesseractSolver,
}

# Assembled rather than instantiated like the rest, because they compose the others.
ENSEMBLE = "ensemble"
ENSEMBLE_FAST = "ensemble-fast"
"""Same voting, ddddocr members only: about a tenth of the time, and on the
measured corpus one image worse. Use it when throughput matters more than the
last few percent."""


def available_solvers(include_plugins: bool = True) -> list[str]:
    return sorted([*_registry(include_plugins), ENSEMBLE, ENSEMBLE_FAST])


log = logging.getLogger("capat.solvers")


def _registry(include_plugins: bool = True) -> dict[str, type[Solver]]:
    """Built-in engines plus whatever registered under `capat.solvers`.

    `ep.load()` imports third-party code, and this runs while argparse is
    still building the help string for -s. One plugin whose own dependency is
    missing therefore used to take down every command, `capat --help`
    included. A plugin that cannot be imported is skipped with a warning: the
    tool it extends keeps working without it.
    """
    registry = dict(_BUILTINS)
    if include_plugins:
        for ep in entry_points(group="capat.solvers"):
            try:
                obj = ep.load()
            except Exception as exc:  # noqa: BLE001 - third-party import, any failure
                log.warning("solver plugin %r could not be loaded: %s", ep.name, exc)
                continue
            if isinstance(obj, type) and issubclass(obj, Solver):
                registry[ep.name] = obj
    return registry


MODEL_SUFFIX = ".onnx"


def is_model_path(name: str) -> bool:
    """True when -s names a model file rather than a registered engine.

    Unambiguous by construction: no registered name ends in `.onnx`, and no
    model file is named after an engine.
    """
    return name.lower().endswith(MODEL_SUFFIX)


def build_solver(
    name: str,
    preprocessor: Preprocessor | None = None,
    charset: str | None = None,
    expected_length: int | None = None,
    include_plugins: bool = True,
    charset_file: str | None = None,
) -> Solver:
    if is_model_path(name):
        # Loaded through ddddocr, which is the runtime for this format; a
        # trained model is a file path here, not a plugin to install.
        from capat.solvers.ddddocr_solver import DdddOcrSolver

        return DdddOcrSolver(
            preprocessor=preprocessor,
            charset=charset,
            expected_length=expected_length,
            model_path=name,
            charsets_path=charset_file,
        )
    if name in (ENSEMBLE, ENSEMBLE_FAST):
        return default_ensemble(
            charset=charset,
            expected_length=expected_length,
            preprocessor=preprocessor,
            include_slow=name == ENSEMBLE,
        )
    registry = _registry(include_plugins)
    try:
        cls = registry[name]
    except KeyError:
        raise ValueError(
            f"unknown solver {name!r}; available: {', '.join(sorted([*registry, ENSEMBLE]))}, "
            "or the path to a .onnx model"
        ) from None
    return cls(preprocessor=preprocessor, charset=charset, expected_length=expected_length)
