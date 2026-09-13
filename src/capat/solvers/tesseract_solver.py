from __future__ import annotations

import io
from typing import Any

from capat.solvers.base import Fragment, Solver, SolverUnavailable

_DEFAULT_CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


class TesseractSolver(Solver):
    """Classical recognition via Tesseract.

    Kept alongside EasyOCR because the comparison is itself the point: a
    twenty-year-old engine that runs on a laptop CPU is often enough, which
    makes "an attacker would need a GPU" an untenable assumption.
    """

    name = "tesseract"

    def __init__(self, *args: Any, psm: int = 7, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._psm = psm

    def recognize(self, image: bytes) -> list[Fragment]:
        try:
            import pytesseract
            from PIL import Image
        except ImportError as exc:
            raise SolverUnavailable(
                "pytesseract is not installed. Install it with: "
                "pip install pytesseract  (the tesseract binary must also be on PATH). "
                "Or pick another engine: -s ddddocr, -s easyocr."
            ) from exc

        charset = self.charset or _DEFAULT_CHARSET
        config = f"--psm {self._psm} -c tessedit_char_whitelist={charset}"
        try:
            data: dict[str, list[Any]] = pytesseract.image_to_data(
                Image.open(io.BytesIO(image)),
                config=config,
                output_type=pytesseract.Output.DICT,
            )
        except OSError as exc:  # tesseract binary missing
            raise SolverUnavailable(f"tesseract binary not usable: {exc}") from exc

        fragments: list[Fragment] = []
        # strict=False: a malformed dict from tesseract should degrade the
        # solve, not abort the run.
        for text, conf, left, width in zip(
            data["text"], data["conf"], data["left"], data["width"], strict=False
        ):
            cleaned = str(text).strip().replace(" ", "")
            confidence = float(conf)
            if not cleaned or confidence < 0:
                continue
            fragments.append(
                Fragment(
                    text=cleaned,
                    confidence=confidence / 100.0,
                    x_center=float(left) + float(width) / 2.0,
                )
            )
        return fragments
