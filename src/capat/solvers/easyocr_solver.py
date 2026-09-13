from __future__ import annotations

import threading
from typing import Any

from capat.solvers.base import Fragment, Solver, SolverUnavailable

_DEFAULT_CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


class EasyOCRSolver(Solver):
    """Deep-learning recognition via EasyOCR.

    The model is loaded once, lazily, on first use - not at import time, so
    that `--help` and the test suite stay fast and importing the package never
    reaches out to download weights.
    """

    name = "easyocr"

    def __init__(
        self,
        *args: Any,
        languages: tuple[str, ...] = ("en",),
        text_threshold: float = 0.5,
        low_text: float = 0.3,
        mag_ratio: float = 2.0,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._languages = list(languages)
        # Detection defaults are tuned for photographs of signage, where a
        # false positive is costly. A CAPTCHA is the opposite case: the glyphs
        # are deliberately faint and broken, and missing one loses the whole
        # answer, so detection is deliberately more eager here.
        self._text_threshold = text_threshold
        self._low_text = low_text
        self._mag_ratio = mag_ratio
        self._reader: Any = None
        self._init_lock = threading.Lock()

    def _get_reader(self) -> Any:
        if self._reader is None:
            with self._init_lock:
                if self._reader is None:
                    try:
                        import easyocr
                    except ImportError as exc:
                        raise SolverUnavailable(
                            "easyocr is not installed. Install it with: "
                            "pip install easyocr  (large: it pulls in torch). "
                            "-s ddddocr is about 10 MB and usually reads CAPTCHAs better."
                        ) from exc
                    self._reader = easyocr.Reader(self._languages, verbose=False)
        return self._reader

    def recognize(self, image: bytes) -> list[Fragment]:
        results = self._get_reader().readtext(
            image,
            detail=1,
            allowlist=self.charset or _DEFAULT_CHARSET,
            text_threshold=self._text_threshold,
            low_text=self._low_text,
            mag_ratio=self._mag_ratio,
        )
        fragments: list[Fragment] = []
        for box, text, confidence in results:
            xs = [float(point[0]) for point in box]
            fragments.append(
                Fragment(
                    text=str(text).replace(" ", ""),
                    confidence=float(confidence),
                    x_center=sum(xs) / len(xs),
                )
            )
        return fragments
