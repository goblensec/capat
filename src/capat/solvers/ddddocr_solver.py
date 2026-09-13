from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from capat.solvers.base import Fragment, Solver, SolverUnavailable


class DdddOcrSolver(Solver):
    """Recognition via ddddocr, a model trained specifically on CAPTCHAs.

    Worth having alongside a general engine because the difference is
    structural, not incremental. Scene-text engines detect text regions and
    then read each one, so two glyphs that touch become a single region and
    one of them is lost - which is exactly what deliberate glyph overlap is
    designed to cause. This model reads the whole image as one sequence, so
    overlap costs it much less. It is also ONNX rather than torch: about ten
    megabytes, no GPU, and roughly an order of magnitude faster.

    Two model weights ship with it. They fail on different images, so the
    `beta` flag is worth sweeping rather than fixing - see EnsembleSolver.
    A model trained elsewhere loads through the same class: this engine is the
    reference runtime for CRNN+CTC ONNX, so a custom model is a file path
    rather than a plugin to write.
    """

    name = "ddddocr"

    def __init__(
        self,
        *args: Any,
        beta: bool = False,
        model_path: str | None = None,
        charsets_path: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._beta = beta
        self._model_path = model_path
        self._charsets_path = charsets_path
        self._ocr: Any = None
        self._init_lock = threading.Lock()

    def _custom_kwargs(self) -> dict[str, Any]:
        """Arguments that point ddddocr at a model on disk.

        The charset is not optional for a custom model - CTC output is indices,
        and without the labels the answer is silently the wrong alphabet - so a
        missing one is an error here rather than a wrong reading later.
        """
        if not self._model_path:
            return {"beta": self._beta}
        model = Path(self._model_path)
        if not model.is_file():
            raise SolverUnavailable(f"no model file at {model}")
        charsets = Path(self._charsets_path) if self._charsets_path else model.with_suffix(".json")
        if not charsets.is_file():
            raise SolverUnavailable(
                f"model {model.name} needs its charset: expected {charsets}, "
                "or give one with --charset-file"
            )
        return {
            "det": False,
            "ocr": False,
            "import_onnx_path": str(model),
            "charsets_path": str(charsets),
        }

    def _get_ocr(self) -> Any:
        if self._ocr is None:
            with self._init_lock:
                if self._ocr is None:
                    try:
                        import ddddocr
                    except ImportError as exc:
                        raise SolverUnavailable(
                            "ddddocr is not installed. Install it with: "
                            "pip install ddddocr  (about 10 MB, no GPU, no torch). "
                            "Or pick another engine: -s easyocr, -s tesseract."
                        ) from exc
                    kwargs = self._custom_kwargs()
                    try:
                        self._ocr = ddddocr.DdddOcr(show_ad=False, **kwargs)
                    except Exception as exc:  # noqa: BLE001 - any load failure
                        # ddddocr raises its own exception types with messages
                        # in Chinese. Unhandled, an operator gets a traceback
                        # about someone else's library instead of a fixable
                        # statement about their own file.
                        raise SolverUnavailable(
                            f"could not load {self._model_path}: {exc}. The charset file must "
                            'be JSON with "charset", "word", "image" ([width, height]; width -1 '
                            'scales to the height) and "channel"'
                        ) from exc
        return self._ocr

    def recognize(self, image: bytes) -> list[Fragment]:
        ocr = self._get_ocr()
        try:
            try:
                result = ocr.classification(image, probability=True)
            except TypeError:
                # Custom models in some releases do not report per-character
                # probability; a bare reading is still worth having.
                result = ocr.classification(image)
        except Exception as exc:  # noqa: BLE001 - any inference failure
            if not self._model_path:
                raise
            # A custom model only fails this way when its sidecar does not
            # describe it. ddddocr reports that in Chinese, from inside its own
            # call stack; the operator needs a statement about their own file.
            raise SolverUnavailable(
                f"{Path(self._model_path).name} failed on an image: {exc}. Check the charset "
                'file: "image" is [width, height] and width -1 scales to the height'
            ) from exc

        if isinstance(result, dict):
            text = str(result.get("text", ""))
            confidence = float(result.get("confidence", 0.0) or 0.0)
        else:  # older releases return a bare string
            text, confidence = str(result), 0.0

        # The bundled charset includes CJK; a Latin/digit CAPTCHA never wants
        # it, and it would otherwise survive into the answer. A custom model
        # was trained on its own charset, so nothing is filtered there.
        if not self._model_path:
            text = "".join(ch for ch in text if ch.isascii())
        if not text:
            return []

        # One sequence, not per-character boxes: there is nothing to order.
        return [Fragment(text=text, confidence=confidence, x_center=0.0)]

    def __repr__(self) -> str:
        if self._model_path:
            return f"<DdddOcrSolver model={Path(self._model_path).name}>"
        return f"<DdddOcrSolver beta={self._beta}>"
