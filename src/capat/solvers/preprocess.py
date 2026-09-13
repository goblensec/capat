from __future__ import annotations

import io
from dataclasses import asdict, dataclass
from typing import Any

from PIL import Image, ImageFilter, ImageOps


@dataclass(slots=True)
class Preprocessor:
    """Deterministic image cleanup applied before recognition.

    The defaults target the classic "distorted glyphs over thin noise lines"
    CAPTCHA: upscale so strokes survive thresholding, drop colour (noise lines
    are often coloured while glyphs are not - but so is the reverse, hence
    grayscale rather than channel picking), median-filter away 1px lines, then
    binarize. Every step is a knob because the right recipe is per-target;
    `capat bench` exists to find it empirically.
    """

    scale: float = 3.0
    min_saturation: int = 0
    """Drop pixels below this colour saturation, 0-255 (0 disables).

    Many CAPTCHAs draw coloured glyphs over grey noise lines. Saturation
    separates the two exactly, where a grayscale threshold cannot: the lines
    and the strokes land at similar brightness, so tuning the threshold trades
    one for the other. Applied before grayscale conversion."""

    grayscale: bool = True
    autocontrast: bool = True
    median: int = 3
    """Median filter kernel (odd, 0 disables). This is what removes the thin
    strike-through lines without eating glyph strokes."""

    threshold: int | None = 140
    """Binarization cut-off, 0-255. None keeps grayscale."""

    invert: bool = False
    dilate: int = 0
    """Thicken dark strokes (odd kernel, 0 disables).

    Thresholding thins and sometimes breaks glyph strokes, and a detector that
    misses a faint character reports a CAPTCHA as unsolved when the recipe,
    not the engine, was the limit. Applied after binarization."""

    border: int = 10
    """Quiet margin. OCR engines lose glyphs that touch the image edge."""

    def apply(self, data: bytes) -> bytes:
        img: Image.Image = Image.open(io.BytesIO(data))
        if img.mode in ("RGBA", "LA", "P"):
            # Composite onto white rather than dropping alpha: a naive convert
            # renders transparent pixels black and buries the glyphs.
            img = img.convert("RGBA")
            img = Image.alpha_composite(Image.new("RGBA", img.size, "white"), img)
        if img.mode not in ("L", "RGB"):
            img = img.convert("RGB")
        if self.scale and self.scale != 1.0:
            img = img.resize(
                (max(1, int(img.width * self.scale)), max(1, int(img.height * self.scale))),
                Image.Resampling.LANCZOS,
            )
        if self.min_saturation:
            rgb = img.convert("RGB")
            saturation = rgb.convert("HSV").getchannel("S")
            # Keep saturated pixels; everything greyer becomes background.
            mask = saturation.point(lambda v: 255 if v >= self.min_saturation else 0, mode="1")
            white = Image.new("RGB", rgb.size, "white")
            img = Image.composite(rgb, white, mask)
        if self.grayscale:
            img = img.convert("L")
        if self.autocontrast:
            img = ImageOps.autocontrast(img.convert("L"))
        if self.median and self.median > 1:
            img = img.filter(ImageFilter.MedianFilter(size=self.median | 1))
        if self.threshold is not None:
            img = img.convert("L").point(lambda p: 255 if p > self.threshold else 0, mode="L")
        if self.dilate and self.dilate > 1:
            # MinFilter spreads the darkest pixel, thickening dark strokes.
            img = img.convert("L").filter(ImageFilter.MinFilter(size=self.dilate | 1))
        if self.invert:
            img = ImageOps.invert(img.convert("L"))
        if self.border:
            fill = 0 if self.invert else 255
            img = ImageOps.expand(img, border=self.border, fill=fill)

        out = io.BytesIO()
        img.convert("RGB").save(out, format="PNG")
        return out.getvalue()

    def describe(self) -> dict[str, Any]:
        return asdict(self)
