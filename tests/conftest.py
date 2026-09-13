from __future__ import annotations

import io

import pytest
from PIL import Image

from capat.core.config import Config
from capat.core.profile import LoginProfile, SuccessCriteria
from capat.solvers.base import Fragment, Solver

CONFIG = Config(requests_per_second=1000, retries=0)


class ScriptedSolver(Solver):
    """Returns queued answers. Keeps tests off the real OCR models."""

    name = "scripted"

    def __init__(self, answers: list[str], **kwargs: object) -> None:
        super().__init__(preprocessor=None, **kwargs)  # type: ignore[arg-type]
        self.answers = list(answers)
        self.calls = 0

    def recognize(self, image: bytes) -> list[Fragment]:
        self.calls += 1
        answer = self.answers.pop(0) if self.answers else ""
        return [Fragment(text=answer, confidence=0.9, x_center=0.0)]

    async def warmup(self) -> None:
        """No model to load, and a real warmup would eat a scripted answer."""
        return None


@pytest.fixture
def config() -> Config:
    return CONFIG


@pytest.fixture
def profile() -> LoginProfile:
    return LoginProfile(
        login_url="https://app.example.test/login",
        captcha_url="https://app.example.test/captcha.png",
        username="auditee",
        criteria=SuccessCriteria(
            captcha_failure=["invalid captcha"],
            auth_failure=["invalid username or password"],
            success=["welcome back"],
        ),
    )


@pytest.fixture
def png_bytes() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (120, 40), "white").save(buf, format="PNG")
    return buf.getvalue()
