from __future__ import annotations

import io
import time

import httpx
import pytest
import respx
from PIL import Image

from capat.core.config import Config
from capat.core.engine import Engine
from capat.core.result import Finding, Severity
from capat.corpus import CorpusBenchmark, load_corpus
from capat.http.client import HttpClient
from capat.http.rate_limiter import RateLimiter
from capat.modules.base import Module
from capat.reporting.reporter import Reporter
from tests.conftest import CONFIG, ScriptedSolver


class Noisy(Module):
    name = "noisy"

    async def run(self, target, client):
        raise RuntimeError("boom")


class Quiet(Module):
    name = "quiet"

    async def run(self, target, client):
        return [Finding(module=self.name, title="ok", target=target.url)]


# --------------------------------------------------------------------------
# engine
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_engine_isolates_a_failing_module_without_hiding_it():
    """One module dying must not abort the others - but it must still be
    reported. Isolation used to mean a WARNING in the log and nothing in the
    report, so a run whose check crashed printed "no findings" and exited 0."""
    engine = Engine(CONFIG, [Noisy(), Quiet()])
    findings = await engine.run(["app.example.test"])
    assert [f.module for f in findings] == ["noisy", "quiet"]
    assert "RuntimeError" in findings[0].title


def test_engine_requires_at_least_one_module():
    with pytest.raises(ValueError):
        Engine(CONFIG, [])


# --------------------------------------------------------------------------
# http client
# --------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_sessions_do_not_share_cookies():
    """Each login attempt needs its own jar, or workers overwrite each other's
    pending CAPTCHA answer server-side."""
    respx.get("https://app.example.test/set").mock(
        return_value=httpx.Response(200, headers={"set-cookie": "sid=abc; Path=/"})
    )
    seen: list[str] = []
    respx.get("https://app.example.test/read").mock(
        side_effect=lambda request: (
            seen.append(request.headers.get("cookie", "")),
            httpx.Response(200),
        )[1]
    )

    async with HttpClient(CONFIG) as client:
        async with client.session() as first:
            await first.get("https://app.example.test/set")
            await first.get("https://app.example.test/read")
        async with client.session() as second:
            await second.get("https://app.example.test/read")

    assert "sid=abc" in seen[0]
    assert "sid=abc" not in seen[1]


# --------------------------------------------------------------------------
# rate limiter
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_burst_is_free_then_throttles():
    limiter = RateLimiter(rate=20, burst=2)
    start = time.monotonic()
    for _ in range(4):
        await limiter.acquire()
    assert time.monotonic() - start >= 0.08


def test_rejects_non_positive_rate():
    with pytest.raises(ValueError):
        RateLimiter(rate=0)


def test_config_validates_its_knobs():
    with pytest.raises(ValueError):
        Config(concurrency=0)
    with pytest.raises(ValueError):
        Config(requests_per_second=0)
    with pytest.raises(ValueError):
        Config(samples=0)


# --------------------------------------------------------------------------
# corpus benchmark
# --------------------------------------------------------------------------


def _write_png(path):
    buf = io.BytesIO()
    Image.new("RGB", (40, 20), "white").save(buf, format="PNG")
    path.write_bytes(buf.getvalue())


def test_load_corpus_labels_from_filename(tmp_path):
    _write_png(tmp_path / "A8R36.png")
    _write_png(tmp_path / "T29MG_002.png")
    (tmp_path / "notes.txt").write_text("ignored", encoding="utf-8")

    images = load_corpus(tmp_path)
    assert sorted(i.label for i in images) == ["A8R36", "T29MG"]


def test_load_corpus_rejects_an_empty_directory(tmp_path):
    with pytest.raises(ValueError, match="no labeled images"):
        load_corpus(tmp_path)


def test_load_corpus_rejects_a_missing_directory(tmp_path):
    with pytest.raises(NotADirectoryError):
        load_corpus(tmp_path / "nope")


@pytest.mark.asyncio
async def test_benchmark_scores_exact_and_partial_matches(tmp_path):
    _write_png(tmp_path / "A8R36.png")
    _write_png(tmp_path / "T29MG.png")
    images = sorted(load_corpus(tmp_path), key=lambda i: i.label)

    report = await CorpusBenchmark(ScriptedSolver(["A8R36", "T29MX"])).run(images)

    assert report.total == 2
    assert report.solved == 1
    assert report.accuracy == 0.5
    assert 0.5 < report.character_accuracy < 1.0
    assert report.to_dict()["accuracy"] == 0.5


@pytest.mark.asyncio
async def test_benchmark_case_sensitivity_is_configurable(tmp_path):
    _write_png(tmp_path / "A8R36.png")
    images = load_corpus(tmp_path)

    assert (await CorpusBenchmark(ScriptedSolver(["a8r36"])).run(images)).accuracy == 1.0
    strict = CorpusBenchmark(ScriptedSolver(["a8r36"]), case_sensitive=True)
    assert (await strict.run(images)).accuracy == 0.0


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------


def test_markdown_report_includes_remediation():
    out = io.StringIO()
    Reporter(out).render(
        [
            Finding(
                module="captcha-gate",
                title="CAPTCHA not required",
                target="https://app.example.test/login",
                severity=Severity.CRITICAL,
                description="desc",
                remediation="fix it",
            )
        ],
        fmt="markdown",
    )
    text = out.getvalue()
    assert "# CAPTCHA assessment" in text
    assert "critical" in text
    assert "fix it" in text


def test_unknown_format_is_rejected():
    with pytest.raises(ValueError, match="unknown format"):
        Reporter(io.StringIO()).render([], fmt="xml")
