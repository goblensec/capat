from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable, Sequence

from capat.core.config import Config
from capat.core.result import Finding, Severity
from capat.core.target import Target
from capat.http.client import HttpClient
from capat.modules.base import Module

log = logging.getLogger("capat.engine")


class Engine:
    """Coordinates modules against targets with bounded concurrency.

    The engine knows nothing about what any module does. It normalizes
    targets, fans out (module, target) pairs, limits how many run at once, and
    isolates failures so one bad host cannot abort the run.
    """

    def __init__(self, config: Config, modules: Sequence[Module]) -> None:
        if not modules:
            raise ValueError("at least one module is required")
        self._config = config
        self._modules = list(modules)
        self._semaphore = asyncio.Semaphore(config.concurrency)

    async def run(self, targets: Iterable[str]) -> list[Finding]:
        normalized = [Target(t) for t in targets]

        # Kept alongside the results so a failure can name the module it came
        # from; asyncio.gather preserves order.
        pairs = [(module, target) for target in normalized for module in self._modules]

        async with HttpClient(self._config) as client:
            results = await asyncio.gather(
                *(self._run_one(module, target, client) for module, target in pairs),
                return_exceptions=True,
            )

        findings: list[Finding] = []
        for (module, target), outcome in zip(pairs, results, strict=True):
            if isinstance(outcome, BaseException):
                log.warning("%s raised against %s: %s", module.name, target.url, outcome)
                findings.append(self._crashed(module, target, outcome))
                continue
            findings.extend(outcome)
        return findings

    @staticmethod
    def _crashed(module: Module, target: Target, exc: BaseException) -> Finding:
        """A module that died is reported, not logged and dropped.

        Isolating a failure must not turn it into a clean result. This used to
        be a `log.warning` and nothing else, so a module that raised - an
        unreadable CAPTCHA endpoint, a 403 where an image was expected - left
        the run printing "no findings" and exiting 0. That is the same defect
        as a false CRITICAL, pointed the other way: the report claimed a check
        had passed that never ran.
        """
        return Finding(
            module=module.name,
            title=f"{module.name} could not complete: {type(exc).__name__}",
            target=target.url,
            severity=Severity.INFO,
            description=(
                f"The check stopped on an unexpected error and reports nothing about the "
                f"target. Treat this as a gap in the run, not as a control that held. "
                f"The error was: {exc}"
            ),
            remediation=(
                "Re-run with --debug to see the request that failed. A wrong --captcha-url, "
                "a response that is not the image or JSON the profile describes, or a header "
                "the target requires are the usual causes."
            ),
            evidence={"error_type": type(exc).__name__, "error": str(exc)},
        )

    async def _run_one(self, module: Module, target: Target, client: HttpClient) -> list[Finding]:
        async with self._semaphore:
            log.debug("run %s against %s", module.name, target.host)
            return await module.run(target, client)
