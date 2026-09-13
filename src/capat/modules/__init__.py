from __future__ import annotations

import logging
from importlib.metadata import entry_points

from capat.modules.base import Module
from capat.modules.credential_audit import CredentialAudit
from capat.modules.gate_enforcement import CaptchaGate
from capat.modules.login_flow import Attempt, LoginFlow
from capat.modules.solve_rate import CaptchaSolveRate

__all__ = [
    "Module",
    "Attempt",
    "LoginFlow",
    "CaptchaGate",
    "CaptchaSolveRate",
    "CredentialAudit",
    "load_plugin_modules",
]


log = logging.getLogger("capat.modules")


def load_plugin_modules() -> list[type[Module]]:
    """Third-party modules registered under the capat.modules group.

    Built-in modules are constructed in the CLI because each needs a different
    slice of the run configuration; plugins are returned as classes so the
    caller decides how to instantiate them.
    """
    found: list[type[Module]] = []
    for ep in entry_points(group="capat.modules"):
        try:
            obj = ep.load()
        except Exception as exc:  # noqa: BLE001 - third-party import, any failure
            # One unimportable plugin must not abort a run of the built-ins.
            log.warning("module plugin %r could not be loaded: %s", ep.name, exc)
            continue
        if isinstance(obj, type) and issubclass(obj, Module):
            found.append(obj)
    return found
