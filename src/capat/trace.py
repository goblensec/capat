"""Per-request tracing, for when the report is not enough.

A run reports outcomes. When those outcomes look wrong the operator needs the
layer underneath: what was sent, what came back, and how it was read.
Reconstructing that from a proxy log is slower than printing it.

The marker carries the classification - `[+]` got in, `[-]` reached the
credential check, `[!]` never got past the CAPTCHA - because those three are
what the whole measurement rests on, and they are what the eye should land on
while a run scrolls past.

Opt-in and off by default: enabled, it prints the values submitted, passwords
and solved answers included. It belongs on a terminal during tuning, not in a
log file or a client report.
"""

from __future__ import annotations

from typing import Any, TextIO

import httpx
from rich.console import Console
from rich.text import Text

BODY_CHARS = 240

# Outcome -> (marker, style). An attempt rejected for its credentials is the
# good news during tuning: the CAPTCHA was solved, so the pipeline works.
OUTCOMES = {
    "success": ("[+]", "bold green"),
    "auth_failure": ("[-]", "yellow"),
    "captcha_failure": ("[!]", "red"),
    "unknown": ("[?]", "bold magenta"),
}

_console: Console | None = None


def enable(stream: TextIO | None = None) -> None:
    """Turn tracing on. Idempotent, so repeated calls do not double-print."""
    global _console
    if _console is None:
        _console = Console(stderr=stream is None, file=stream, highlight=False)


def disable() -> None:
    global _console
    _console = None


def enabled() -> bool:
    return _console is not None


def _body(resp: httpx.Response) -> str:
    text = " ".join(resp.text.split())
    return text[:BODY_CHARS] + ("..." if len(text) > BODY_CHARS else "")


def _status_style(code: int) -> str:
    if code >= 500:
        return "bold red"
    return "yellow" if code >= 400 else "green"


def attempt(username: str, password: str, captcha: str, resp: httpx.Response, outcome: Any) -> None:
    """One login round-trip: what went out, what came back, how it was read."""
    if _console is None:
        return
    name = str(getattr(outcome, "value", outcome))
    marker, style = OUTCOMES.get(name, ("[?]", "white"))

    line = Text(f"{marker} ", style=style)
    line.append("login   ", style="bold")
    line.append("user=", style="dim")
    line.append(username or "<empty>", style="cyan")
    line.append(" pass=", style="dim")
    line.append(password or "<empty>", style="bold cyan")
    line.append(" captcha=", style="dim")
    line.append(captcha or "<omitted>", style="magenta" if captcha else "dim")
    line.append(" -> ", style="dim")
    line.append(str(resp.status_code), style=_status_style(resp.status_code))
    line.append(" ")
    line.append(name, style=style)
    _console.print(line)
    _console.print(Text(f"    {_body(resp)}", style="dim"))


def challenge(url: str, resp: httpx.Response, solved: str = "") -> None:
    if _console is None:
        return
    line = Text("[*] ", style="cyan")
    line.append("captcha ", style="bold")
    line.append(url, style="dim")
    line.append(" -> ", style="dim")
    line.append(str(resp.status_code), style=_status_style(resp.status_code))
    line.append(f", {len(resp.content)} bytes", style="dim")
    if solved:
        line.append(" read as ", style="dim")
        line.append(solved, style="magenta")
    _console.print(line)


def note(message: str, marker: str = "[*]", style: str = "cyan") -> None:
    """A line of context between requests: a retry, a skip, a lockout stop."""
    if _console is None:
        return
    line = Text(f"{marker} ", style=style)
    line.append(message, style="dim" if style == "cyan" else style)
    _console.print(line)
