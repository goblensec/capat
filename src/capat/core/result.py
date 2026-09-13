from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


class Severity(enum.IntEnum):
    """Ordered so findings sort and filter naturally."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(slots=True)
class Finding:
    """A single observation produced by a module.

    Findings are the one thing modules return. Keep evidence small.

    A password this tool discovers IS reported in full, in the title and the
    evidence, alongside its wordlist line: the operator is authorized, and a
    finding that will not say which password worked cannot be acted on. That
    makes a findings file a credential file - treat it as one, and note that
    `--format json` output is not safe to paste into a ticket unread.

    Everything else stays out: session cookies, bearer tokens, and CSRF values
    identify a live session and prove nothing the finding needs.
    """

    module: str
    title: str
    target: str
    severity: Severity = Severity.INFO
    description: str = ""
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = str(self.severity)
        data["discovered_at"] = self.discovered_at.isoformat()
        return data
