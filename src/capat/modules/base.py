from __future__ import annotations

import abc

from capat.core.result import Finding
from capat.core.target import Target
from capat.http.client import HttpClient


class Module(abc.ABC):
    """Base class for every check.

    Contract:
      - one narrow job per subclass
      - set `name` (kebab-case) and `description`
      - implement `run`, returning a list of Finding (possibly empty)
      - catch expected network errors internally and return an INFO Finding;
        do not let them escape and abort the whole run
      - never write to stdout/stderr
      - report a discovered password in full - the operator is authorized and
        needs to know which one worked - but never a session cookie or token
      - never report a check that could not run as a clean result: a silent
        `return []` reads as "the control held" and is the same defect as a
        false CRITICAL
    """

    name: str = "unnamed"
    description: str = ""
    requires_solver: bool = False
    opt_in: bool = False
    """Modules that submit real credentials are off unless explicitly enabled."""

    @abc.abstractmethod
    async def run(self, target: Target, client: HttpClient) -> list[Finding]:
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r}>"
