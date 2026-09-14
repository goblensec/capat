from __future__ import annotations

from dataclasses import dataclass

DEFAULT_USER_AGENT = "capat/0.1 (+https://github.com/goblensec/capat)"


@dataclass(slots=True)
class Config:
    """Every runtime knob in one place. No behavior lives here."""

    concurrency: int = 5
    """Maximum number of (module, target) checks in flight at once."""

    requests_per_second: float = 2.0
    """Global cap on outbound request rate. Deliberately low: every request
    this tool makes lands on an authentication endpoint."""

    timeout: float = 15.0
    """Per-request connect+read timeout, in seconds."""

    retries: int = 2
    """Retry attempts for transient transport/timeout errors."""

    user_agent: str = DEFAULT_USER_AGENT
    """Honest identifier. Do not spoof a browser by default."""

    verify_tls: bool = True
    follow_redirects: bool = True

    proxy: str | None = None
    """Upstream proxy, so operators can route the run through Burp/ZAP."""

    samples: int = 25
    """CAPTCHAs fetched and solved per solve-rate measurement."""

    lockout_threshold: int = 4
    """Auth failures against one identity before the credential audit drops
    it. Locking out a real account during a test is an incident, so this sits
    one below the commonest policy (5) rather than level with it."""

    ignore_lockout: bool = False

    def __post_init__(self) -> None:
        if self.concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        if self.requests_per_second <= 0:
            raise ValueError("requests_per_second must be > 0")
        if self.samples < 1:
            raise ValueError("samples must be >= 1")
        if self.lockout_threshold < 1:
            raise ValueError("lockout_threshold must be >= 1")
