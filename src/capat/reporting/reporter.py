from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from typing import TextIO

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from capat.core.result import Finding
from capat.corpus import BenchReport

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

FORMATS = ("table", "json", "markdown")


class Reporter:
    """Renders findings to a chosen output format.

    Markdown exists because the point of this tool is usually to be shown to
    someone who has to decide whether to keep the CAPTCHA. That audience reads
    a document, not a terminal.
    """

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream or sys.stdout
        self._console = Console(file=self._stream)

    def render(self, findings: Sequence[Finding], fmt: str = "table") -> None:
        renderers = {"table": self._table, "json": self._json, "markdown": self._markdown}
        try:
            renderer = renderers[fmt]
        except KeyError:
            raise ValueError(f"unknown format: {fmt!r}") from None
        renderer(findings)

    def _json(self, findings: Sequence[Finding]) -> None:
        json.dump([f.to_dict() for f in findings], self._stream, indent=2)
        self._stream.write("\n")

    def _table(self, findings: Sequence[Finding]) -> None:
        if not findings:
            self._console.print("[dim]no findings[/dim]")
            return
        table = Table(title="capat findings")
        for col in ("severity", "module", "title"):
            table.add_column(col, overflow="fold")
        for f in self._sorted(findings):
            sev = str(f.severity)
            # Finding text is data, not markup. A remediation naming an
            # extra - pip install "capat[ddddocr]" - had its one useful
            # token eaten by rich as an unknown style tag.
            table.add_row(
                f"[{_SEVERITY_STYLE.get(sev, '')}]{sev}[/]",
                escape(f.module),
                escape(f.title),
            )
        self._console.print(table)

        # Every finding's detail, not just the severe ones. An INFO or LOW
        # finding is usually where this tool qualifies its own result - "4
        # responses matched none of the criteria", "this measures the engine,
        # not the target" - and a severity threshold hid exactly that, leaving
        # the default view stating a bare conclusion that json and markdown
        # both qualified. The table is the summary; this is the report.
        for f in self._sorted(findings):
            if not f.description and not f.remediation:
                continue
            self._console.print(
                f"\n[bold]{escape(f.title)}[/bold]  [dim]({escape(f.module)})[/dim]"
            )
            if f.description:
                self._console.print(f"  {escape(f.description)}")
            if f.remediation:
                self._console.print(f"  [green]fix:[/green] {escape(f.remediation)}")

    def _markdown(self, findings: Sequence[Finding]) -> None:
        w = self._stream.write
        w("# CAPTCHA assessment\n\n")
        if not findings:
            w("No findings.\n")
            return
        w("| Severity | Check | Finding |\n|---|---|---|\n")
        for f in self._sorted(findings):
            w(f"| {f.severity} | `{f.module}` | {f.title} |\n")
        w("\n")
        for f in self._sorted(findings):
            w(f"## {f.title}\n\n")
            w(f"**Severity:** {f.severity} &nbsp;&nbsp; **Target:** {f.target}\n\n")
            if f.description:
                w(f"{f.description}\n\n")
            if f.remediation:
                w(f"**Recommendation.** {f.remediation}\n\n")
            if f.evidence:
                w("```json\n" + json.dumps(f.evidence, indent=2, default=str) + "\n```\n\n")

    @staticmethod
    def _sorted(findings: Sequence[Finding]) -> list[Finding]:
        return sorted(findings, key=lambda f: f.severity, reverse=True)


class BenchReporter:
    """Renders an offline corpus benchmark."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream or sys.stdout
        self._console = Console(file=self._stream)

    def render(self, report: BenchReport, fmt: str = "table", show_all: bool = False) -> None:
        if fmt == "json":
            json.dump(report.to_dict(), self._stream, indent=2)
            self._stream.write("\n")
            return
        if fmt == "markdown":
            self._markdown(report)
            return
        self._table(report, show_all)

    def _table(self, report: BenchReport, show_all: bool) -> None:
        # Without --show-all the correct rows are dropped, so every `match`
        # cell reads "no" under a headline accuracy that is not zero. The
        # title has to say the table is the misses, or it reads as the whole
        # corpus contradicting the summary line below it - and a column that
        # can only hold one value is not worth its width.
        rows = [a for a in report.attempts if show_all or not a.correct]
        table = Table(title=f"capat: {report.engine} vs. labeled corpus")
        table.add_column("label")
        table.add_column("predicted")
        if show_all:
            table.add_column("match")
        table.add_column("conf", justify="right")
        table.add_column("sec", justify="right")

        for a in rows:
            cells = [
                escape(a.label),
                escape(a.predicted) if a.predicted else "[dim]-[/dim]",
            ]
            if show_all:
                cells.append("[green]yes[/green]" if a.correct else "[red]no[/red]")
            cells += [f"{a.confidence:.2f}", f"{a.elapsed:.2f}"]
            table.add_row(*cells)
        if table.row_count:
            self._console.print(table)
            if not show_all:
                # Printed under the table rather than in its title: the title
                # is centred on the table's own width, which is narrow enough
                # here to wrap the sentence over three lines.
                self._console.print(
                    f"[dim]the {len(rows)} missed of {report.total}; "
                    f"--show-all lists every row[/dim]"
                )

        self._console.print(
            f"\n[bold]{report.solved}/{report.total} solved exactly[/bold] "
            f"= [bold]{report.accuracy:.1%}[/bold] accuracy   "
            f"(character similarity {report.character_accuracy:.1%})"
        )
        if report.attempts_per_hour:
            self._console.print(
                f"{report.mean_latency:.2f}s mean per solve  ->  "
                f"~{report.attempts_per_hour:,.0f} correct solves/hour, single process"
            )

    def _markdown(self, report: BenchReport) -> None:
        w = self._stream.write
        w(f"# CAPTCHA solve-rate benchmark ({report.engine})\n\n")
        w(f"- **Accuracy:** {report.accuracy:.1%} ({report.solved}/{report.total} exact)\n")
        w(f"- **Character similarity:** {report.character_accuracy:.1%}\n")
        w(f"- **Mean time per solve:** {report.mean_latency:.2f}s\n")
        if report.attempts_per_hour:
            w(
                f"- **Throughput:** ~{report.attempts_per_hour:,.0f} correct solves/hour, "
                "one process, commodity hardware\n"
            )
        w("\n")
        w("| Label | Predicted | Correct |\n|---|---|---|\n")
        for a in report.attempts:
            w(f"| `{a.label}` | `{a.predicted}` | {'yes' if a.correct else 'no'} |\n")
        w("\n")
