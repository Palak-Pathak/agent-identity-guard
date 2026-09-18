"""Click + Rich command line interface for agent-identity-guard.

Usage:
    agent-identity-guard audit --path <repo_path>
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .agent_audit import audit_agent_commits
from .errors import AgentGuardError
from .models import Finding, Rule, Severity
from .scanner import scan_workflows

__all__ = ["audit", "main"]

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.MEDIUM: "bold magenta",
    Severity.LOW: "bold cyan",
    Severity.INFO: "dim",
}

console = Console()
error_console = Console(stderr=True)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="agent-identity-guard")
def main() -> None:
    """Audit a repository for agent/bot identity and CI supply-chain risk."""


@main.command()
@click.option(
    "--path",
    "repo_path",
    type=click.Path(exists=True, file_okay=False, resolve_path=True, path_type=Path),
    default=".",
    show_default="current directory",
    help="Path to the repository root to audit.",
)
def audit(repo_path: Path) -> None:
    """Run the workflow and git-history audits against REPO_PATH.

    Exits with status 1 when at least one CRITICAL finding is reported.
    """
    findings: list[Finding] = []
    warnings: list[str] = []

    try:
        findings.extend(scan_workflows(repo_path))
    except AgentGuardError as exc:
        warnings.append(f"Workflow audit skipped: {exc}")

    try:
        findings.extend(audit_agent_commits(repo_path))
    except AgentGuardError as exc:
        warnings.append(f"Git history audit skipped: {exc}")

    findings.sort(key=lambda finding: (finding.severity.rank, finding.file, finding.rule.id))

    _render_report(repo_path, findings)
    for warning in warnings:
        error_console.print(Text("warning: ", style="yellow").append(warning))

    if any(finding.severity is Severity.CRITICAL for finding in findings):
        raise SystemExit(1)


def _render_report(repo_path: Path, findings: list[Finding]) -> None:
    console.print()
    console.print(f"[bold]agent-identity-guard[/bold] [dim]v{__version__}[/dim]")
    console.print(Text("Auditing ", style="").append(str(repo_path), style="cyan"))

    if not findings:
        console.print(
            Panel(
                "[bold green]No risk findings detected.[/bold green]",
                border_style="green",
                expand=False,
            )
        )
        return

    console.print(_findings_table(findings))
    console.print(_severity_summary(findings))
    _render_rule_reference(findings)


def _findings_table(findings: list[Finding]) -> Table:
    table = Table(
        title=f"Findings ({len(findings)})",
        title_style="bold",
        header_style="bold white",
        expand=True,
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("File", overflow="fold")
    table.add_column("Rule", overflow="fold")
    table.add_column("Details", overflow="fold")

    for finding in findings:
        style = SEVERITY_STYLES.get(finding.severity, "white")
        table.add_row(
            Text(finding.severity.value, style=style),
            Text(finding.file),
            Text(f"{finding.rule.id} · {finding.rule.title}"),
            Text(finding.message),
        )
    return table


def _severity_summary(findings: list[Finding]) -> Text:
    counts = Counter(finding.severity for finding in findings)
    summary = Text("Summary: ")
    first = True
    for severity in Severity:
        count = counts.get(severity, 0)
        if not count:
            continue
        if not first:
            summary.append("   ")
        summary.append(f"{severity.value} {count}", style=SEVERITY_STYLES[severity])
        first = False
    return summary


def _render_rule_reference(findings: list[Finding]) -> None:
    rules: dict[str, Rule] = {}
    for finding in findings:
        rules.setdefault(finding.rule.id, finding.rule)

    console.print()
    console.print("[bold]Rule reference[/bold]")
    for rule in sorted(rules.values(), key=lambda item: item.id):
        style = SEVERITY_STYLES.get(rule.severity, "white")
        heading = Text(f"  {rule.id} ", style=style)
        heading.append(rule.title, style="bold")
        console.print(heading)
        console.print(Text(f"      {rule.description}", style="dim"))
