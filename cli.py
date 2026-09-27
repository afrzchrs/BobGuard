#!/usr/bin/env python3
"""BobGuard CLI Frontend - Visual interface powered by Rich."""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

# Mengimpor backend resmi
try:
    from bobguard_backend import BobGuardBackend
except ImportError:
    print("[ERROR] Cannot import BobGuardBackend from bobguard_backend.py.")
    sys.exit(1)

console = Console()

ASCII_BANNER = r"""
 ____        _      ____                     _ 
| __ )  ___ | |__  / ___|_   _  __ _ _ __ __| |
|  _ \ / _ \| '_ \| |  _| | | |/ _` | '__/ _` |
| |_) | (_) | |_) | |_| | |_| | (_| | | | (_| |
|____/ \___/|_.__/ \____|\__,_|\__,_|_|  \__,_|
"""


def print_hero_banner() -> None:
    banner_text = Text(ASCII_BANNER, style="bold cyan")
    subtitle = Text(
        "Autonomous OWASP Security Triage & Remediation Engine\nPowered by IBM Bob 2.0",
        style="dim white",
    )
    console.print(Panel(banner_text, subtitle=subtitle, border_style="bright_blue"))


def render_triage_table(findings: List[Dict[str, Any]]) -> None:
    if not findings:
        console.print("\n[bold green]✓ Codebase Clean: No confirmed OWASP vulnerabilities detected![/bold green]\n")
        return

    table = Table(
        title="\n[bold yellow]🛡️  OWASP Top 10 Vulnerability Triage Report[/bold yellow]",
        show_lines=True,
        header_style="bold bright_white on blue",
    )
    table.add_column("No", justify="center", width=4)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Confidence", justify="center", width=12)
    table.add_column("OWASP Category", width=28)
    table.add_column("Vulnerability")
    table.add_column("File:Line", style="magenta")

    for idx, f in enumerate(findings, 1):
        sev = str(f.get("severity", "MEDIUM")).upper()
        if sev == "CRITICAL":
            sev_styled = "[bold white on red] CRITICAL [/bold white on red]"
        elif sev == "HIGH":
            sev_styled = "[bold red]HIGH[/bold red]"
        elif sev == "MEDIUM":
            sev_styled = "[bold yellow]MEDIUM[/bold yellow]"
        else:
            sev_styled = "[bold blue]LOW[/bold blue]"

        table.add_row(
            str(idx),
            sev_styled,
            str(f.get("confidence", "MEDIUM")),
            str(f.get("category", "General Security")),
            str(f.get("name", "Unknown Issue")),
            f"{Path(f.get('file', '')).name}:{f.get('line', '?')}",
        )

    console.print(table)


def display_remediation_proposal(finding: Dict[str, Any], proposal: Dict[str, Any]) -> None:
    details = (
        f"[bold red]Finding:[/bold red] {finding.get('name', 'N/A')}\n"
        f"[bold]Location:[/bold] {finding.get('file', 'N/A')} (Line {finding.get('line', '?')})\n"
        f"[bold]OWASP ID:[/bold] {finding.get('rule_id', 'N/A')} - {finding.get('category', 'N/A')}\n"
        f"[bold]Severity:[/bold] {finding.get('severity', 'MEDIUM')}\n"
        f"[bold green]Root Cause:[/bold green] {proposal.get('root_cause', 'N/A')}"
    )
    console.print(Panel(details, title="[bold]Remediation Proposal[/bold]", border_style="cyan"))

    old = str(proposal.get("old_snippet", finding.get("snippet", "")))
    new = str(proposal.get("replacement", ""))
    if old and new:
        diff = f"- {old}\n+ {new}"
        console.print(
            Panel(
                Syntax(diff, "diff", theme="monokai", line_numbers=False),
                title="[bold]Proposed Patch Diff[/bold]",
                border_style="yellow",
            )
        )


def print_validation(result: Dict[str, Any]) -> None:
    status = result.get("status", "UNKNOWN")

    if status == "FIXED & VERIFIED":
        console.print("\n[bold green]✓ FIXED & VERIFIED[/bold green]")
    elif status == "PATCH FAILED / ROLLED BACK":
        console.print("\n[bold red]✗ PATCH FAILED / ROLLED BACK[/bold red]")
    else:
        console.print(f"\n[yellow]Status: {status}[/yellow]")

    for key, label in (
        ("baseline", "Baseline tests"),
        ("syntax", "Targeted syntax validation"),
        ("tests", "Post-patch tests"),
        ("security_rescan", "Security re-scan"),
    ):
        val = result.get(key)
        if not val:
            continue

        passed = bool(val.get("passed"))
        icon = "✓" if passed else "✗"
        style = "green" if passed else "red"
        console.print(
            f"[{style}]{icon} {label}: {val.get('status')}[/{style}]"
        )

        # Tampilkan detail diagnosis terutama untuk syntax validation.
        # Backend dapat mengembalikan stdout/stderr gabungan pada "output".
        diagnostic = str(val.get("output") or "").strip()
        command = val.get("command")

        if not passed and diagnostic:
            title = f"{label} - stderr / diagnostic output"
            console.print(
                Panel(
                    Text(diagnostic),
                    title=title,
                    border_style="red" if key == "syntax" else "yellow",
                )
            )

        if not passed and command:
            console.print(
                f"[dim]Command: {command}[/dim]"
            )

        # Jika backend mengirim traceback terpisah, tampilkan utuh.
        tb = str(val.get("traceback") or "").strip()
        if tb:
            console.print(
                Panel(
                    Text(tb),
                    title=f"{label} - full traceback",
                    border_style="red",
                )
            )

    # Tampilkan detail patch jika pipeline gagal menerapkan perubahan.
    apply_message = str(result.get("apply_message") or "").strip()
    if apply_message:
        console.print(
            Panel(
                Text(apply_message),
                title="Patch application details",
                border_style="yellow",
            )
        )



def _print_full_traceback(exc: BaseException) -> None:
    """Display an unexpected CLI traceback in a readable Rich panel."""
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    console.print(
        Panel(
            Text(tb),
            title="Unexpected CLI traceback",
            border_style="red",
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BobGuard: OWASP Top 10 audit and verified remediation engine."
    )
    parser.add_argument(
        "action",
        choices=["run", "scan"],
        nargs="?",
        default="run",
        help="run = audit + remediation; scan = read-only audit",
    )
    parser.add_argument(
        "--dir",
        default="sample-app",
        help="Target workspace directory to audit (default: sample-app)",
    )
    args = parser.parse_args()

    print_hero_banner()

    # Early check target workspace
    target_path = Path(args.dir)
    if BobGuardBackend.is_directory_empty_or_no_code(target_path):
        msg = (
            f"[bold red]Workspace directory '[cyan]{target_path}[/cyan]' is empty or contains no supported code![/bold red]\n\n"
            "[bold yellow]👉 copy or pull your code to sample-app to let Bob do his audit job[/bold yellow]\n"
        )
        console.print(Panel(msg, title="[bold red]⚠️  Empty Target Workspace[/bold red]", border_style="red"))
        sys.exit(0)

    try:
        backend = BobGuardBackend(project_root=args.dir)
    except Exception as exc:
        console.print(f"[bold red]Initialization Error:[/bold red] {exc}")
        sys.exit(1)

    console.print(f"[dim green]✓ OWASP rules loaded: {backend.rules_path.name} ({len(backend.rules)} active rules)[/dim green]")
    console.print(f"[dim green]✓ Audit orchestrator loaded: {backend.audit_prompt_path.name}[/dim green]")
    console.print(f"[dim green]✓ Remediation protocol loaded: {backend.patch_prompt_path.name}[/dim green]\n")

    with console.status(f"[bold green]Scanning codebase in '{args.dir}' against OWASP rules..."):
        findings = backend.scan_entire_codebase(args.dir)

    render_triage_table(findings)

    if args.action == "scan" or not findings:
        return

    target = findings[0]

    try:
        with console.status("[bold green]Generating safe remediation proposal with IBM Bob..."):
            proposal = backend.generate_patch_with_bob(target)
        proposal["line"] = target.get("line")
    except Exception as exc:
        console.print(f"[bold red]Remediation generation failed:[/bold red] {exc}")
        return

    display_remediation_proposal(target, proposal)

    confirmed = Confirm.ask(
        f"[bold white]Authorize BobGuard to patch [cyan]{Path(target.get('file', '')).name}[/cyan] automatically?[/bold white]",
        default=False,
    )
    if not confirmed:
        console.print("[yellow]Remediation cancelled by user.[/yellow]")
        return

    try:
        with console.status("[bold green]Applying patch and running verification pipeline..."):
            result = backend.remediate_and_verify(target)
    except Exception as exc:
        console.print(f"[bold red]Remediation pipeline failed:[/bold red] {exc}")
        return

    try:
        print_validation(result)
    except Exception as exc:
        _print_full_traceback(exc)
        raise


if __name__ == "__main__":
    main()