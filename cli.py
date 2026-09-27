#!/usr/bin/env python3
"""BobGuard CLI Frontend - audit, remediation, verification and rollback."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

try:
    from bobguard_backend import BobGuardBackend
except ImportError:
    try:
        from bobguard_backend import BobGuardBackend
    except ImportError:
        print("[ERROR] Cannot import BobGuardBackend. Check bobguard_backend_3.py or bobguard_backend.py.")
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
        console.print(
            "\n[bold green]✓ No confirmed OWASP Top 10:2025 vulnerabilities detected.[/bold green]\n"
        )
        return

    table = Table(
        title="\n[bold yellow]🛡 OWASP Top 10:2025 Vulnerability Triage[/bold yellow]",
        show_lines=True,
        header_style="bold bright_white on blue",
    )
    table.add_column("No", justify="center", width=4)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Confidence", justify="center", width=12)
    table.add_column("OWASP Category", width=28)
    table.add_column("Vulnerability")
    table.add_column("File:Line", style="magenta")

    for idx, finding in enumerate(findings, 1):
        severity = str(finding.get("severity", "MEDIUM")).upper()
        if severity == "CRITICAL":
            sev = "[bold white on red] CRITICAL [/bold white on red]"
        elif severity == "HIGH":
            sev = "[bold red]HIGH[/bold red]"
        elif severity == "MEDIUM":
            sev = "[bold yellow]MEDIUM[/bold yellow]"
        else:
            sev = "[bold blue]LOW[/bold blue]"

        table.add_row(
            str(idx),
            sev,
            str(finding.get("confidence", "MEDIUM")),
            str(finding.get("category", "General Security")),
            str(finding.get("name", "Unknown Issue")),
            f"{finding.get('file', 'unknown')}:{finding.get('line', '?')}",
        )

    console.print(table)


def display_remediation_proposal(finding: Dict[str, Any], proposal: Dict[str, Any]) -> None:
    details = (
        f"[bold red]Finding:[/bold red] {finding.get('name', 'N/A')}\n"
        f"[bold]Location:[/bold] {finding.get('file', 'N/A')} (Line {finding.get('line', '?')})\n"
        f"[bold]OWASP:[/bold] {finding.get('rule_id', 'N/A')} - {finding.get('category', 'N/A')}\n"
        f"[bold]Severity:[/bold] {finding.get('severity', 'MEDIUM')}\n"
        f"[bold]Confidence:[/bold] {finding.get('confidence', 'MEDIUM')}\n"
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
        value = result.get(key)
        if not value:
            continue
        passed = value.get("passed")
        icon = "✓" if passed else "✗"
        style = "green" if passed else "red"
        console.print(f"[{style}]{icon} {label}: {value.get('status')}[/{style}]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BobGuard: OWASP Top 10:2025 audit + verified remediation"
    )
    parser.add_argument(
        "action",
        choices=["run", "scan"],
        nargs="?",
        default="run",
        help="run = audit + interactive remediation; scan = read-only audit",
    )
    parser.add_argument(
        "--dir",
        default="sample-app",
        help="Target repository directory (default: sample-app)",
    )
    args = parser.parse_args()

    print_hero_banner()

    # --- EARLY GUARD CHECK: SAMPLE-APP VALIDATION ---
    target_path = Path(args.dir)
    # Tentukan folder yang dicek (sample-app atau target khusus)
    check_dir = target_path if "sample-app" in str(target_path) else Path("sample-app")

    if BobGuardBackend.is_directory_empty_or_no_code(check_dir):
        message = (
            f"[bold red]Workspace directory '[cyan]{check_dir}[/cyan]' is empty or contains no supported code files![/bold red]\n\n"
            "[bold yellow]copy or pull your code to sample-app to let Bob do his audit job[/bold yellow]\n\n"
            "[dim]Quick example commands:[/dim]\n"
            f"  • [cyan]cp -r /path/to/your/source/* {check_dir}/[/cyan]\n"
            f"  • [cyan]git clone <repo-url> {check_dir}[/cyan]\n"
        )
        console.print(
            Panel(
                message,
                title="[bold red]Empty Target Workspace[/bold red]",
                border_style="red",
            )
        )
        sys.exit(0)

    # Inisialisasi Backend setelah workspace terbukti memiliki file kode
    try:
        backend = BobGuardBackend(args.dir)
    except Exception as exc:
        console.print(f"[bold red]Initialization Error:[/bold red] {exc}")
        sys.exit(1)

    console.print(
        f"[dim green]✓ OWASP rules loaded: {backend.rules_path} ({len(backend.rules)} categories)[/dim green]"
    )
    console.print(
        f"[dim green]✓ Audit orchestrator loaded: {backend.audit_prompt_path}[/dim green]"
    )
    console.print(
        f"[dim green]✓ Remediation protocol loaded: {backend.patch_prompt_path}[/dim green]\n"
    )

    with console.status(
        "[bold green]Scanning codebase against OWASP Top 10:2025..."
    ):
        findings = backend.scan_entire_codebase(args.dir)

    render_triage_table(findings)

    if args.action == "scan" or not findings:
        return

    target = findings[0]

    try:
        with console.status("[bold green]Generating safe remediation proposal..."):
            proposal = backend.generate_patch_with_bob(target)
        proposal["line"] = target.get("line")
    except Exception as exc:
        console.print(f"[bold red]Remediation generation failed:[/bold red] {exc}")
        return

    display_remediation_proposal(target, proposal)

    confirmed = Confirm.ask(
        f"[bold white]Authorize BobGuard to patch {target.get('file')} automatically?[/bold white]",
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

    print_validation(result)

    security = result.get("security_rescan", {})
    remaining = security.get("remaining_findings", []) if security else []
    if remaining:
        console.print("[yellow]Remaining matching findings:[/yellow]")
        for item in remaining:
            console.print(
                f"  • {item.get('rule_id')} {item.get('name')} "
                f"at {item.get('file')}:{item.get('line')}"
            )


if __name__ == "__main__":
    main()