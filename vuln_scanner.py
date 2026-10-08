#!/usr/bin/env python3
"""
AI-Vuln-Scanner — Interactive & CLI Entry Point
Backward-compatible wrapper supporting legacy interactive workflow
and delegating to the upgraded asynchronous evidence-grounded security engine.
"""

import sys
import asyncio
from backend.cli import main as cli_main
from backend.core.scanner import run_scan
from backend.utils.logger import logger
from rich.console import Console

console = Console()

def interactive_mode():
    console.print("[bold cyan]╔═══════════════════════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║     AI-Powered Web Application Vulnerability Scanner      ║[/bold cyan]")
    console.print("[bold cyan]╚═══════════════════════════════════════════════════════════╝[/bold cyan]")
    target_url = input("Enter the target URL: ").strip()
    if not target_url:
        console.print("[red]Target URL cannot be empty.[/red]")
        sys.exit(1)

    profile = input("Select scan profile [quick, standard, deep, passive, api, full] (default: standard): ").strip() or "standard"

    console.print(f"\n[bold green][*] Launching {profile.upper()} scan against: {target_url}...[/bold green]\n")

    scan = asyncio.run(run_scan(target_url=target_url, profile=profile))

    console.print(f"\n[bold]Scan ID:[/bold] {scan.id}")
    console.print(f"[bold]Security Posture Score:[/bold] {scan.summary.security_score} / 100")
    console.print(f"[bold]Total Findings:[/bold] {scan.summary.total_findings}\n")

    for f in scan.findings:
        sev_color = "red" if f.severity in ("CRITICAL", "HIGH") else "yellow"
        console.print(f"[{sev_color}][!] [{f.severity}] {f.title}[/{sev_color}]")
        console.print(f"    Target: {f.target} | Param: {f.parameter or 'N/A'}")
        console.print(f"    Confidence: {f.confidence}% ({f.validation_status}) | Risk: {f.risk_score}/10")
        if f.ai_explanation:
            console.print(f"    Why: {f.ai_explanation.get('why_detected', '')[:120]}...")
        console.print()

    if not scan.findings:
        console.print("[green][+] No vulnerabilities detected with this scan profile.[/green]")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli_main()
    else:
        interactive_mode()
