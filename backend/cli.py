import argparse
import asyncio
import sys
import os
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from backend.models.scan import ScanConfig, ScanModel
from backend.core.orchestrator import ScanOrchestrator
from backend.core.comparison import ScanComparisonEngine
from backend.reports.sarif import SarifExporter
from backend.reports.html import HtmlReportExporter
from backend.reports.pdf import PdfReportExporter
from backend.api.storage import ScanStore

console = Console()

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║        AEGIS AI-VULN-SCANNER — SECURITY ENGINE v2.0       ║
    ║   Deterministic • Explainable AI • Attack Graph Analysis  ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")

async def cmd_scan(args):
    print_banner()
    console.print(f"[bold green][*] Target:[/bold green] {args.target}")
    console.print(f"[bold green][*] Profile:[/bold green] {args.profile.upper()}")

    config = ScanConfig(
        target_url=args.target,
        profile=args.profile,
        max_concurrency=args.concurrency,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        allow_local=not args.disallow_local
    )

    orchestrator = ScanOrchestrator(config)
    ScanStore.register_orchestrator(orchestrator.scan_id, orchestrator)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Initializing assessment engine...", total=100)

        def on_prog(model: ScanModel):
            progress.update(task, completed=model.progress, description=f"[cyan]{model.current_phase}")

        orchestrator.on_progress_update = on_prog
        scan = await orchestrator.execute()
        ScanStore.save(scan)

    if scan.status == "failed":
        console.print(f"[bold red][!] Scan Failed: {scan.error_message}[/bold red]")
        sys.exit(1)

    # Display Security Posture Score
    score = scan.summary.security_score
    score_color = "green" if score >= 80 else ("yellow" if score >= 60 else "red")
    console.print(Panel(
        f"[bold {score_color}]SECURITY POSTURE SCORE: {score} / 100[/bold {score_color}]\n"
        f"Critical: [red]{scan.summary.severity_breakdown.critical}[/red] | "
        f"High: [orange3]{scan.summary.severity_breakdown.high}[/orange3] | "
        f"Medium: [yellow]{scan.summary.severity_breakdown.medium}[/yellow] | "
        f"Low: [blue]{scan.summary.severity_breakdown.low}[/blue]",
        title="Assessment Summary",
        border_style=score_color
    ))

    # Findings Table
    if scan.findings:
        table = Table(title="Detected Vulnerabilities & Evidence", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="bold")
        table.add_column("Type")
        table.add_column("Target / Param")
        table.add_column("Confidence")
        table.add_column("Risk")
        table.add_column("OWASP / CWE")

        for f in scan.findings:
            sev_color = {
                "CRITICAL": "red",
                "HIGH": "orange3",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFORMATIONAL": "white"
            }.get(f.severity, "white")

            table.add_row(
                f"[{sev_color}]{f.severity}[/{sev_color}]",
                f.type,
                f"{f.parameter or f.target[:30]}",
                f"{f.confidence}% ({f.validation_status})",
                f"{f.risk_score}/10",
                f"{f.owasp.get('id', '')} | {f.cwe.get('id', '')}"
            )
        console.print(table)
    else:
        console.print("[bold green][+] No vulnerabilities detected with this scan profile.[/bold green]")

    # Export report if requested
    if args.format and args.output:
        fmt = args.format.lower()
        console.print(f"[*] Exporting report to {args.output} (format: {fmt.upper()})...")
        if fmt == "sarif":
            content = SarifExporter.export_json_string(scan)
            with open(args.output, "w") as f:
                f.write(content)
        elif fmt == "html":
            content = HtmlReportExporter.render(scan)
            with open(args.output, "w") as f:
                f.write(content)
        elif fmt == "pdf":
            pdf_bytes = PdfReportExporter.render_bytes(scan)
            with open(args.output, "wb") as f:
                f.write(pdf_bytes)
        else:
            with open(args.output, "w") as f:
                f.write(scan.model_dump_json(indent=2))
        console.print(f"[bold green][+] Report saved to {args.output}[/bold green]")

def cmd_list(args):
    scans = ScanStore.list_all()
    if not scans:
        console.print("[yellow]No historical scans found.[/yellow]")
        return

    table = Table(title="Historical Vulnerability Scans", show_header=True, header_style="bold cyan")
    table.add_column("Scan ID")
    table.add_column("Target")
    table.add_column("Profile")
    table.add_column("Status")
    table.add_column("Score")
    table.add_column("Findings")
    table.add_column("Date")

    for s in scans:
        table.add_row(
            s.id,
            s.target_url,
            s.profile,
            s.status,
            f"{s.summary.security_score}/100",
            str(s.summary.total_findings),
            s.created_at[:19]
        )
    console.print(table)

def cmd_findings(args):
    scan = ScanStore.get(args.scan_id)
    if not scan:
        console.print(f"[red]Scan '{args.scan_id}' not found.[/red]")
        sys.exit(1)

    for f in scan.findings:
        panel_content = (
            f"[bold]Target:[/bold] {f.target}\n"
            f"[bold]Parameter:[/bold] {f.parameter or 'N/A'}\n"
            f"[bold]Severity:[/bold] {f.severity} | [bold]Risk Score:[/bold] {f.risk_score}/10 | [bold]Confidence:[/bold] {f.confidence}%\n"
            f"[bold]Validation Status:[/bold] {f.validation_status}\n"
            f"[bold]OWASP:[/bold] {f.owasp.get('id')} ({f.owasp.get('name')})\n"
            f"[bold]CWE:[/bold] {f.cwe.get('id')} ({f.cwe.get('name')})\n\n"
            f"[bold cyan]WHY DETECTED:[/bold cyan]\n{f.ai_explanation.get('why_detected', 'N/A') if f.ai_explanation else 'N/A'}\n\n"
            f"[bold green]RECOMMENDED ACTION:[/bold green]\n{f.remediation.get('recommendation', 'N/A') if f.remediation else 'N/A'}"
        )
        console.print(Panel(panel_content, title=f"[{f.severity}] {f.title}", border_style="cyan"))

def cmd_compare(args):
    scan_a = ScanStore.get(args.scan_a)
    scan_b = ScanStore.get(args.scan_b)
    if not scan_a or not scan_b:
        console.print("[red]Both scan IDs must exist to perform comparison.[/red]")
        sys.exit(1)

    res = ScanComparisonEngine.compare(scan_a, scan_b)
    console.print(Panel(
        f"[bold]Scan A (Baseline):[/bold] {scan_a.id} ({scan_a.summary.security_score}/100)\n"
        f"[bold]Scan B (Current):[/bold] {scan_b.id} ({scan_b.summary.security_score}/100)\n"
        f"[bold]Score Delta:[/bold] [{'green' if res.score_improvement >= 0 else 'red'}]{res.score_improvement:+0.1f}[/]\n\n"
        f"NEW: [red]{res.summary['new']}[/red] | "
        f"FIXED: [green]{res.summary['fixed']}[/green] | "
        f"UNCHANGED: [yellow]{res.summary['unchanged']}[/yellow] | "
        f"REGRESSED: [orange3]{res.summary['regressed']}[/orange3]",
        title="Scan Comparison Result"
    ))

def cmd_export(args):
    scan = ScanStore.get(args.scan_id)
    if not scan:
        console.print(f"[red]Scan '{args.scan_id}' not found.[/red]")
        sys.exit(1)

    fmt = args.format.lower()
    if fmt == "sarif":
        content = SarifExporter.export_json_string(scan)
        with open(args.output, "w") as f:
            f.write(content)
    elif fmt == "html":
        content = HtmlReportExporter.render(scan)
        with open(args.output, "w") as f:
            f.write(content)
    elif fmt == "pdf":
        pdf_bytes = PdfReportExporter.render_bytes(scan)
        with open(args.output, "wb") as f:
            f.write(pdf_bytes)
    else:
        with open(args.output, "w") as f:
            f.write(scan.model_dump_json(indent=2))
    console.print(f"[bold green][+] Exported {fmt.upper()} report to {args.output}[/bold green]")

def main():
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="AEGIS AI-Vuln-Scanner — Professional AI-Powered Vulnerability Scanner CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Command: scan
    scan_p = subparsers.add_parser("scan", help="Execute vulnerability assessment scan")
    scan_p.add_argument("--target", "-t", required=True, help="Target URL (e.g. http://localhost:8000)")
    scan_p.add_argument("--profile", "-p", default="standard", choices=["quick", "standard", "deep", "passive", "api", "full"], help="Scan profile")
    scan_p.add_argument("--concurrency", "-c", type=int, default=5, help="Maximum concurrent requests")
    scan_p.add_argument("--rate-limit", "-r", type=float, default=15.0, help="Requests per second limit")
    scan_p.add_argument("--timeout", type=float, default=10.0, help="HTTP request timeout in seconds")
    scan_p.add_argument("--disallow-local", action="store_true", help="Reject private/loopback targets")
    scan_p.add_argument("--format", choices=["json", "sarif", "html", "pdf"], help="Export report format")
    scan_p.add_argument("--output", "-o", help="Filepath to write exported report")

    # Command: list
    subparsers.add_parser("list", help="List all executed scans")

    # Command: findings
    find_p = subparsers.add_parser("findings", help="Inspect detailed findings for a scan")
    find_p.add_argument("scan_id", help="Scan ID to inspect")

    # Command: compare
    comp_p = subparsers.add_parser("compare", help="Compare two scans (Scan A vs Scan B)")
    comp_p.add_argument("scan_a", help="Baseline scan ID")
    comp_p.add_argument("scan_b", help="Target scan ID")

    # Command: export
    exp_p = subparsers.add_parser("export", help="Export report for a scan")
    exp_p.add_argument("scan_id", help="Scan ID to export")
    exp_p.add_argument("--format", "-f", default="sarif", choices=["json", "sarif", "html", "pdf"], help="Export format")
    exp_p.add_argument("--output", "-o", required=True, help="Output destination file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        asyncio.run(cmd_scan(args))
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "findings":
        cmd_findings(args)
    elif args.command == "compare":
        cmd_compare(args)
    elif args.command == "export":
        cmd_export(args)

if __name__ == "__main__":
    main()
