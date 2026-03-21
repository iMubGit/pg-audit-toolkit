import typer
import json
from datetime import datetime
from rich.console import Console
from pg_audit_toolkit.connection import get_connection
from pg_audit_toolkit.rules import RULES

app = typer.Typer(
    help="pg-audit-toolkit: Security & Compliance Auditor for PostgreSQL databases",
    no_args_is_help=True
)
console = Console()


@app.command()
def scan(
    db_url: str = typer.Argument(..., help="PostgreSQL connection URL"),
    json_output: bool = typer.Option(False, "--json", help="Output results in raw JSON format")
):
    """Audit a PostgreSQL database for security & compliance issues."""
    conn = None
    try:
        conn = get_connection(db_url)
        findings = []

        for rule in RULES:
            findings.extend(rule(conn))

        report = {
            "scan_time": datetime.utcnow().isoformat(),
            "total_findings": len(findings),
            "summary": {
                "critical": len([f for f in findings if f.risk == "CRITICAL"]),
                "high": len([f for f in findings if f.risk == "HIGH"]),
                "medium": len([f for f in findings if f.risk == "MEDIUM"]),
                "low": len([f for f in findings if f.risk == "LOW"]),
            },
            "findings": [f.model_dump() for f in findings]
        }

        if json_output:
            print(json.dumps(report, indent=2))
        else:
            console.print("\n[bold green]Postgres Audit Toolkit Scan Complete[/bold green]\n")

            if not findings:
                console.print("[bold blue]No issues found. Your database looks clean.[/bold blue]")
            else:
                for f in findings:
                    console.print(
                        f"[bold red]{f.risk.value}[/bold red] {f.issue}\n"
                        f"  → [yellow]Detail:[/yellow] {f.description}\n"
                        f"  → [cyan]Control:[/cyan] {f.control}\n"
                    )
                console.print(f"[bold]Total Findings:[/bold] {len(findings)}\n")

    except Exception as e:
        console.print(f"[bold red]ERROR:[/bold red] {str(e)}")
        raise typer.Exit(code=1)

    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    app()