import typer
import json
from datetime import datetime
from rich.console import Console
from pg_audit_toolkit.connection import get_connection
from pg_audit_toolkit.rules import RULES

app = typer.Typer()
console = Console()

@app.command()
def scan(db_url: str = typer.Argument(..., help="PostgreSQL connection URL"), json_output: bool = typer.Option(False, "--json")):
    """Audit a PostgreSQL database for security & compliance issues."""
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
            console.print("[bold green]Postgres Audit Toolkit Scan Complete[/bold green]")
            for f in findings:
                console.print(
                    f"[bold red]{f.risk}[/bold red] {f.issue}\n"
                    f"  → {f.description}\n"
                    f"  → Control: {f.control}"
                )
        conn.close()
    except Exception as e:
        console.print(f"[bold red]ERROR:[/bold red] {str(e)}")
        raise typer.Exit(code=1)