import typer
from pathlib import Path
from rich.console import Console
from rich import print as rprint

from src.parsers.requirements import parse_requirements
from src.scanners.osv import query_vulnerabilities
from src.scanners.code_scanner import scan_project

app = typer.Typer()
console = Console()

@app.command()
def scan(path: str):
    """Scan a project for vulnerable dependencies."""
    project_path = Path(path)
    
    if project_path.is_file():
        requirements_file = project_path
    else:
        requirements_file = project_path / "requirements.txt"
    
    if not requirements_file.exists():
        rprint(f"[red]Error:[/red] No requirements.txt found in {path}")
        raise typer.Exit(1)
    
    rprint(f"\n[bold]🔍 Scanning dependencies in {requirements_file}...[/bold]\n")
    
    dependencies = parse_requirements(requirements_file)
    
    if not dependencies:
        rprint("[yellow]No dependencies found.[/yellow]")
        raise typer.Exit(0)
    
    rprint(f"Found [bold]{len(dependencies)}[/bold] dependencies\n")
    
    vulnerable_count = 0
    for dep in dependencies:
        vulns = query_vulnerabilities(dep.name, dep.version)
        
        if vulns:
            vulnerable_count += 1
            version_str = dep.version or "any"
            rprint(f"[red]⚠️  {dep.name} {version_str}[/red]")
            
            for vuln in vulns:
                severity_color = get_severity_color(vuln.severity)
                severity_display = vuln.severity or "UNKNOWN"
                rprint(f"   └── [{severity_color}]{vuln.id}[/{severity_color}] ({severity_display})")
                rprint(f"       {truncate(vuln.summary, 80)}")
            
            project_dir = project_path if project_path.is_dir() else project_path.parent
            usages = scan_project(project_dir, dep.name)
            
            if usages:
                rprint(f"   [cyan]📍 Used in:[/cyan]")
                for usage in usages:
                    relative_path = Path(usage.file_path).relative_to(project_dir)
                    rprint(f"      - {relative_path}:{usage.line_number} → [dim]{usage.line_content}[/dim]")
            else:
                rprint(f"   [dim]📍 Not directly imported (may be transitive dependency)[/dim]")

            rprint()

    if vulnerable_count > 0:
        rprint(f"[bold red]Found {vulnerable_count} vulnerable dependencies[/bold red]")
        raise typer.Exit(1)
    else:
        rprint("[bold green]No vulnerabilities found![/bold green]")
        raise typer.Exit(0)

def get_severity_color(severity: str | None) -> str:
    """Return color based on severity."""
    if not severity:
        return "yellow"
    
    severity_upper = severity.upper()
    if "CRITICAL" in severity_upper or "HIGH" in severity_upper:
        return "red"
    elif "MEDIUM" in severity_upper or "MODERATE" in severity_upper:
        return "yellow"
    else:
        return "blue"

def truncate(text: str, max_length: int) -> str:
    """Truncate text to max length."""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."

if __name__ == "__main__":
    app()