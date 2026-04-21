"""
Command-line interface for the vulnerability scanner.
"""

import asyncio
import sys
from pathlib import Path
from typing import List, Optional

import click
from loguru import logger
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

from .core.models import ScannerOptions, Severity
from .core.template_loader import TemplateLoader
from .core.engine import ScanningEngine
from .reporting.exporters import ExporterFactory


# Setup logger
logger.remove()
logger.add(sys.stderr, format="<level>{level: <8}</level> | {message}")

console = Console()


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.pass_context
def cli(ctx, verbose):
    """Vulnerability scanner CLI."""
    if verbose:
        logger.enable("vuln_scanner")
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


@cli.command()
@click.option("--templates", "-t", multiple=True, required=True, help="Template path(s) or glob patterns")
@click.option("--url", "-u", multiple=True, required=True, help="Target URL(s)")
@click.option("--tags", multiple=True, help="Filter templates by tags (comma-separated)")
@click.option("--exclude-tags", multiple=True, help="Exclude templates by tags")
@click.option("--concurrency", "-c", type=int, default=10, help="Number of concurrent workers")
@click.option("--timeout", type=int, default=30, help="Request timeout in seconds")
@click.option("--retries", type=int, default=3, help="Number of retries")
@click.option("--rate-limit", type=float, default=0, help="Rate limit (requests per second)")
@click.option("--proxy", type=str, help="HTTP proxy URL")
@click.option("--output", "-o", type=str, help="Output file path")
@click.option("--format", "-f", type=click.Choice(["json", "jsonl", "csv", "html"]), default="json", help="Output format")
@click.option("--deduplicate", is_flag=True, help="Deduplicate results")
@click.pass_context
def scan(
    ctx,
    templates: tuple,
    url: tuple,
    tags: tuple,
    exclude_tags: tuple,
    concurrency: int,
    timeout: int,
    retries: int,
    rate_limit: float,
    proxy: Optional[str],
    output: Optional[str],
    format: str,
    deduplicate: bool,
):
    """Execute vulnerability scan."""
    
    asyncio.run(_scan_async(
        templates=list(templates),
        targets=list(url),
        tags=list(tags),
        exclude_tags=list(exclude_tags),
        concurrency=concurrency,
        timeout=timeout,
        retries=retries,
        rate_limit=rate_limit,
        proxy=proxy,
        output=output,
        output_format=format,
        deduplicate=deduplicate,
    ))


async def _scan_async(
    templates: List[str],
    targets: List[str],
    tags: List[str],
    exclude_tags: List[str],
    concurrency: int,
    timeout: int,
    retries: int,
    rate_limit: float,
    proxy: Optional[str],
    output: Optional[str],
    output_format: str,
    deduplicate: bool,
):
    """Execute scan asynchronously."""
    
    console.print("[bold blue]Vulnerability Scanner[/bold blue]\n")
    
    try:
        # Load templates
        with console.status("[bold green]Loading templates..."):
            loader = TemplateLoader(cache_size=1000)
            
            # Flatten tags and exclude_tags if they contain commas
            flattened_tags = []
            for tag_group in tags:
                flattened_tags.extend([t.strip() for t in tag_group.split(",")])
            
            flattened_exclude = []
            for tag_group in exclude_tags:
                flattened_exclude.extend([t.strip() for t in tag_group.split(",")])
            
            loaded_templates, errors = loader.load_templates(
                templates,
                include_tags=flattened_tags,
                exclude_tags=flattened_exclude,
            )
            
            if errors:
                console.print(f"[yellow]Warning: {len(errors)} template errors[/yellow]")
                for error in errors[:5]:
                    console.print(f"  {error}")
        
        if not loaded_templates:
            console.print("[red]No templates loaded[/red]")
            return
        
        console.print(f"[green]✓ Loaded {len(loaded_templates)} templates[/green]\n")
        
        # Create scanner options
        options = ScannerOptions(
            concurrency=concurrency,
            timeout=timeout,
            retries=retries,
            rate_limit=rate_limit,
            proxy=proxy,
            deduplicate=deduplicate,
        )
        
        # Create exporter
        exporter = ExporterFactory.create(output_format, output)
        
        # Initialize engine
        engine = ScanningEngine(options)
        await engine.initialize()
        
        try:
            # Display scan info
            table = Table(title="Scan Configuration")
            table.add_column("Parameter", style="cyan")
            table.add_column("Value", style="magenta")
            table.add_row("Targets", ", ".join(targets[:3]) + ("..." if len(targets) > 3 else ""))
            table.add_row("Templates", str(len(loaded_templates)))
            table.add_row("Concurrency", str(concurrency))
            table.add_row("Timeout", f"{timeout}s")
            table.add_row("Output Format", output_format)
            console.print(table)
            console.print()
            
            # Execute scan with progress bar
            results_found = 0
            
            with Progress() as progress:
                task = progress.add_task("[cyan]Scanning...", total=None)
                
                async for result in engine.scan(loaded_templates, targets):
                    exporter.add_result(result)
                    
                    if result.matched:
                        results_found += 1
                        # Update progress with found result
                        severity_color = {
                            Severity.CRITICAL: "red",
                            Severity.HIGH: "red",
                            Severity.MEDIUM: "yellow",
                            Severity.LOW: "green",
                            Severity.INFO: "blue",
                        }.get(result.severity, "white")
                        
                        progress.print(
                            f"[{severity_color}]✓ Found: {result.template_name} on {result.target}[/{severity_color}]"
                        )
            
            # Export results
            console.print(f"\n[green]✓ Scan completed[/green]")
            console.print(f"[green]✓ Found {results_found} vulnerabilities[/green]")
            
            # Export
            exporter.export()
            console.print(f"[green]✓ Results exported[/green]")
        
        finally:
            await engine.close()
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.exception("Scan failed")
        sys.exit(1)


@cli.command()
@click.argument("template_path", type=click.Path(exists=True))
def validate_template(template_path: str):
    """Validate a template file."""
    
    loader = TemplateLoader()
    
    try:
        template = loader.load_single(template_path)
        
        console.print("[green]✓ Template is valid[/green]\n")
        
        # Display template info
        table = Table(title="Template Info")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_row("ID", template.id)
        table.add_row("Name", template.info.name)
        table.add_row("Author", template.info.author or "N/A")
        table.add_row("Severity", template.info.severity.value if template.info.severity else "N/A")
        table.add_row("HTTP Requests", str(len(template.http)))
        table.add_row("DNS Requests", str(len(template.dns)))
        table.add_row("Network Requests", str(len(template.network)))
        
        console.print(table)
    
    except Exception as e:
        console.print(f"[red]✗ Template validation failed: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option("--templates", "-t", multiple=True, required=True, help="Template path(s) or glob patterns")
@click.option("--tags", multiple=True, help="Filter by tags")
def list_templates(templates: tuple, tags: tuple):
    """List available templates."""
    
    loader = TemplateLoader()
    
    # Flatten tags
    flattened_tags = []
    for tag_group in tags:
        flattened_tags.extend([t.strip() for t in tag_group.split(",")])
    
    loaded_templates, errors = loader.load_templates(
        list(templates),
        include_tags=flattened_tags,
    )
    
    if errors:
        console.print(f"[yellow]Errors loading templates:[/yellow]")
        for error in errors[:10]:
            console.print(f"  {error}")
        console.print()
    
    # Display templates
    table = Table(title=f"Templates ({len(loaded_templates)} total)")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="magenta")
    table.add_column("Author", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("Tags", style="blue")
    
    for template in sorted(loaded_templates, key=lambda t: t.id):
        severity_str = template.info.severity.value if template.info.severity else "N/A"
        tags_str = ", ".join(template.info.tags) if template.info.tags else "N/A"
        
        table.add_row(
            template.id,
            template.info.name,
            template.info.author or "N/A",
            severity_str,
            tags_str,
        )
    
    console.print(table)


def main():
    """Entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
