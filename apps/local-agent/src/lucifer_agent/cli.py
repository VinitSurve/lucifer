import click
from rich.console import Console
from rich.table import Table
from .config import AgentConfig
from .sysinfo import get_system_metrics
from .ollama_client import OllamaClient
from .client import AgentDaemon

console = Console()

@click.group()
def main():
    """Project Lucifer - Local macOS Agent CLI."""
    pass

@main.command()
def status():
    """Display local system metrics and Ollama status."""
    metrics = get_system_metrics()
    ollama = OllamaClient()
    ollama_info = ollama.check_health()

    table = Table(title="Lucifer Local Agent Status")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Operating System", f"{metrics['os']} {metrics['platform_version']} ({metrics['arch']})")
    table.add_row("Python Version", metrics["python_version"])
    table.add_row("CPU Usage", f"{metrics['cpu_percent']}%")
    table.add_row("RAM Usage", f"{metrics['ram_used_percent']}% of {metrics['ram_total_gb']} GB")
    table.add_row("Disk Free", f"{metrics['disk_free_gb']} GB (of {metrics['disk_total_gb']} GB)")

    ol_status = "[bold green]Online[/]" if ollama_info["running"] else "[bold red]Offline[/]"
    table.add_row("Local Ollama", ol_status)
    if ollama_info["running"]:
        models_str = ", ".join(ollama_info["models"]) if ollama_info["models"] else "None pulled"
        table.add_row("Ollama Models", models_str)

    console.print(table)

@main.command()
def doctor():
    """Run diagnostics on local agent prerequisites and connections."""
    console.print("[bold cyan]Running Lucifer Agent Diagnostics...[/bold cyan]")
    metrics = get_system_metrics()
    ollama = OllamaClient()
    ollama_info = ollama.check_health()

    console.print(f"✅ Python Runtime: {metrics['python_version']} (Compatible)")
    console.print(f"✅ Disk Space: {metrics['disk_free_gb']} GB free")

    if ollama_info["running"]:
        console.print(f"✅ Local Ollama Daemon: Running ({len(ollama_info['models'])} models available)")
    else:
        console.print(f"⚠️ Local Ollama Daemon: Not responding on 127.0.0.1:11434 (run 'ollama serve' to start)")

    config = AgentConfig()
    console.print(f"ℹ️ Cloud Endpoint: {config.cloud_url}")
    console.print(f"ℹ️ Allowed Execution Directories: {len(config.allowed_directories)} paths configured")

@main.command()
@click.option("--cloud-url", help="Override Cloudflare Worker URL")
def run(cloud_url):
    """Start the local agent outbound polling daemon."""
    config = AgentConfig()
    if cloud_url:
        config.cloud_url = cloud_url

    console.print(f"[bold green]Starting Lucifer Agent daemon...[/bold green]")
    console.print(f"Device ID: [cyan]{config.device_id}[/cyan]")
    console.print(f"Connecting outbound to: [cyan]{config.cloud_url}[/cyan]")

    daemon = AgentDaemon(config)
    try:
        daemon.run_loop()
    except KeyboardInterrupt:
        console.print("[yellow]Agent daemon stopped by user.[/yellow]")

if __name__ == "__main__":
    main()
