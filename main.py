import asyncio
import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.layout import Layout

from scanner.port_scanner import scan_ports_async
from scanner.banner import grab_banner
from scanner.host_discovery import discover_hosts_async
from vuln.analyzer import analyze
from output.writer import save_json_report, save_txt_report
from utils.cli_theme import print_logo, console, print_info, print_success, print_warning, THEME

async def run_scan(target, ports, network_scan, output_file, save_txt):
    print_logo()
    
    targets = []
    if network_scan:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task(f"Discovering live hosts in {target}...", total=254)
            targets = await discover_hosts_async(target)
            progress.update(task, completed=254, description=f"Found {len(targets)} live hosts")
    else:
        targets = [target]

    final_results = []
    
    # Create the results table
    table = Table(title="Vortex Scan Results", show_header=True, header_style="bold magenta")
    table.add_column("Host", style="cyan")
    table.add_column("Open Ports", style="green")
    table.add_column("Findings", style="yellow")
    table.add_column("Severity", justify="center")

    with Live(table, console=console, refresh_per_second=4):
        for host in targets:
            print_info(f"Scanning {host}...")
            open_ports = await scan_ports_async(host, ports)
            banners = {}
            
            for port in open_ports:
                banner = grab_banner(host, port)
                banners[port] = banner if banner else ""
            
            host_findings = analyze(host, open_ports, banners)
            
            # Format findings for table
            finding_text = "\n".join([f["issue"] for f in host_findings]) if host_findings else "None"
            severity_text = ""
            if host_findings:
                high_count = sum(1 for f in host_findings if f["severity"] == "HIGH")
                if high_count > 0:
                    severity_text = f"[bold red]HIGH ({high_count})[/]"
                else:
                    severity_text = "[bold yellow]MEDIUM[/]"
            else:
                severity_text = "[dim green]SECURE[/]"

            table.add_row(
                host,
                ", ".join(map(str, open_ports)) if open_ports else "None",
                finding_text,
                severity_text
            )

            final_results.append({
                "scan_target": host,
                "open_ports": open_ports,
                "banners": banners,
                "findings": host_findings
            })

    report = {
        "scan_tool": "Vortex",
        "results": final_results
    }
    
    save_json_report(report, output_file)
    if save_txt:
        save_txt_report(report, output_file.replace(".json", ".txt"))
    
    console.print(Panel(f"Scan completed. Reports saved: [bold white]{output_file}[/]", style="green", title="Success"))

def main():
    parser = argparse.ArgumentParser(description="Vortex - High Performance Network Scanner")
    parser.add_argument("target", nargs="?", help="Target IP or Network prefix (e.g. 192.168.1.)")
    parser.add_argument("-p", "--ports", help="Comma separated ports to scan", default=None)
    parser.add_argument("-n", "--network", action="store_true", help="Perform network discovery scan")
    parser.add_argument("-o", "--output", help="Output JSON file", default="vortex_report.json")
    parser.add_argument("-t", "--txt", action="store_true", help="Save TXT report as well")
    
    args = parser.parse_args()

    if not args.target:
        print_logo()
        console.print("\n[bold cyan]Interactive Mode[/]")
        try:
            target = console.input("[bold white]Enter target (IP or Network): [/]").strip()
            if not target:
                print_error("Target is required.")
                return
            
            network_scan = console.input("[bold white]Scan entire network? (y/N): [/]").strip().lower() == "y"
            ports_input = console.input("[bold white]Enter ports (default: common ports): [/]").strip()
            ports = list(map(int, ports_input.split(","))) if ports_input else [21,22,23,25,53,80,110,139,143,443,445,3389]
            output_file = console.input("[bold white]Output JSON file (vortex_report.json): [/]").strip() or "vortex_report.json"
            save_txt = console.input("[bold white]Save TXT report? (y/N): [/]").strip().lower() == "y"
        except (KeyboardInterrupt, EOFError):
            return
    else:
        target = args.target
        network_scan = args.network
        ports = list(map(int, args.ports.split(","))) if args.ports else [21,22,23,25,53,80,110,139,143,443,445,3389]
        output_file = args.output
        save_txt = args.txt

    asyncio.run(run_scan(target, ports, network_scan, output_file, save_txt))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan aborted by user.[/]")
        sys.exit(0)