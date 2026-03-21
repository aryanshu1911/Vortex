from scanner.port_scanner import scan_ports
from scanner.banner import grab_banner
from scanner.host_discovery import discover_hosts
from vuln.analyzer import analyze
from output.writer import save_json_report, save_txt_report
from utils.cli_theme import print_logo, spinner, GREEN, RED, YELLOW, MAGENTA, RESET

def prompt_user():
    print("\nEnter target:")
    print(" - Single IP → 192.168.1.100")
    print(" - Network   → 192.168.1. (or 192.168.1.0/24)")
    target = input("> ").strip()

    print("\nScan entire network? (y/N):")
    network_scan = input("> ").strip().lower() == "y"

    # ✅ FIX: normalize target
    if network_scan:
        if "/" in target:
            network_target = target
        elif target.endswith("."):
            network_target = target + "0/24"
        else:
            # auto convert IP → network
            parts = target.split(".")
            network_target = ".".join(parts[:3]) + ".0/24"
    else:
        network_target = target

    print("\nEnter ports (default: 21,22,23,25,53,80,110,139,143,443,445,3389):")
    ports_input = input("> ").strip()
    ports = list(map(int, ports_input.split(","))) if ports_input else [21,22,23,25,53,80,110,139,143,443,445,3389]

    print("\nEnter output JSON file (default: vortex_report.json):")
    output_file = input("> ").strip() or "vortex_report.json"

    print("\nSave TXT report? (y/N):")
    save_txt = input("> ").strip().lower() == "y"

    return network_target, ports, network_scan, output_file, save_txt


if __name__ == "__main__":
    print_logo()
    target, ports, network_scan, output_file, save_txt = prompt_user()
    targets = []

    if network_scan:
        spinner(f"Discovering live hosts in {target}", duration=3)
        targets = discover_hosts(target)
        print(f"{MAGENTA}[*] Found {len(targets)} live hosts: {targets}{RESET}")
    else:
        targets = [target]

    final_report = []

    for host in targets:
        print(f"\n{YELLOW}[*] Scanning {host}...{RESET}")
        open_ports = scan_ports(host, ports)
        banners = {}

        for port in open_ports:
            banner = grab_banner(host, port)
            banners[port] = banner if banner else ""
            print(f"{GREEN}[+] {host}:{port} → {banner or '(no banner)'}{RESET}")

        findings = analyze(host, open_ports, banners)

        for f in findings:
            color = RED if f["severity"] == "HIGH" else YELLOW
            print(f"{color}[!] {f['ip']}:{f['port']} → {f['issue']} ({f['severity']}){RESET}")

        final_report.append({
            "scan_target": host,
            "open_ports": open_ports,
            "banners": banners,
            "findings": findings
        })

    report = {
        "scan_tool": "Vortex",
        "results": final_report
    }
    save_json_report(report, output_file)
    if save_txt:
        save_txt_report(report, output_file.replace(".json", ".txt"))

    print(f"{MAGENTA}\n[✔] Vortex scan completed. Reports saved.{RESET}")