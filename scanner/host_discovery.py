import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor

def ping_host(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", "-w", "1000", ip]
    try:
        return subprocess.run(command, stdout=subprocess.DEVNULL).returncode == 0
    except:
        return False

def discover_hosts(network_prefix):
    live_hosts = []
    ips = [f"{network_prefix}{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(ping_host, ips))
    for i, alive in enumerate(results, start=1):
        if alive:
            live_hosts.append(f"{network_prefix}{i}")
    return live_hosts