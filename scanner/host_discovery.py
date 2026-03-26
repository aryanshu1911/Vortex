import asyncio
import platform

async def ping_host(ip):
    """
    Asynchronously ping a host.
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    # -w 1000 is 1 second timeout on Windows
    command = ["ping", param, "1", "-w", "1000", ip]
    
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await proc.wait()
        return ip if proc.returncode == 0 else None
    except Exception:
        return None

async def discover_hosts_async(target, max_concurrent=50):
    """
    Discover live hosts in a network concurrently.
    Correctly handles CIDR notation or raw IP/prefix.
    """
    if "/" in target:
        # Simple CIDR handling for /24
        network_prefix = ".".join(target.split(".")[:3]) + "."
    elif target.count(".") == 3:
        # Full IP provided, strip last octet
        network_prefix = ".".join(target.split(".")[:3]) + "."
    elif target.count(".") == 2 and target.endswith("."):
        # Already a prefix
        network_prefix = target
    else:
        # Fallback
        network_prefix = target if target.endswith(".") else target + "."
        
    ips = [f"{network_prefix}{i}" for i in range(1, 255)]
    semaphore = asyncio.Semaphore(max_concurrent)

    async def sem_ping(ip):
        async with semaphore:
            return await ping_host(ip)

    tasks = [sem_ping(ip) for ip in ips]
    results = await asyncio.gather(*tasks)
    return [ip for ip in results if ip is not None]

# For backward compatibility
def discover_hosts(network_prefix):
    return asyncio.run(discover_hosts_async(network_prefix))