import asyncio
import socket

async def scan_port(ip, port, timeout=0.5):
    """
    Asynchronously scan a single port.
    """
    try:
        # Use asyncio.open_connection for high-performance async I/O
        conn = asyncio.open_connection(ip, port)
        await asyncio.wait_for(conn, timeout=timeout)
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None

async def scan_ports_async(ip, ports, max_concurrent=200):
    """
    Scan a list of ports concurrently using a semaphore to limit concurrency.
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def sem_scan(port):
        async with semaphore:
            return await scan_port(ip, port)

    tasks = [sem_scan(port) for port in ports]
    results = await asyncio.gather(*tasks)
    return [port for port in results if port is not None]

# For backward compatibility if needed, but we'll move to full async
def scan_ports(ip, ports):
    return asyncio.run(scan_ports_async(ip, ports))