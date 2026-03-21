import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        if sock.connect_ex((ip, port)) == 0:
            sock.close()
            return port
        sock.close()
    except:
        pass
    return None

def scan_ports(ip, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)
    for port in results:
        if port:
            open_ports.append(port)
    return open_ports