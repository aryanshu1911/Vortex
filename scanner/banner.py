import socket
import ssl

def grab_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((ip, port))

        # HTTP (80) or HTTPS (443)
        if port == 80:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode(errors="ignore").strip()
            sock.close()
            return banner if banner else None

        elif port == 443:
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                ssock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = ssock.recv(1024).decode(errors="ignore").strip()
                return banner if banner else None

        else:
            # Other services: FTP, SMTP, SSH, SMB, RDP
            banner = sock.recv(1024).decode(errors="ignore").strip()
            sock.close()
            return banner if banner else None

    except Exception as e:
        return None