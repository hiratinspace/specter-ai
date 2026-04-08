"""
port_scan.py — TCP Port Scanner with Banner Grabbing
Scans common ports using raw sockets. Grabs service banners where possible.

Sample usage:
    from modules.port_scan import run_port_scan
    results = run_port_scan("example.com", mode="quick")
"""

import socket
import ssl
import concurrent.futures
from datetime import datetime

HTTPS_PORTS = {443, 8443, 465, 993, 995}

# Top 20 ports for quick mode
TOP_20_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]

# Top 1000 ports for full mode (most common services)
TOP_1000_PORTS = list(set(TOP_20_PORTS + [
    8, 20, 26, 27, 37, 49, 69, 70, 79, 81, 82, 83, 84, 85, 88, 89, 90,
    99, 100, 106, 109, 113, 119, 125, 137, 138, 146, 179, 199, 211, 212,
    222, 264, 290, 311, 389, 406, 407, 416, 417, 425, 427, 444, 458, 464,
    465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 548, 554,
    587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687,
    691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800,
    801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981,
    987, 990, 992, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021,
    1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1110, 1234,
    1433, 1434, 1521, 1701, 1720, 1741, 1755, 1900, 2000, 2001, 2049,
    2100, 2181, 2375, 2376, 2379, 2380, 2404, 3000, 3001, 3128, 3268,
    3269, 3300, 3310, 4000, 4001, 4045, 4190, 4443, 4444, 4567, 4662,
    4899, 5000, 5001, 5004, 5009, 5060, 5101, 5190, 5222, 5269, 5353,
    5432, 5631, 5666, 5800, 5900, 5938, 5985, 5986, 6000, 6001, 6002,
    6003, 6004, 6005, 6006, 6007, 6379, 6443, 6667, 6881, 7000, 7001,
    7070, 7080, 7443, 7474, 7777, 7779, 8000, 8001, 8002, 8008, 8009,
    8010, 8031, 8043, 8080, 8081, 8085, 8086, 8088, 8090, 8099, 8180,
    8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983,
    9000, 9001, 9002, 9090, 9100, 9200, 9300, 9418, 9443, 9999, 10000,
    10001, 10250, 27017, 27018, 27019, 50000, 50070, 61616
]))

# Well-known port → service name mapping
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC",
    119: "NNTP", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "IKE/VPN", 512: "rexec", 513: "rlogin",
    514: "Syslog", 515: "LPD", 587: "SMTP (submission)", 636: "LDAPS",
    873: "rsync", 902: "VMware", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle DB", 1723: "PPTP VPN",
    2049: "NFS", 2375: "Docker (unencrypted)", 2376: "Docker TLS",
    2379: "etcd", 3000: "Dev server", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM HTTP", 5986: "WinRM HTTPS",
    6379: "Redis", 6443: "Kubernetes API", 7001: "WebLogic",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 8888: "Jupyter/HTTP-alt",
    9200: "Elasticsearch", 9300: "Elasticsearch cluster",
    10250: "Kubernetes kubelet", 27017: "MongoDB",
}


def grab_banner(ip, port, timeout=2):
    """Attempt to grab a service banner from an open port."""
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, port))

        if port in HTTPS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw_sock, server_hostname=ip)
        else:
            s = raw_sock

        with s:
            if port in (80, 443, 8080, 8000, 8008, 8443, 8888):
                s.send(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner on connect
            else:
                s.send(b"\r\n")
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            first_line = banner.split("\n")[0].strip()
            return first_line[:200] if first_line else None
    except Exception:
        return None


def scan_port(ip, port, timeout=1.5):
    """
    Scan a single TCP port.
    Returns dict with port info if open, None if closed.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = SERVICE_MAP.get(port, "unknown")
                banner = grab_banner(ip, port)
                return {
                    "port":    port,
                    "state":   "open",
                    "service": service,
                    "banner":  banner,
                }
    except Exception:
        pass
    return None


def resolve_target(target):
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        raise RuntimeError(f"Cannot resolve target '{target}': {e}")


def run_port_scan(target, mode="quick"):
    """
    Main entry point for port scanning.

    Returns dict with keys:
        target_ip, ports_scanned, open_ports, scan_time, mode
    """
    ip = resolve_target(target)
    ports = TOP_20_PORTS if mode == "quick" else sorted(set(TOP_1000_PORTS))
    open_ports = []
    start = datetime.now()

    # Use up to 100 threads for speed; reduce if hitting rate limits
    max_workers = 50 if mode == "quick" else 100

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    elapsed = (datetime.now() - start).total_seconds()

    return {
        "target_ip":    ip,
        "mode":         mode,
        "ports_scanned": len(ports),
        "open_ports":   open_ports,
        "scan_time_s":  round(elapsed, 2),
    }