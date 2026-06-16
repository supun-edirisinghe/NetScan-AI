
"""
Core port scanning engine using asyncio for async socket scanning
and python-nmap for deeper OS/service detection.
"""
import asyncio
import socket
import ipaddress
import time
import logging
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime

logger = logging.getLogger(__name__)

# Well-known port service names
KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP-TLS", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 4444: "Metasploit", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9200: "Elasticsearch", 27017: "MongoDB",
}

# Risk weights per port (higher = more risky if open)
PORT_RISK_WEIGHTS = {
    23: 0.95,    # Telnet - unencrypted
    21: 0.85,    # FTP - unencrypted
    135: 0.80,   # MSRPC - Windows attack surface
    139: 0.80,   # NetBIOS
    445: 0.90,   # SMB - ransomware target
    3389: 0.85,  # RDP - brute force target
    4444: 1.0,   # Metasploit default
    5900: 0.75,  # VNC - often unencrypted
    6379: 0.80,  # Redis - often no auth
    9200: 0.75,  # Elasticsearch - often exposed
    27017: 0.75, # MongoDB - often no auth
    1521: 0.70,  # Oracle
    1433: 0.70,  # MSSQL
    3306: 0.65,  # MySQL
    5432: 0.60,  # PostgreSQL
    22: 0.30,    # SSH - encrypted but brute force risk
    80: 0.20,    # HTTP
    443: 0.10,   # HTTPS - low risk
    8080: 0.25,  # HTTP-Alt
}


async def _check_port(host: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """Async TCP connect scan for a single port."""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        service = KNOWN_SERVICES.get(port, "unknown")
        risk_weight = PORT_RISK_WEIGHTS.get(port, 0.2)
        return {
            "port": port,
            "state": "open",
            "service": service,
            "risk_weight": risk_weight,
        }
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return {"port": port, "state": "closed"}


async def scan_host_ports(
    host: str,
    ports: List[int],
    timeout: float = 2.0,
    concurrency: int = 100,
    progress_callback: Optional[Callable] = None,
) -> Dict[str, Any]:
    """Scan all given ports on a single host with concurrency control."""
    semaphore = asyncio.Semaphore(concurrency)

    async def bounded_check(port: int):
        async with semaphore:
            return await _check_port(host, port, timeout)

    # Try to resolve hostname
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {
            "host": host,
            "status": "error",
            "error": "Could not resolve hostname",
            "open_ports": [],
        }

    start = time.time()
    tasks = [bounded_check(port) for port in ports]
    results = await asyncio.gather(*tasks)
    elapsed = time.time() - start

    open_ports = [r for r in results if r["state"] == "open"]

    return {
        "host": host,
        "ip": ip,
        "status": "up",
        "open_ports": open_ports,
        "total_scanned": len(ports),
        "scan_duration": round(elapsed, 2),
    }


def parse_port_range(port_range: str) -> List[int]:
    """Parse port range string like '1-1024', '80,443,8080', '1-100,443'."""
    ports = set()
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def expand_targets(target: str) -> List[str]:
    """Expand CIDR notation or comma-separated hosts to a list of IPs."""
    hosts = []
    for t in target.split(","):
        t = t.strip()
        try:
            network = ipaddress.ip_network(t, strict=False)
            if network.num_addresses > 256:
                raise ValueError(f"Network too large: {t}. Max /24 supported.")
            hosts.extend(
                [str(ip) for ip in network.hosts()]
                or [str(network.network_address)]
            )
        except ValueError:
            # Treat as hostname
            hosts.append(t)
    return hosts


async def run_full_scan(
    target: str,
    port_range: str = "1-1024",
    scan_type: str = "tcp",
    timeout: float = 2.0,
    progress_callback: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Full network scan: expand targets, scan ports, aggregate results.
    Returns structured results ready for AI analysis.
    """
    hosts = expand_targets(target)
    ports = parse_port_range(port_range)

    logger.info(f"Scanning {len(hosts)} hosts, {len(ports)} ports each")

    scan_start = time.time()
    completed_hosts = 0

    # Host-level concurrency control
    host_semaphore = asyncio.Semaphore(10)

    async def scan_one_host(host: str):
        nonlocal completed_hosts
        async with host_semaphore:
            result = await scan_host_ports(host, ports, timeout)
            completed_hosts += 1

            # Send real-time progress via WebSocket callback
            if progress_callback:
                pct = int((completed_hosts / len(hosts)) * 100)
                try:
                    await progress_callback({
                        "type": "progress",
                        "percent": pct,
                        "completed": completed_hosts,
                        "total": len(hosts),
                        "current_host": host,
                    })
                except Exception as cb_err:
                    logger.warning(f"Progress callback error: {cb_err}")

            return result

    tasks = [scan_one_host(h) for h in hosts]
    host_results = await asyncio.gather(*tasks)

    total_duration = time.time() - scan_start

    # Aggregate stats
    all_open_ports = []
    port_distribution = {}
    hosts_up = 0

    for hr in host_results:
        if hr.get("status") == "up" and hr.get("open_ports"):
            hosts_up += 1
            for p in hr["open_ports"]:
                all_open_ports.append(p)
                port = str(p["port"])
                port_distribution[port] = port_distribution.get(port, 0) + 1

    return {
        "target": target,
        "scan_type": scan_type,
        "port_range": port_range,
        "total_hosts": len(hosts),
        "hosts_up": hosts_up,
        "total_open_ports": len(all_open_ports),
        "port_distribution": port_distribution,
        "hosts": host_results,
        "scan_duration": round(total_duration, 2),
        "scanned_at": datetime.utcnow().isoformat(),
    }


def try_nmap_scan(target: str, port_range: str = "1-1024") -> Optional[Dict]:
    """
    Optional nmap-based scan for deeper service/OS detection.
    Falls back gracefully if nmap is not installed.
    """
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(hosts=target, ports=port_range, arguments="-sV -O --open -T4")

        results = {}
        for host in nm.all_hosts():
            host_data = {
                "ip": host,
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "os": (
                    nm[host].get("osmatch", [{}])[0].get("name", "Unknown")
                    if nm[host].get("osmatch") else "Unknown"
                ),
                "open_ports": [],
            }
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    port_info = nm[host][proto][port]
                    if port_info["state"] == "open":
                        host_data["open_ports"].append({
                            "port": port,
                            "protocol": proto,
                            "service": port_info.get("name", "unknown"),
                            "version": port_info.get("version", ""),
                            "product": port_info.get("product", ""),
                            "state": "open",
                            "risk_weight": PORT_RISK_WEIGHTS.get(port, 0.2),
                        })
            results[host] = host_data
        return results
    except ImportError:
        logger.warning("python-nmap not installed. Using socket scanner only.")
        return None
    except Exception as e:
        logger.error(f"Nmap scan failed: {e}")
        return None