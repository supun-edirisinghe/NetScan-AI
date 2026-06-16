"""
CVE Live Lookup Service
Fetches real CVE data from NVD (National Vulnerability Database) API.
Free API - no key required for basic usage.
"""
import httpx
import logging
import asyncio
from typing import List, Dict, Any
from app.services.scanner import KNOWN_SERVICES

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Cached CVE data to avoid repeated API calls
_cve_cache: Dict[str, List] = {}

# High-value CVEs per service (built-in fallback)
KNOWN_CVES = {
    "SMB": [
        {"id": "CVE-2017-0144", "severity": "CRITICAL", "score": 9.3,
         "description": "EternalBlue - SMB remote code execution (WannaCry)"},
        {"id": "CVE-2020-0796", "severity": "CRITICAL", "score": 10.0,
         "description": "SMBGhost - Windows SMBv3 remote code execution"},
        {"id": "CVE-2017-0145", "severity": "CRITICAL", "score": 9.3,
         "description": "EternalRomance - SMB remote code execution"},
    ],
    "RDP": [
        {"id": "CVE-2019-0708", "severity": "CRITICAL", "score": 9.8,
         "description": "BlueKeep - RDP pre-auth remote code execution"},
        {"id": "CVE-2021-34535", "severity": "CRITICAL", "score": 8.8,
         "description": "Remote Desktop Client remote code execution"},
        {"id": "CVE-2019-1181", "severity": "CRITICAL", "score": 9.8,
         "description": "DejaBlue - RDP remote code execution"},
    ],
    "FTP": [
        {"id": "CVE-2010-4221", "severity": "HIGH", "score": 10.0,
         "description": "ProFTPD remote code execution vulnerability"},
        {"id": "CVE-2015-3306", "severity": "HIGH", "score": 10.0,
         "description": "ProFTPD mod_copy arbitrary file copy"},
    ],
    "Telnet": [
        {"id": "CVE-2020-15778", "severity": "MEDIUM", "score": 7.8,
         "description": "Telnet scp command injection vulnerability"},
    ],
    "SSH": [
        {"id": "CVE-2023-38408", "severity": "CRITICAL", "score": 9.8,
         "description": "OpenSSH remote code execution via ssh-agent"},
        {"id": "CVE-2024-6387", "severity": "HIGH", "score": 8.1,
         "description": "regreSSHion - OpenSSH race condition RCE"},
    ],
    "HTTP": [
        {"id": "CVE-2021-41773", "severity": "CRITICAL", "score": 9.8,
         "description": "Apache HTTP Server path traversal and RCE"},
        {"id": "CVE-2021-42013", "severity": "CRITICAL", "score": 9.8,
         "description": "Apache HTTP Server path traversal vulnerability"},
    ],
    "MySQL": [
        {"id": "CVE-2012-2122", "severity": "HIGH", "score": 5.1,
         "description": "MySQL authentication bypass vulnerability"},
        {"id": "CVE-2016-6662", "severity": "CRITICAL", "score": 9.8,
         "description": "MySQL remote root code execution"},
    ],
    "Redis": [
        {"id": "CVE-2022-0543", "severity": "CRITICAL", "score": 10.0,
         "description": "Redis Lua sandbox escape and RCE"},
        {"id": "CVE-2023-28425", "severity": "MEDIUM", "score": 5.5,
         "description": "Redis SRANDMEMBER crash vulnerability"},
    ],
    "MongoDB": [
        {"id": "CVE-2019-2386", "severity": "MEDIUM", "score": 7.1,
         "description": "MongoDB unauthorized data access vulnerability"},
    ],
    "Elasticsearch": [
        {"id": "CVE-2021-22145", "severity": "MEDIUM", "score": 6.5,
         "description": "Elasticsearch memory disclosure vulnerability"},
        {"id": "CVE-2014-3120", "severity": "HIGH", "score": 6.8,
         "description": "Elasticsearch remote code execution via Groovy"},
    ],
    "PostgreSQL": [
        {"id": "CVE-2019-10164", "severity": "CRITICAL", "score": 8.8,
         "description": "PostgreSQL stack overflow in password handling"},
    ],
    "MSSQL": [
        {"id": "CVE-2020-0618", "severity": "HIGH", "score": 8.8,
         "description": "SQL Server Reporting Services remote code execution"},
    ],
    "VNC": [
        {"id": "CVE-2019-15681", "severity": "HIGH", "score": 7.5,
         "description": "LibVNCServer memory leak vulnerability"},
        {"id": "CVE-2020-14398", "severity": "HIGH", "score": 7.5,
         "description": "LibVNCServer infinite loop vulnerability"},
    ],
    "NetBIOS": [
        {"id": "CVE-2017-0144", "severity": "CRITICAL", "score": 9.3,
         "description": "EternalBlue affects NetBIOS/SMB services"},
    ],
    "MSRPC": [
        {"id": "CVE-2003-0352", "severity": "CRITICAL", "score": 10.0,
         "description": "MS RPC DCOM buffer overflow (Blaster worm)"},
    ],
}


async def fetch_cves_from_nvd(keyword: str, max_results: int = 3) -> List[Dict]:
    """Fetch CVEs from NVD API for a given service keyword."""
    cache_key = f"{keyword}_{max_results}"
    if cache_key in _cve_cache:
        return _cve_cache[cache_key]

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(
                NVD_API_URL,
                params={
                    "keywordSearch": keyword,
                    "resultsPerPage": max_results,
                    "cvssV3Severity": "HIGH",
                }
            )
            if response.status_code == 200:
                data = response.json()
                cves = []
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "Unknown")
                    descriptions = cve.get("descriptions", [])
                    desc = next(
                        (d["value"] for d in descriptions if d["lang"] == "en"),
                        "No description available"
                    )
                    metrics = cve.get("metrics", {})
                    score = 0.0
                    severity = "UNKNOWN"
                    if "cvssMetricV31" in metrics:
                        cvss = metrics["cvssMetricV31"][0]["cvssData"]
                        score = cvss.get("baseScore", 0)
                        severity = cvss.get("baseSeverity", "UNKNOWN")
                    elif "cvssMetricV2" in metrics:
                        cvss = metrics["cvssMetricV2"][0]["cvssData"]
                        score = cvss.get("baseScore", 0)
                        severity = "HIGH" if score >= 7 else "MEDIUM"

                    cves.append({
                        "id": cve_id,
                        "severity": severity,
                        "score": score,
                        "description": desc[:150] + "..." if len(desc) > 150 else desc,
                    })

                _cve_cache[cache_key] = cves
                return cves
    except Exception as e:
        logger.warning(f"NVD API call failed for '{keyword}': {e}")

    return []


async def get_cves_for_port(port: int, service: str) -> List[Dict]:
    """
    Get CVEs for a given port/service combination.
    Uses built-in database first, then tries NVD API.
    """
    service_name = service or KNOWN_SERVICES.get(port, "unknown")

    # Check built-in CVE database first
    if service_name in KNOWN_CVES:
        return KNOWN_CVES[service_name]

    # Try NVD API for unknown services
    if service_name and service_name != "unknown":
        nvd_cves = await fetch_cves_from_nvd(service_name)
        if nvd_cves:
            return nvd_cves

    return []


async def enrich_scan_with_cves(scan_results: Dict) -> Dict:
    """
    Enrich scan results with CVE data for each open port on each host.
    """
    hosts = scan_results.get("hosts", [])
    enriched_hosts = []

    for host in hosts:
        open_ports = host.get("open_ports", [])
        enriched_ports = []

        # Fetch CVEs concurrently for all ports
        async def enrich_port(port_info):
            port = port_info.get("port", 0)
            service = port_info.get("service", "unknown")
            cves = await get_cves_for_port(port, service)
            return {**port_info, "cves": cves}

        if open_ports:
            tasks = [enrich_port(p) for p in open_ports]
            enriched_ports = await asyncio.gather(*tasks)

        enriched_hosts.append({**host, "open_ports": enriched_ports})

    return {**scan_results, "hosts": enriched_hosts}