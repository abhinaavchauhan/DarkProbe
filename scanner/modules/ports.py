"""
DarkProbe Network Recon — Port Scanner
=======================================
Scans common ports on the target host.
Identifies open ports and maps them to probable services.
"""

import socket
from typing import List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from scanner.core.analyzer import Vulnerability, Severity
from scanner.utils.logger import logger
from scanner.utils.helpers import PORT_SERVICE_MAP


class PortScanner:
    """
    Open Port Scanner Module.
    
    Scans target host for open ports and maps them
    to probable running services.
    """

    MODULE_NAME = "DarkProbe Network Recon"

    DEFAULT_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 993, 995, 1433, 1521, 3306, 3389,
        5432, 5900, 6379, 8080, 8443, 8888, 27017,
    ]

    def __init__(
        self,
        timeout: float = 1.5,
        threads: int = 10,
        ports: List[int] = None,
    ):
        self.timeout = timeout
        self.threads = threads
        self.ports = ports or self.DEFAULT_PORTS
        self.open_ports: List[Dict[str, any]] = []
        self.vulnerabilities: List[Vulnerability] = []

    def _scan_port(self, host: str, port: int) -> Tuple[int, bool, str]:
        """
        Scan a single port on the target host.
        Returns (port, is_open, service_name).
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()

            is_open = result == 0
            service = PORT_SERVICE_MAP.get(port, "Unknown")
            return (port, is_open, service)
        except socket.gaierror:
            return (port, False, "DNS Resolution Failed")
        except socket.timeout:
            return (port, False, "Timeout")
        except Exception:
            return (port, False, "Error")

    def _grab_banner(self, host: str, port: int) -> str:
        """Attempt to grab a service banner from an open port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            sock.send(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner[:200] if banner else ""
        except Exception:
            return ""

    def scan(self, target_url: str) -> List[Vulnerability]:
        """
        Scan the target for open ports.
        
        Args:
            target_url: Target URL to extract hostname from
            
        Returns:
            List of informational vulnerabilities for open ports
        """
        logger.module_start(self.MODULE_NAME)
        self.open_ports = []
        self.vulnerabilities = []

        # Extract hostname
        parsed = urlparse(target_url)
        host = parsed.hostname
        if not host:
            logger.error(f"Could not extract hostname from {target_url}")
            return self.vulnerabilities

        logger.info(f"Scanning {len(self.ports)} ports on {host}")

        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(host)
            logger.info(f"Resolved {host} → {ip}")
        except socket.gaierror:
            logger.error(f"Could not resolve hostname: {host}")
            return self.vulnerabilities

        # Scan ports in parallel
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._scan_port, host, port): port
                for port in self.ports
            }

            for future in as_completed(futures):
                try:
                    port, is_open, service = future.result()
                    if is_open:
                        # Try banner grab
                        banner = self._grab_banner(host, port)

                        port_info = {
                            "port": port,
                            "service": service,
                            "banner": banner,
                            "state": "open",
                        }
                        self.open_ports.append(port_info)

                        # Determine severity based on service
                        severity = Severity.INFO
                        description = f"Port {port} ({service}) is open on {host}"

                        if port in (21, 23, 135, 139, 445, 3389, 5900):
                            severity = Severity.MEDIUM
                            description += " — This service may pose a security risk"

                        vuln = Vulnerability(
                            vuln_type="Open Port Detected",
                            url=f"{host}:{port}",
                            severity=severity,
                            description=description,
                            evidence=f"Banner: {banner}" if banner else f"Port {port} responded to TCP connection",
                            recommendation=(
                                f"Verify that port {port} ({service}) needs to be exposed. "
                                f"Close unnecessary ports and restrict access with firewalls."
                            ),
                            module=self.MODULE_NAME,
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Port {port}/tcp OPEN — {service}")

                except Exception as e:
                    logger.debug(f"Port scan error: {e}")

        # Sort by port number
        self.open_ports.sort(key=lambda x: x["port"])
        self.vulnerabilities.sort(key=lambda x: int(x.url.split(":")[1]) if ":" in x.url else 0)

        logger.module_complete(self.MODULE_NAME, len(self.open_ports))
        return self.vulnerabilities

    def get_open_ports(self) -> List[Dict]:
        """Return list of open ports with details."""
        return self.open_ports
