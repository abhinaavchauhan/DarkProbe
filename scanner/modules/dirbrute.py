"""
DarkProbe Directory Brute Forcer
=================================
Discovers hidden directories and files using a wordlist.
"""

from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from scanner.core.requester import Requester
from scanner.core.analyzer import Vulnerability, Severity
from scanner.utils.logger import logger
from scanner.utils.helpers import load_payloads, get_payload_path


class DirBruteForcer:
    """
    Directory brute-force scanner.
    
    Discovers hidden directories, files, and admin panels
    using a wordlist-driven approach.
    """

    MODULE_NAME = "DarkProbe Dir Scanner"

    # Status codes indicating potentially interesting content
    INTERESTING_CODES = {200, 201, 301, 302, 307, 308, 401, 403}

    def __init__(
        self,
        requester: Requester,
        threads: int = 10,
        wordlist: str = None,
    ):
        self.requester = requester
        self.threads = threads
        self.wordlist_path = wordlist or get_payload_path("dirs")
        self.wordlist = load_payloads(self.wordlist_path)
        self.vulnerabilities: List[Vulnerability] = []
        self.discovered: List[dict] = []

    def _check_path(self, base_url: str, path: str) -> Optional[dict]:
        """Check if a directory/file exists at the given path."""
        url = urljoin(base_url.rstrip("/") + "/", path)
        response = self.requester.get(url, allow_redirects=False)

        if response and response.status_code in self.INTERESTING_CODES:
            return {
                "url": url,
                "path": path,
                "status_code": response.status_code,
                "content_length": len(response.content) if response.content else 0,
            }

        return None

    def scan(self, target_url: str) -> List[Vulnerability]:
        """
        Run directory brute-force scan.
        
        Args:
            target_url: Base URL to scan
            
        Returns:
            List of vulnerabilities for discovered directories
        """
        logger.module_start(self.MODULE_NAME)
        self.vulnerabilities = []
        self.discovered = []

        logger.info(f"Testing {len(self.wordlist)} paths against {target_url}")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_path, target_url, path): path
                for path in self.wordlist
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.discovered.append(result)
                        status = result["status_code"]
                        path = result["path"]
                        url = result["url"]

                        # Determine severity based on what was found
                        severity = Severity.LOW
                        description = f"Directory/file '{path}' discovered (HTTP {status})"

                        sensitive_paths = {
                            "admin", "administrator", "phpmyadmin", "cpanel",
                            "wp-admin", ".git", ".svn", ".env", ".htpasswd",
                            "config", "backup", "backups", "database", "db",
                            "sql", "shell", "cmd", "console",
                        }

                        if path.lower() in sensitive_paths:
                            severity = Severity.HIGH
                            description = f"Sensitive path '{path}' discovered (HTTP {status})"

                        if status == 401:
                            severity = Severity.MEDIUM
                            description = f"Protected resource '{path}' found (HTTP 401 - Authentication Required)"
                        elif status == 403:
                            severity = Severity.LOW
                            description = f"Forbidden resource '{path}' found (HTTP 403)"

                        vuln = Vulnerability(
                            vuln_type="Directory/File Discovery",
                            url=url,
                            severity=severity,
                            description=description,
                            evidence=f"HTTP {status}, Content-Length: {result['content_length']}",
                            recommendation=(
                                "Remove or restrict access to unnecessary files and directories. "
                                "Implement proper access controls and disable directory listing."
                            ),
                            module=self.MODULE_NAME,
                        )
                        self.vulnerabilities.append(vuln)
                        logger.info(f"Found: /{path} [HTTP {status}]")

                except Exception as e:
                    logger.debug(f"Dir scan error: {e}")

        logger.module_complete(self.MODULE_NAME, len(self.discovered))
        return self.vulnerabilities
