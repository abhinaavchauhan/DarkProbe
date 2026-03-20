"""
DarkProbe Header Analyzer
==========================
Detects HTTP security header misconfigurations.
"""

from typing import List

from scanner.core.requester import Requester
from scanner.core.analyzer import ResponseAnalyzer, Vulnerability
from scanner.utils.logger import logger


class HeaderScanner:
    """
    HTTP Security Header Scanner Module.
    
    Checks for missing or misconfigured security headers
    on the target application.
    """

    MODULE_NAME = "DarkProbe Header Analysis"

    def __init__(self, requester: Requester, analyzer: ResponseAnalyzer):
        self.requester = requester
        self.analyzer = analyzer
        self.vulnerabilities: List[Vulnerability] = []

    def scan(self, target_url: str) -> List[Vulnerability]:
        """
        Scan the target URL for header misconfigurations.
        
        Args:
            target_url: URL to check headers on
            
        Returns:
            List of header-related vulnerabilities
        """
        logger.module_start(self.MODULE_NAME)
        self.vulnerabilities = []

        response = self.requester.get(target_url)
        if not response:
            logger.error(f"Could not fetch {target_url} for header analysis")
            return self.vulnerabilities

        # Check security headers
        header_vulns = self.analyzer.check_security_headers(
            dict(response.headers), target_url
        )
        self.vulnerabilities.extend(header_vulns)

        # Check response anomalies
        anomaly_vulns = self.analyzer.analyze_response_anomalies(
            response.text, response.status_code, target_url
        )
        self.vulnerabilities.extend(anomaly_vulns)

        for vuln in self.vulnerabilities:
            logger.vulnerability_found(
                vuln.vuln_type, vuln.url, str(vuln.severity)
            )

        logger.module_complete(self.MODULE_NAME, len(self.vulnerabilities))
        return self.vulnerabilities
