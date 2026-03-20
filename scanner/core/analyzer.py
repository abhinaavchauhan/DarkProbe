"""
DarkProbe Intelligence Core (Response Analyzer)
================================================
Analyzes HTTP responses for vulnerability indicators.
Uses regex pattern matching and keyword detection with severity classification.
"""

import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Vulnerability severity levels."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    INFO = "Info"

    def __str__(self):
        return self.value


@dataclass
class Vulnerability:
    """Represents a single detected vulnerability."""
    vuln_type: str
    url: str
    severity: Severity
    description: str
    evidence: str = ""
    parameter: str = ""
    payload: str = ""
    recommendation: str = ""
    module: str = ""
    
    def to_dict(self) -> dict:
        return {
            "type": self.vuln_type,
            "url": self.url,
            "severity": str(self.severity),
            "description": self.description,
            "evidence": self.evidence[:500],  # Truncate evidence
            "parameter": self.parameter,
            "payload": self.payload,
            "recommendation": self.recommendation,
            "module": self.module,
        }


class ResponseAnalyzer:
    """
    DarkProbe Intelligence Core — Analyzes responses for vulnerability indicators.
    """

    # SQL error signatures organized by database
    SQL_ERROR_PATTERNS = [
        # MySQL
        r"you have an error in your sql syntax",
        r"warning.*mysql_",
        r"unclosed quotation mark",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"mysql_query",
        r"mysqli_",
        r"MariaDB",
        # PostgreSQL
        r"pg_query",
        r"pg_exec",
        r"pg_fetch",
        r"PostgreSQL.*ERROR",
        r"unterminated quoted string",
        # MSSQL
        r"microsoft sql server",
        r"sql server.*error",
        r"unclosed quotation mark after the character string",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        # Oracle
        r"ORA-\d{5}",
        r"oracle.*error",
        r"quoted string not properly terminated",
        # SQLite
        r"sqlite3?\.",
        r"SQLite/JDBCDriver",
        r"sqlite.*error",
        # Generic
        r"sql syntax.*error",
        r"syntax error.*sql",
        r"SQL syntax.*MySQL",
        r"valid MySQL result",
        r"SQL command not properly ended",
        r"unexpected end of SQL command",
        r"supplied argument is not a valid",
        r"Division by zero in",
        r"mysql_real_escape_string",
    ]

    # XSS reflection patterns
    XSS_REFLECTION_PATTERNS = [
        r"<script>alert\(",
        r"<img\s+src=x\s+onerror=",
        r"<svg\s*onload=",
        r"<body\s+onload=",
        r"javascript:alert\(",
        r"<iframe\s+src=",
        r"onerror\s*=\s*alert",
        r"onload\s*=\s*alert",
        r"onfocus\s*=\s*alert",
        r"onmouseover\s*=\s*alert",
    ]

    # Security headers to check
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "severity": Severity.MEDIUM,
            "description": "HTTP Strict Transport Security (HSTS) header is missing",
            "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header",
        },
        "X-Content-Type-Options": {
            "severity": Severity.LOW,
            "description": "X-Content-Type-Options header is missing (MIME sniffing protection)",
            "recommendation": "Add 'X-Content-Type-Options: nosniff' header",
        },
        "X-Frame-Options": {
            "severity": Severity.MEDIUM,
            "description": "X-Frame-Options header is missing (clickjacking protection)",
            "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header",
        },
        "Content-Security-Policy": {
            "severity": Severity.MEDIUM,
            "description": "Content-Security-Policy header is missing",
            "recommendation": "Implement a Content Security Policy to prevent XSS and data injection attacks",
        },
        "X-XSS-Protection": {
            "severity": Severity.LOW,
            "description": "X-XSS-Protection header is missing",
            "recommendation": "Add 'X-XSS-Protection: 1; mode=block' header",
        },
        "Referrer-Policy": {
            "severity": Severity.LOW,
            "description": "Referrer-Policy header is missing",
            "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header",
        },
        "Permissions-Policy": {
            "severity": Severity.LOW,
            "description": "Permissions-Policy header is missing",
            "recommendation": "Add Permissions-Policy header to control browser feature access",
        },
    }

    def __init__(self):
        # Compile regex patterns for performance
        self._sql_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.SQL_ERROR_PATTERNS
        ]
        self._xss_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.XSS_REFLECTION_PATTERNS
        ]

    def detect_sql_errors(self, response_text: str) -> List[str]:
        """Check response text for SQL error patterns."""
        matches = []
        for pattern in self._sql_patterns:
            match = pattern.search(response_text)
            if match:
                matches.append(match.group(0))
        return matches

    def detect_xss_reflection(self, response_text: str, payload: str) -> bool:
        """
        Check if an XSS payload is reflected in the response.
        Returns True if the exact payload appears in the response HTML.
        """
        # Direct payload reflection check
        if payload in response_text:
            return True

        # Pattern-based detection
        for pattern in self._xss_patterns:
            if pattern.search(response_text):
                return True

        return False

    def check_security_headers(
        self, headers: Dict[str, str], url: str
    ) -> List[Vulnerability]:
        """
        Check for missing security headers.
        Returns a list of vulnerabilities for each missing header.
        """
        vulnerabilities = []
        response_headers = {k.lower(): v for k, v in headers.items()}

        for header, info in self.SECURITY_HEADERS.items():
            if header.lower() not in response_headers:
                vuln = Vulnerability(
                    vuln_type="Missing Security Header",
                    url=url,
                    severity=info["severity"],
                    description=f"{info['description']} on {url}",
                    evidence=f"Header '{header}' not found in response",
                    recommendation=info["recommendation"],
                    module="Header Analysis",
                )
                vulnerabilities.append(vuln)

        # Check for information disclosure headers
        server = response_headers.get("server", "")
        if server:
            vuln = Vulnerability(
                vuln_type="Information Disclosure",
                url=url,
                severity=Severity.LOW,
                description=f"Server header reveals technology: {server}",
                evidence=f"Server: {server}",
                recommendation="Remove or obfuscate the Server header to prevent technology fingerprinting",
                module="Header Analysis",
            )
            vulnerabilities.append(vuln)

        x_powered = response_headers.get("x-powered-by", "")
        if x_powered:
            vuln = Vulnerability(
                vuln_type="Information Disclosure",
                url=url,
                severity=Severity.LOW,
                description=f"X-Powered-By header reveals technology: {x_powered}",
                evidence=f"X-Powered-By: {x_powered}",
                recommendation="Remove the X-Powered-By header",
                module="Header Analysis",
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def analyze_response_anomalies(
        self, response_text: str, status_code: int, url: str
    ) -> List[Vulnerability]:
        """Detect HTTP response anomalies."""
        vulnerabilities = []

        # Check for directory listing
        dir_listing_patterns = [
            r"Index of /",
            r"Directory listing for",
            r"<title>Directory listing",
            r"Parent Directory",
        ]
        for pattern in dir_listing_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                vuln = Vulnerability(
                    vuln_type="Directory Listing",
                    url=url,
                    severity=Severity.MEDIUM,
                    description="Directory listing is enabled, exposing file structure",
                    evidence=pattern,
                    recommendation="Disable directory listing in the web server configuration",
                    module="Response Analysis",
                )
                vulnerabilities.append(vuln)
                break

        # Check for error page information disclosure
        error_patterns = [
            (r"stack\s*trace", "Stack trace exposed in response"),
            (r"debug\s*mode.*(?:true|on|enabled)", "Debug mode appears to be enabled"),
            (r"(?:PHP|ASP|JSP)\s+(?:Warning|Error|Notice)", "Server-side error messages exposed"),
        ]
        for pattern, desc in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                vuln = Vulnerability(
                    vuln_type="Information Disclosure",
                    url=url,
                    severity=Severity.LOW,
                    description=desc,
                    evidence=f"Pattern matched: {pattern}",
                    recommendation="Configure proper error handling to suppress detailed error messages in production",
                    module="Response Analysis",
                )
                vulnerabilities.append(vuln)

        return vulnerabilities
