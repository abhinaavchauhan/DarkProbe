"""
DarkProbe SQL Engine — SQL Injection Scanner
=============================================
Tests GET and POST parameters with multiple SQLi payloads.
Detects error-based, union-based, and time-based SQL injection.
"""

import time
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.core.requester import Requester
from scanner.core.analyzer import ResponseAnalyzer, Vulnerability, Severity
from scanner.core.crawler import CrawlResult, FormData
from scanner.utils.logger import logger
from scanner.utils.helpers import (
    load_payloads,
    get_payload_path,
    inject_payload_into_url,
    get_query_params,
)


class SQLiScanner:
    """
    SQL Injection Scanner Module.
    
    Tests both GET parameters and POST form data against
    a comprehensive library of SQLi payloads.
    """

    MODULE_NAME = "DarkProbe SQL Engine"

    # Time-based detection threshold (seconds)
    TIME_THRESHOLD = 4.0

    # Time-based payloads requiring special handling
    TIME_BASED_PAYLOADS = [
        "' WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)#",
        "'; SELECT pg_sleep(5)--",
    ]

    def __init__(
        self,
        requester: Requester,
        analyzer: ResponseAnalyzer,
        threads: int = 5,
        max_payloads: int = 0,
    ):
        self.requester = requester
        self.analyzer = analyzer
        self.threads = threads
        self.payloads = load_payloads(get_payload_path("sqli"))
        if max_payloads > 0:
            self.payloads = self.payloads[:max_payloads]
        self.vulnerabilities: List[Vulnerability] = []

    def _test_get_param(
        self, url: str, payload: str
    ) -> Optional[Vulnerability]:
        """Test a single GET parameter with a payload."""
        injected_urls = inject_payload_into_url(url, payload)

        for injected_url in injected_urls:
            # Check for time-based injection
            if payload in self.TIME_BASED_PAYLOADS:
                start_time = time.time()
                response = self.requester.get(injected_url)
                elapsed = time.time() - start_time

                if elapsed >= self.TIME_THRESHOLD:
                    return Vulnerability(
                        vuln_type="SQL Injection (Time-Based Blind)",
                        url=url,
                        severity=Severity.HIGH,
                        description=(
                            f"Time-based blind SQL injection detected. "
                            f"Server response delayed by {elapsed:.2f}s "
                            f"(threshold: {self.TIME_THRESHOLD}s)"
                        ),
                        evidence=f"Response time: {elapsed:.2f}s with payload",
                        parameter=injected_url.split("?")[1] if "?" in injected_url else "",
                        payload=payload,
                        recommendation=(
                            "Use parameterized queries (prepared statements) "
                            "instead of string concatenation for SQL queries. "
                            "Implement input validation and sanitization."
                        ),
                        module=self.MODULE_NAME,
                    )
            else:
                # Error-based detection
                response = self.requester.get(injected_url)
                if response and response.text:
                    errors = self.analyzer.detect_sql_errors(response.text)
                    if errors:
                        return Vulnerability(
                            vuln_type="SQL Injection (Error-Based)",
                            url=url,
                            severity=Severity.HIGH,
                            description=(
                                f"Error-based SQL injection detected. "
                                f"SQL error patterns found in response: {', '.join(errors[:3])}"
                            ),
                            evidence=errors[0],
                            parameter=injected_url.split("?")[1] if "?" in injected_url else "",
                            payload=payload,
                            recommendation=(
                                "Use parameterized queries (prepared statements). "
                                "Never concatenate user input into SQL queries. "
                                "Implement proper error handling to suppress SQL errors in responses."
                            ),
                            module=self.MODULE_NAME,
                        )

        return None

    def _test_form(
        self, form: FormData, payload: str
    ) -> Optional[Vulnerability]:
        """Test a form with a payload in all input fields."""
        if not form.inputs:
            return None

        # Build form data with payload in each field
        for target_input in form.inputs:
            if target_input["type"] in ("hidden", "submit", "button", "image"):
                continue

            form_data = {}
            for inp in form.inputs:
                if inp["name"] == target_input["name"]:
                    form_data[inp["name"]] = payload
                else:
                    form_data[inp["name"]] = inp.get("value", "test")

            if form.method == "POST":
                response = self.requester.post(form.action, data=form_data)
            else:
                response = self.requester.get(form.action, params=form_data)

            if response and response.text:
                errors = self.analyzer.detect_sql_errors(response.text)
                if errors:
                    return Vulnerability(
                        vuln_type="SQL Injection (Error-Based)",
                        url=form.action,
                        severity=Severity.HIGH,
                        description=(
                            f"SQL injection via {form.method} form at {form.url}. "
                            f"Vulnerable parameter: {target_input['name']}. "
                            f"SQL error patterns: {', '.join(errors[:3])}"
                        ),
                        evidence=errors[0],
                        parameter=target_input["name"],
                        payload=payload,
                        recommendation=(
                            "Use parameterized queries for all database operations. "
                            "Validate and sanitize all form inputs server-side. "
                            "Implement proper error handling."
                        ),
                        module=self.MODULE_NAME,
                    )

        return None

    def scan(self, crawl_result: CrawlResult) -> List[Vulnerability]:
        """
        Run the SQL injection scan against all discovered targets.
        
        Args:
            crawl_result: Results from the crawler containing URLs and forms
            
        Returns:
            List of discovered SQL injection vulnerabilities
        """
        logger.module_start(self.MODULE_NAME)
        self.vulnerabilities = []

        # Track already-found vulnerable endpoints to avoid duplicates
        found_endpoints = set()

        # Test GET parameters
        urls_with_params = list(crawl_result.urls_with_params)
        if urls_with_params:
            logger.info(f"Testing {len(urls_with_params)} URL(s) with GET parameters")

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {}
                for url in urls_with_params:
                    for payload in self.payloads:
                        future = executor.submit(self._test_get_param, url, payload)
                        futures[future] = (url, payload)

                for future in as_completed(futures):
                    try:
                        vuln = future.result()
                        if vuln and vuln.url not in found_endpoints:
                            self.vulnerabilities.append(vuln)
                            found_endpoints.add(vuln.url)
                            logger.vulnerability_found(
                                vuln.vuln_type, vuln.url, str(vuln.severity)
                            )
                    except Exception as e:
                        logger.debug(f"SQLi scan error: {e}")

        # Test forms
        forms = crawl_result.forms
        if forms:
            logger.info(f"Testing {len(forms)} form(s) for SQL injection")

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {}
                for form in forms:
                    for payload in self.payloads:
                        future = executor.submit(self._test_form, form, payload)
                        futures[future] = (form.action, payload)

                for future in as_completed(futures):
                    try:
                        vuln = future.result()
                        if vuln and vuln.url not in found_endpoints:
                            self.vulnerabilities.append(vuln)
                            found_endpoints.add(vuln.url)
                            logger.vulnerability_found(
                                vuln.vuln_type, vuln.url, str(vuln.severity)
                            )
                    except Exception as e:
                        logger.debug(f"SQLi form scan error: {e}")

        logger.module_complete(self.MODULE_NAME, len(self.vulnerabilities))
        return self.vulnerabilities
