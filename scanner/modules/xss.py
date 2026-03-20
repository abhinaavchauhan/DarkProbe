"""
DarkProbe Script Engine — XSS Scanner
======================================
Detects reflected and basic DOM-based Cross-Site Scripting vulnerabilities.
Tests GET parameters and POST forms with comprehensive XSS payloads.
"""

from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.core.requester import Requester
from scanner.core.analyzer import ResponseAnalyzer, Vulnerability, Severity
from scanner.core.crawler import CrawlResult, FormData
from scanner.utils.logger import logger
from scanner.utils.helpers import (
    load_payloads,
    get_payload_path,
    inject_payload_into_url,
)


class XSSScanner:
    """
    Cross-Site Scripting (XSS) Scanner Module.
    
    Detects:
    - Reflected XSS via GET parameters
    - Reflected XSS via POST forms
    - Basic DOM-based XSS indicators
    """

    MODULE_NAME = "DarkProbe Script Engine"

    # DOM-based XSS sink patterns
    DOM_SINKS = [
        "document.write(",
        "document.writeln(",
        "innerHTML",
        "outerHTML",
        "eval(",
        "setTimeout(",
        "setInterval(",
        "document.location",
        "window.location",
        "location.href",
        "location.assign(",
        "location.replace(",
    ]

    # DOM-based XSS source patterns
    DOM_SOURCES = [
        "document.URL",
        "document.documentURI",
        "document.referrer",
        "window.name",
        "location.search",
        "location.hash",
        "location.href",
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
        self.payloads = load_payloads(get_payload_path("xss"))
        if max_payloads > 0:
            self.payloads = self.payloads[:max_payloads]
        self.vulnerabilities: List[Vulnerability] = []

    def _test_get_param(
        self, url: str, payload: str
    ) -> Optional[Vulnerability]:
        """Test a GET parameter for reflected XSS."""
        injected_urls = inject_payload_into_url(url, payload)

        for injected_url in injected_urls:
            response = self.requester.get(injected_url)
            if response and response.text:
                if self.analyzer.detect_xss_reflection(response.text, payload):
                    return Vulnerability(
                        vuln_type="Reflected XSS",
                        url=url,
                        severity=Severity.HIGH,
                        description=(
                            f"Reflected Cross-Site Scripting detected. "
                            f"The injected payload was reflected in the response without sanitization."
                        ),
                        evidence=f"Payload reflected in response HTML",
                        parameter=injected_url.split("?")[1] if "?" in injected_url else "",
                        payload=payload,
                        recommendation=(
                            "Implement output encoding/escaping for all user-supplied input. "
                            "Use Content-Security-Policy headers. "
                            "Validate and sanitize inputs on both client and server side."
                        ),
                        module=self.MODULE_NAME,
                    )

        return None

    def _test_form(
        self, form: FormData, payload: str
    ) -> Optional[Vulnerability]:
        """Test a form for reflected XSS."""
        if not form.inputs:
            return None

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
                if self.analyzer.detect_xss_reflection(response.text, payload):
                    return Vulnerability(
                        vuln_type="Reflected XSS (Form)",
                        url=form.action,
                        severity=Severity.HIGH,
                        description=(
                            f"Reflected XSS via {form.method} form at {form.url}. "
                            f"Vulnerable parameter: {target_input['name']}."
                        ),
                        evidence=f"Payload reflected in form response",
                        parameter=target_input["name"],
                        payload=payload,
                        recommendation=(
                            "Sanitize and encode all form inputs before rendering in HTML. "
                            "Implement Content-Security-Policy headers. "
                            "Use framework-level auto-escaping features."
                        ),
                        module=self.MODULE_NAME,
                    )

        return None

    def _check_dom_xss(self, url: str) -> List[Vulnerability]:
        """Check for potential DOM-based XSS indicators in page source."""
        vulnerabilities = []

        response = self.requester.get(url)
        if not response or not response.text:
            return vulnerabilities

        html = response.text

        # Check for dangerous DOM manipulation patterns
        for sink in self.DOM_SINKS:
            if sink in html:
                for source in self.DOM_SOURCES:
                    if source in html:
                        vuln = Vulnerability(
                            vuln_type="Potential DOM-based XSS",
                            url=url,
                            severity=Severity.MEDIUM,
                            description=(
                                f"Potential DOM-based XSS detected. "
                                f"Found dangerous sink '{sink}' and source '{source}' "
                                f"in the same page. Manual verification recommended."
                            ),
                            evidence=f"Sink: {sink}, Source: {source}",
                            recommendation=(
                                "Avoid using dangerous DOM manipulation methods with user-controlled input. "
                                "Use textContent instead of innerHTML. "
                                "Implement DOMPurify or similar sanitization library."
                            ),
                            module=self.MODULE_NAME,
                        )
                        vulnerabilities.append(vuln)
                        break  # One finding per sink is enough
                break

        return vulnerabilities

    def scan(self, crawl_result: CrawlResult) -> List[Vulnerability]:
        """
        Run the XSS scan against all discovered targets.
        
        Args:
            crawl_result: Results from the crawler
            
        Returns:
            List of discovered XSS vulnerabilities
        """
        logger.module_start(self.MODULE_NAME)
        self.vulnerabilities = []
        found_endpoints = set()

        # Test GET parameters for reflected XSS
        urls_with_params = list(crawl_result.urls_with_params)
        if urls_with_params:
            logger.info(f"Testing {len(urls_with_params)} URL(s) for reflected XSS")

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
                        logger.debug(f"XSS scan error: {e}")

        # Test forms for reflected XSS
        forms = crawl_result.forms
        if forms:
            logger.info(f"Testing {len(forms)} form(s) for XSS")

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
                        logger.debug(f"XSS form scan error: {e}")

        # Check for DOM-based XSS
        logger.info("Checking for DOM-based XSS indicators")
        for url in list(crawl_result.urls)[:20]:  # Limit DOM checks
            dom_vulns = self._check_dom_xss(url)
            for vuln in dom_vulns:
                if vuln.url not in found_endpoints:
                    self.vulnerabilities.append(vuln)
                    found_endpoints.add(vuln.url)
                    logger.vulnerability_found(
                        vuln.vuln_type, vuln.url, str(vuln.severity)
                    )

        logger.module_complete(self.MODULE_NAME, len(self.vulnerabilities))
        return self.vulnerabilities
