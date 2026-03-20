"""
DarkProbe — Intelligent Attack Surface Analysis Engine
=======================================================
Main CLI entry point.

Usage:
    python main.py --url <target> [--threads 10] [--output report.html] [--depth 3]

⚠️ Use only on authorized systems. Unauthorized scanning is illegal.
"""

import sys
import time
import argparse
from typing import List

from scanner.core.requester import Requester
from scanner.core.crawler import Crawler
from scanner.core.analyzer import ResponseAnalyzer, Vulnerability
from scanner.modules.sqli import SQLiScanner
from scanner.modules.xss import XSSScanner
from scanner.modules.ports import PortScanner
from scanner.modules.dirbrute import DirBruteForcer
from scanner.modules.headers import HeaderScanner
from scanner.utils.logger import logger
from scanner.utils.helpers import validate_url
from reports.generator import ReportGenerator


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="DarkProbe",
        description=(
            "🛡️ DarkProbe — Intelligent Attack Surface Analysis Engine\n"
            "A modular web application vulnerability scanner."
        ),
        epilog="⚠️  Use only on authorized systems. Unauthorized scanning is illegal.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--url", "-u",
        required=True,
        help="Target URL to scan (e.g., http://example.com)",
    )
    parser.add_argument(
        "--threads", "-t",
        type=int,
        default=5,
        help="Number of concurrent threads (default: 5)",
    )
    parser.add_argument(
        "--depth", "-d",
        type=int,
        default=3,
        help="Maximum crawl depth (default: 3)",
    )
    parser.add_argument(
        "--max-urls",
        type=int,
        default=100,
        help="Maximum URLs to crawl (default: 100)",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output report filename (e.g., report.html or report.json)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["html", "json", "both"],
        default="both",
        help="Report format (default: both)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay between requests in seconds for rate limiting (default: 0)",
    )
    parser.add_argument(
        "--no-sqli",
        action="store_true",
        help="Skip SQL injection scanning",
    )
    parser.add_argument(
        "--no-xss",
        action="store_true",
        help="Skip XSS scanning",
    )
    parser.add_argument(
        "--no-ports",
        action="store_true",
        help="Skip port scanning",
    )
    parser.add_argument(
        "--no-dirs",
        action="store_true",
        help="Skip directory brute-forcing",
    )
    parser.add_argument(
        "--no-headers",
        action="store_true",
        help="Skip header analysis",
    )
    parser.add_argument(
        "--proxy",
        type=str,
        default=None,
        help="Proxy URL (e.g., http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify SSL certificates (default: off)",
    )

    return parser.parse_args()


def run_scan(args) -> dict:
    """
    Execute the full DarkProbe scanning pipeline.
    Returns a dict with scan results for use by both CLI and web UI.
    """
    start_time = time.time()

    # ── Validate target URL ──
    target_url = validate_url(args.url)
    if not target_url:
        logger.error(f"Invalid URL: {args.url}")
        sys.exit(1)

    logger.print_banner()
    logger.scan_start(target_url)

    # ── Initialize components ──
    requester = Requester(
        timeout=args.timeout,
        delay=args.delay,
        verify_ssl=args.verify_ssl,
        proxy=args.proxy,
    )
    analyzer = ResponseAnalyzer()
    all_vulnerabilities: List[Vulnerability] = []

    # ── Phase 1: Reconnaissance (Crawling) ──
    logger.info("═" * 50)
    logger.info("PHASE 1: Reconnaissance — Crawling target")
    logger.info("═" * 50)

    crawler = Crawler(
        requester=requester,
        max_depth=args.depth,
        max_urls=args.max_urls,
    )
    crawl_result = crawler.crawl(target_url)
    crawl_stats = crawler.get_stats()

    logger.info(
        f"Crawl complete: {crawl_stats['urls_found']} URLs, "
        f"{crawl_stats['forms_found']} forms, "
        f"{crawl_stats['urls_with_params']} parameterized URLs"
    )

    # ── Phase 2: Vulnerability Scanning ──
    logger.info("═" * 50)
    logger.info("PHASE 2: Vulnerability Scanning")
    logger.info("═" * 50)

    # SQL Injection
    if not args.no_sqli:
        sqli_scanner = SQLiScanner(
            requester=requester,
            analyzer=analyzer,
            threads=args.threads,
        )
        sqli_vulns = sqli_scanner.scan(crawl_result)
        all_vulnerabilities.extend(sqli_vulns)

    # XSS
    if not args.no_xss:
        xss_scanner = XSSScanner(
            requester=requester,
            analyzer=analyzer,
            threads=args.threads,
        )
        xss_vulns = xss_scanner.scan(crawl_result)
        all_vulnerabilities.extend(xss_vulns)

    # Directory Brute-Force
    if not args.no_dirs:
        dir_scanner = DirBruteForcer(
            requester=requester,
            threads=args.threads,
        )
        dir_vulns = dir_scanner.scan(target_url)
        all_vulnerabilities.extend(dir_vulns)

    # Header Analysis
    if not args.no_headers:
        header_scanner = HeaderScanner(
            requester=requester,
            analyzer=analyzer,
        )
        header_vulns = header_scanner.scan(target_url)
        all_vulnerabilities.extend(header_vulns)

    # Port Scanning
    if not args.no_ports:
        port_scanner = PortScanner(threads=args.threads)
        port_vulns = port_scanner.scan(target_url)
        all_vulnerabilities.extend(port_vulns)

    # ── Phase 3: Report Generation ──
    scan_duration = time.time() - start_time
    logger.info("═" * 50)
    logger.info("PHASE 3: Generating Reports")
    logger.info("═" * 50)

    scan_config = {
        "threads": args.threads,
        "depth": args.depth,
        "max_urls": args.max_urls,
        "timeout": args.timeout,
        "delay": args.delay,
        "modules": {
            "sqli": not args.no_sqli,
            "xss": not args.no_xss,
            "ports": not args.no_ports,
            "dirs": not args.no_dirs,
            "headers": not args.no_headers,
        },
    }

    report_gen = ReportGenerator()
    report_format = args.format
    output_filename = args.output

    reports_generated = []

    if report_format in ("json", "both"):
        json_file = output_filename if output_filename and output_filename.endswith(".json") else None
        json_path = report_gen.generate_json(
            target_url, all_vulnerabilities, scan_duration, crawl_stats, scan_config,
            filename=json_file,
        )
        reports_generated.append(json_path)

    if report_format in ("html", "both"):
        html_file = output_filename if output_filename and output_filename.endswith(".html") else None
        html_path = report_gen.generate_html(
            target_url, all_vulnerabilities, scan_duration, crawl_stats, scan_config,
            filename=html_file,
        )
        reports_generated.append(html_path)

    # ── Summary ──
    logger.info("═" * 50)
    logger.scan_complete(len(all_vulnerabilities), scan_duration)
    logger.info(f"Total HTTP requests: {requester.request_count}")
    for rp in reports_generated:
        logger.info(f"Report saved: {rp}")
    logger.info("═" * 50)

    requester.close()

    return {
        "target_url": target_url,
        "vulnerabilities": all_vulnerabilities,
        "crawl_stats": crawl_stats,
        "scan_duration": scan_duration,
        "scan_config": scan_config,
        "request_count": requester.request_count,
    }


def main():
    """Main entry point for DarkProbe CLI."""
    try:
        args = parse_args()
        run_scan(args)
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user (Ctrl+C)")
        sys.exit(130)
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
