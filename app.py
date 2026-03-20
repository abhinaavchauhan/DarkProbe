"""
DarkProbe Web Dashboard
========================
Premium Flask-based cybersecurity dashboard for DarkProbe.
Features real-time scan progress, vulnerability display, and report downloads.

⚠️ Use only on authorized systems. Unauthorized scanning is illegal.
"""

import os
import json
import time
import threading
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_file

from scanner.core.requester import Requester
from scanner.core.crawler import Crawler
from scanner.core.analyzer import ResponseAnalyzer, Vulnerability
from scanner.modules.sqli import SQLiScanner
from scanner.modules.xss import XSSScanner
from scanner.modules.ports import PortScanner
from scanner.modules.dirbrute import DirBruteForcer
from scanner.modules.headers import HeaderScanner
from scanner.utils.logger import logger
from scanner.utils.helpers import validate_url, format_duration
from reports.generator import ReportGenerator


app = Flask(__name__)
app.secret_key = os.urandom(32)

# ── Global scan state ──
scan_state = {
    "running": False,
    "progress": 0,
    "status": "idle",
    "phase": "",
    "target": "",
    "start_time": None,
    "results": None,
    "error": None,
    "log_messages": [],
}


def reset_scan_state():
    """Reset global scan state."""
    scan_state.update({
        "running": False,
        "progress": 0,
        "status": "idle",
        "phase": "",
        "target": "",
        "start_time": None,
        "results": None,
        "error": None,
        "log_messages": [],
    })


def add_log(message: str, level: str = "info"):
    """Add a log message to the scan state."""
    scan_state["log_messages"].append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "level": level,
        "message": message,
    })
    if len(scan_state["log_messages"]) > 200:
        scan_state["log_messages"] = scan_state["log_messages"][-200:]


def run_background_scan(target_url: str, config: dict):
    """Execute scan in a background thread."""
    try:
        scan_state["running"] = True
        scan_state["target"] = target_url
        scan_state["start_time"] = time.time()
        scan_state["status"] = "running"

        threads = config.get("threads", 5)
        depth = config.get("depth", 3)
        max_urls = config.get("max_urls", 100)
        timeout = config.get("timeout", 10)
        delay = config.get("delay", 0.0)

        requester = Requester(timeout=timeout, delay=delay)
        analyzer = ResponseAnalyzer()
        all_vulns: list = []

        # Phase 1: Crawling
        scan_state["phase"] = "Reconnaissance"
        scan_state["progress"] = 10
        add_log(f"Starting crawl on {target_url}", "info")

        crawler = Crawler(requester=requester, max_depth=depth, max_urls=max_urls)
        crawl_result = crawler.crawl(target_url)
        crawl_stats = crawler.get_stats()

        add_log(
            f"Crawl complete: {crawl_stats['urls_found']} URLs, "
            f"{crawl_stats['forms_found']} forms",
            "info"
        )
        scan_state["progress"] = 25

        # Phase 2: Scanning
        scan_state["phase"] = "Vulnerability Scanning"

        if config.get("sqli", True):
            scan_state["progress"] = 30
            add_log("Running SQL Injection scanner...", "info")
            sqli = SQLiScanner(requester=requester, analyzer=analyzer, threads=threads)
            sqli_vulns = sqli.scan(crawl_result)
            all_vulns.extend(sqli_vulns)
            for v in sqli_vulns:
                add_log(f"[VULN] {v.vuln_type} at {v.url}", "warning")
            scan_state["progress"] = 45

        if config.get("xss", True):
            add_log("Running XSS scanner...", "info")
            xss = XSSScanner(requester=requester, analyzer=analyzer, threads=threads)
            xss_vulns = xss.scan(crawl_result)
            all_vulns.extend(xss_vulns)
            for v in xss_vulns:
                add_log(f"[VULN] {v.vuln_type} at {v.url}", "warning")
            scan_state["progress"] = 60

        if config.get("dirs", True):
            add_log("Running directory scanner...", "info")
            dir_scanner = DirBruteForcer(requester=requester, threads=threads)
            dir_vulns = dir_scanner.scan(target_url)
            all_vulns.extend(dir_vulns)
            scan_state["progress"] = 70

        if config.get("headers", True):
            add_log("Running header analysis...", "info")
            header_scanner = HeaderScanner(requester=requester, analyzer=analyzer)
            header_vulns = header_scanner.scan(target_url)
            all_vulns.extend(header_vulns)
            scan_state["progress"] = 80

        if config.get("ports", True):
            add_log("Running port scanner...", "info")
            port_scanner = PortScanner(threads=threads)
            port_vulns = port_scanner.scan(target_url)
            all_vulns.extend(port_vulns)
            scan_state["progress"] = 90

        # Phase 3: Reports
        scan_state["phase"] = "Generating Reports"
        duration = time.time() - scan_state["start_time"]

        scan_config = {
            "threads": threads,
            "depth": depth,
            "max_urls": max_urls,
            "timeout": timeout,
        }

        report_gen = ReportGenerator()
        json_path = report_gen.generate_json(
            target_url, all_vulns, duration, crawl_stats, scan_config
        )
        html_path = report_gen.generate_html(
            target_url, all_vulns, duration, crawl_stats, scan_config
        )

        sev_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for v in all_vulns:
            s = str(v.severity)
            if s in sev_counts:
                sev_counts[s] += 1

        scan_state["results"] = {
            "target": target_url,
            "total_vulns": len(all_vulns),
            "severity_counts": sev_counts,
            "vulnerabilities": [v.to_dict() for v in all_vulns],
            "crawl_stats": crawl_stats,
            "duration": round(duration, 2),
            "duration_formatted": format_duration(duration),
            "json_report": json_path,
            "html_report": html_path,
            "request_count": requester.request_count,
        }

        scan_state["progress"] = 100
        scan_state["status"] = "completed"
        scan_state["phase"] = "Complete"
        add_log(f"Scan completed! Found {len(all_vulns)} vulnerability(ies)", "info")

        requester.close()

    except Exception as e:
        scan_state["status"] = "error"
        scan_state["error"] = str(e)
        add_log(f"Error: {str(e)}", "error")
    finally:
        scan_state["running"] = False


# ── Routes ──

@app.route("/")
def index():
    """Serve the DarkProbe cybersecurity dashboard."""
    return render_template("dashboard.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Start a new scan."""
    if scan_state["running"]:
        return jsonify({"status": "error", "message": "A scan is already running"}), 409

    data = request.get_json()
    target = data.get("url", "")
    validated = validate_url(target)

    if not validated:
        return jsonify({"status": "error", "message": "Invalid URL"}), 400

    reset_scan_state()

    config = {
        "threads": data.get("threads", 5),
        "depth": data.get("depth", 3),
        "max_urls": data.get("max_urls", 100),
        "timeout": data.get("timeout", 10),
        "delay": data.get("delay", 0.0),
        "sqli": data.get("sqli", True),
        "xss": data.get("xss", True),
        "ports": data.get("ports", True),
        "dirs": data.get("dirs", True),
        "headers": data.get("headers", True),
    }

    thread = threading.Thread(
        target=run_background_scan,
        args=(validated, config),
        daemon=True,
    )
    thread.start()

    return jsonify({"status": "started", "target": validated})


@app.route("/api/status")
def api_status():
    """Get current scan status."""
    return jsonify({
        "running": scan_state["running"],
        "progress": scan_state["progress"],
        "status": scan_state["status"],
        "phase": scan_state["phase"],
        "target": scan_state["target"],
        "error": scan_state["error"],
        "logs": scan_state["log_messages"][-50:],
    })


@app.route("/api/results")
def api_results():
    """Get scan results."""
    return jsonify({"results": scan_state.get("results")})


@app.route("/api/download/<report_type>")
def api_download(report_type):
    """Download a generated report."""
    results = scan_state.get("results")
    if not results:
        return jsonify({"error": "No results available"}), 404

    if report_type == "html":
        filepath = results.get("html_report")
    elif report_type == "json":
        filepath = results.get("json_report")
    else:
        return jsonify({"error": "Invalid report type"}), 400

    if filepath and os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        return jsonify({"error": "Report file not found"}), 404


def start_dashboard(host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
    """Start the DarkProbe web dashboard."""
    logger.info(f"Starting DarkProbe Dashboard on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    start_dashboard(debug=True)
