"""
DarkProbe Reporting System
===========================
Generates professional vulnerability reports in JSON and HTML formats.
HTML reports feature DarkProbe dark-theme branding with interactive tables.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from scanner.core.analyzer import Vulnerability, Severity
from scanner.utils.logger import logger
from scanner.utils.helpers import format_duration


class ReportGenerator:
    """
    Professional vulnerability report generator.
    
    Produces:
    - JSON reports for machine consumption / API integration
    - HTML reports with dark-theme DarkProbe branding
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _build_report_data(
        self,
        target_url: str,
        vulnerabilities: List[Vulnerability],
        scan_duration: float,
        crawl_stats: Dict[str, int],
        scan_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build the structured report data dictionary."""
        # Severity counts
        severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for vuln in vulnerabilities:
            sev = str(vuln.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Group by type
        vuln_by_type: Dict[str, int] = {}
        for vuln in vulnerabilities:
            vuln_by_type[vuln.vuln_type] = vuln_by_type.get(vuln.vuln_type, 0) + 1

        return {
            "meta": {
                "tool": "DarkProbe",
                "version": "1.0.0",
                "tagline": "Intelligent Attack Surface Analysis Engine",
                "scan_date": datetime.now().isoformat(),
                "scan_duration": round(scan_duration, 2),
                "scan_duration_formatted": format_duration(scan_duration),
                "target_url": target_url,
            },
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "severity_counts": severity_counts,
                "vulnerability_types": vuln_by_type,
            },
            "crawl_stats": crawl_stats,
            "scan_config": scan_config,
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
            "disclaimer": (
                "⚠️ ETHICAL DISCLAIMER: DarkProbe is intended for authorized security testing only. "
                "Unauthorized scanning of systems you do not own or have explicit permission to test is illegal. "
                "Use responsibly and ethically."
            ),
        }

    def generate_json(
        self,
        target_url: str,
        vulnerabilities: List[Vulnerability],
        scan_duration: float,
        crawl_stats: Dict[str, int],
        scan_config: Dict[str, Any],
        filename: str = None,
    ) -> str:
        """
        Generate a JSON report.
        
        Returns the file path of the generated report.
        """
        report_data = self._build_report_data(
            target_url, vulnerabilities, scan_duration, crawl_stats, scan_config
        )

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"darkprobe_report_{timestamp}.json"

        filepath = self.output_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        logger.info(f"JSON report saved: {filepath}")
        return str(filepath)

    def generate_html(
        self,
        target_url: str,
        vulnerabilities: List[Vulnerability],
        scan_duration: float,
        crawl_stats: Dict[str, int],
        scan_config: Dict[str, Any],
        filename: str = None,
    ) -> str:
        """
        Generate a professional HTML report with DarkProbe branding.
        
        Returns the file path of the generated report.
        """
        report_data = self._build_report_data(
            target_url, vulnerabilities, scan_duration, crawl_stats, scan_config
        )

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"darkprobe_report_{timestamp}.html"

        html_content = self._render_html(report_data)

        filepath = self.output_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"HTML report saved: {filepath}")
        return str(filepath)

    def _render_html(self, data: Dict[str, Any]) -> str:
        """Render the HTML report template with data."""
        meta = data["meta"]
        summary = data["summary"]
        vulns = data["vulnerabilities"]
        crawl = data.get("crawl_stats", {})

        # Build vulnerability rows
        vuln_rows = ""
        for i, v in enumerate(vulns, 1):
            sev = v["severity"]
            sev_class = sev.lower()
            vuln_rows += f"""
            <tr class="vuln-row" onclick="toggleDetail('detail-{i}')">
                <td>{i}</td>
                <td><span class="severity-badge {sev_class}">{sev}</span></td>
                <td>{v['type']}</td>
                <td class="url-cell" title="{v['url']}">{v['url'][:80]}</td>
                <td>{v['module']}</td>
            </tr>
            <tr id="detail-{i}" class="detail-row" style="display:none;">
                <td colspan="5">
                    <div class="detail-card">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Description</span>
                                <span class="detail-value">{v['description']}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Evidence</span>
                                <span class="detail-value code">{v['evidence']}</span>
                            </div>
                            {"<div class='detail-item'><span class='detail-label'>Parameter</span><span class='detail-value code'>" + v['parameter'] + "</span></div>" if v.get('parameter') else ""}
                            {"<div class='detail-item'><span class='detail-label'>Payload</span><span class='detail-value code'>" + v['payload'].replace('<', '&lt;').replace('>', '&gt;') + "</span></div>" if v.get('payload') else ""}
                            <div class="detail-item">
                                <span class="detail-label">Recommendation</span>
                                <span class="detail-value recommendation">{v['recommendation']}</span>
                            </div>
                        </div>
                    </div>
                </td>
            </tr>"""

        # Build type breakdown
        type_items = ""
        for vtype, count in summary.get("vulnerability_types", {}).items():
            type_items += f'<div class="type-item"><span class="type-name">{vtype}</span><span class="type-count">{count}</span></div>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DarkProbe — Scan Report</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #1a2332;
            --bg-card-hover: #1f2b3d;
            --border: #2a3548;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #06b6d4;
            --accent-purple: #8b5cf6;
            --accent-blue: #3b82f6;
            --severity-high: #ef4444;
            --severity-high-bg: rgba(239, 68, 68, 0.12);
            --severity-medium: #f59e0b;
            --severity-medium-bg: rgba(245, 158, 11, 0.12);
            --severity-low: #06b6d4;
            --severity-low-bg: rgba(6, 182, 212, 0.12);
            --severity-info: #64748b;
            --severity-info-bg: rgba(100, 116, 139, 0.12);
            --glow-cyan: 0 0 20px rgba(6, 182, 212, 0.15);
            --gradient-brand: linear-gradient(135deg, #06b6d4, #8b5cf6);
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1320px;
            margin: 0 auto;
            padding: 0 24px;
        }}

        /* === HEADER === */
        .report-header {{
            background: linear-gradient(180deg, rgba(6, 182, 212, 0.08) 0%, transparent 100%);
            border-bottom: 1px solid var(--border);
            padding: 48px 0 40px;
        }}

        .header-content {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 24px;
        }}

        .brand {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}

        .brand-icon {{
            width: 56px;
            height: 56px;
            background: var(--gradient-brand);
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            box-shadow: var(--glow-cyan);
        }}

        .brand-text h1 {{
            font-size: 28px;
            font-weight: 800;
            background: var(--gradient-brand);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.5px;
        }}

        .brand-text p {{
            font-size: 13px;
            color: var(--text-muted);
            font-weight: 500;
            letter-spacing: 1.5px;
            text-transform: uppercase;
        }}

        .scan-meta {{
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 6px;
            font-size: 13px;
            color: var(--text-secondary);
        }}

        .scan-meta .target {{
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-cyan);
            font-size: 14px;
            font-weight: 500;
        }}

        /* === SUMMARY CARDS === */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
            margin: 32px 0;
        }}

        .summary-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            transition: all 0.2s ease;
        }}

        .summary-card:hover {{
            border-color: rgba(6, 182, 212, 0.3);
            box-shadow: var(--glow-cyan);
        }}

        .card-label {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }}

        .card-value {{
            font-size: 36px;
            font-weight: 800;
            letter-spacing: -1px;
        }}

        .card-value.high {{ color: var(--severity-high); }}
        .card-value.medium {{ color: var(--severity-medium); }}
        .card-value.low {{ color: var(--severity-low); }}
        .card-value.total {{ background: var(--gradient-brand); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }}

        .card-sub {{
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 4px;
        }}

        /* === SEVERITY BADGES === */
        .severity-badge {{
            display: inline-flex;
            align-items: center;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .severity-badge.high {{
            background: var(--severity-high-bg);
            color: var(--severity-high);
            border: 1px solid rgba(239, 68, 68, 0.2);
        }}

        .severity-badge.medium {{
            background: var(--severity-medium-bg);
            color: var(--severity-medium);
            border: 1px solid rgba(245, 158, 11, 0.2);
        }}

        .severity-badge.low {{
            background: var(--severity-low-bg);
            color: var(--severity-low);
            border: 1px solid rgba(6, 182, 212, 0.2);
        }}

        .severity-badge.info {{
            background: var(--severity-info-bg);
            color: var(--severity-info);
            border: 1px solid rgba(100, 116, 139, 0.2);
        }}

        /* === TYPE BREAKDOWN === */
        .breakdown-section {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 32px;
        }}

        .section-title {{
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .section-title::before {{
            content: '';
            width: 4px;
            height: 24px;
            background: var(--gradient-brand);
            border-radius: 2px;
        }}

        .type-list {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}

        .type-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 16px;
            background: var(--bg-secondary);
            border-radius: 8px;
            border: 1px solid var(--border);
        }}

        .type-name {{ color: var(--text-primary); font-weight: 500; }}
        .type-count {{
            background: var(--gradient-brand);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 700;
            font-size: 18px;
        }}

        /* === VULNERABILITY TABLE === */
        .vuln-section {{
            margin-bottom: 48px;
        }}

        .vuln-table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
        }}

        .vuln-table thead th {{
            background: var(--bg-secondary);
            padding: 14px 16px;
            text-align: left;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border);
        }}

        .vuln-row {{
            cursor: pointer;
            transition: background 0.15s ease;
        }}

        .vuln-row:hover {{
            background: var(--bg-card-hover);
        }}

        .vuln-row td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            font-size: 14px;
        }}

        .url-cell {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: var(--accent-cyan);
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        /* === DETAILS === */
        .detail-row td {{
            padding: 0 !important;
            border-bottom: 1px solid var(--border);
        }}

        .detail-card {{
            padding: 20px 24px;
            background: rgba(6, 182, 212, 0.03);
            border-left: 3px solid var(--accent-cyan);
        }}

        .detail-grid {{
            display: flex;
            flex-direction: column;
            gap: 14px;
        }}

        .detail-item {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}

        .detail-label {{
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
        }}

        .detail-value {{
            font-size: 14px;
            color: var(--text-secondary);
            line-height: 1.5;
        }}

        .detail-value.code {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            background: var(--bg-secondary);
            padding: 8px 12px;
            border-radius: 6px;
            border: 1px solid var(--border);
            word-break: break-all;
        }}

        .detail-value.recommendation {{
            color: var(--accent-cyan);
            font-weight: 500;
        }}

        /* === FOOTER === */
        .report-footer {{
            border-top: 1px solid var(--border);
            padding: 32px 0;
            text-align: center;
            color: var(--text-muted);
            font-size: 13px;
        }}

        .disclaimer {{
            background: rgba(239, 68, 68, 0.06);
            border: 1px solid rgba(239, 68, 68, 0.15);
            border-radius: 8px;
            padding: 16px 20px;
            margin: 32px 0;
            color: var(--severity-medium);
            font-size: 13px;
            text-align: center;
        }}

        /* === CRAWL STATS === */
        .stats-row {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px;
            margin-bottom: 32px;
        }}

        .stat-chip {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}

        .stat-chip .stat-num {{
            font-size: 24px;
            font-weight: 700;
            color: var(--accent-blue);
        }}

        .stat-chip .stat-label {{
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 4px;
        }}

        /* === NO RESULTS === */
        .no-vulns {{
            text-align: center;
            padding: 64px 24px;
            color: var(--text-muted);
        }}

        .no-vulns .icon {{ font-size: 48px; margin-bottom: 16px; }}
        .no-vulns h3 {{ font-size: 20px; color: #22c55e; margin-bottom: 8px; }}

        /* === PRINT === */
        @media print {{
            body {{ background: white; color: #1a1a1a; }}
            .vuln-table {{ border: 1px solid #ccc; }}
            .summary-card {{ border: 1px solid #ccc; }}
        }}

        /* === RESPONSIVE === */
        @media (max-width: 768px) {{
            .header-content {{ flex-direction: column; }}
            .scan-meta {{ align-items: flex-start; }}
            .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .url-cell {{ max-width: 150px; }}
        }}
    </style>
</head>
<body>

<header class="report-header">
    <div class="container">
        <div class="header-content">
            <div class="brand">
                <div class="brand-icon">🛡️</div>
                <div class="brand-text">
                    <h1>DarkProbe</h1>
                    <p>Scan Report</p>
                </div>
            </div>
            <div class="scan-meta">
                <div>Target: <span class="target">{meta['target_url']}</span></div>
                <div>Date: {meta['scan_date'][:19].replace('T', ' ')}</div>
                <div>Duration: {meta['scan_duration_formatted']}</div>
                <div>DarkProbe v{meta['version']}</div>
            </div>
        </div>
    </div>
</header>

<main class="container">

    <!-- Summary Cards -->
    <div class="summary-grid">
        <div class="summary-card">
            <div class="card-label">Total Findings</div>
            <div class="card-value total">{summary['total_vulnerabilities']}</div>
            <div class="card-sub">Across all scan modules</div>
        </div>
        <div class="summary-card">
            <div class="card-label">High Severity</div>
            <div class="card-value high">{summary['severity_counts'].get('High', 0)}</div>
            <div class="card-sub">Critical issues requiring immediate attention</div>
        </div>
        <div class="summary-card">
            <div class="card-label">Medium Severity</div>
            <div class="card-value medium">{summary['severity_counts'].get('Medium', 0)}</div>
            <div class="card-sub">Notable issues to address</div>
        </div>
        <div class="summary-card">
            <div class="card-label">Low / Info</div>
            <div class="card-value low">{summary['severity_counts'].get('Low', 0) + summary['severity_counts'].get('Info', 0)}</div>
            <div class="card-sub">Minor issues and informational</div>
        </div>
    </div>

    <!-- Crawl Stats -->
    <div class="stats-row">
        <div class="stat-chip">
            <div class="stat-num">{crawl.get('urls_found', 0)}</div>
            <div class="stat-label">URLs Crawled</div>
        </div>
        <div class="stat-chip">
            <div class="stat-num">{crawl.get('forms_found', 0)}</div>
            <div class="stat-label">Forms Found</div>
        </div>
        <div class="stat-chip">
            <div class="stat-num">{crawl.get('urls_with_params', 0)}</div>
            <div class="stat-label">Parameterized URLs</div>
        </div>
    </div>

    <!-- Type Breakdown -->
    {"<div class='breakdown-section'><h2 class='section-title'>Vulnerability Breakdown</h2><div class='type-list'>" + type_items + "</div></div>" if type_items else ""}

    <!-- Vulnerability Table -->
    <div class="vuln-section">
        <h2 class="section-title">Detailed Findings</h2>
        {"<table class='vuln-table'><thead><tr><th>#</th><th>Severity</th><th>Type</th><th>URL</th><th>Module</th></tr></thead><tbody>" + vuln_rows + "</tbody></table>" if vuln_rows else "<div class='no-vulns'><div class='icon'>✅</div><h3>No Vulnerabilities Found</h3><p>The scan did not detect any known vulnerabilities in the target application.</p></div>"}
    </div>

    <!-- Disclaimer -->
    <div class="disclaimer">{data.get('disclaimer', '')}</div>
</main>

<footer class="report-footer">
    <div class="container">
        <p>Generated by <strong>DarkProbe v{meta['version']}</strong> — Intelligent Attack Surface Analysis Engine</p>
        <p style="margin-top:6px;">Use only on authorized systems. Unauthorized scanning is illegal.</p>
    </div>
</footer>

<script>
    function toggleDetail(id) {{
        const row = document.getElementById(id);
        if (row) {{
            row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
        }}
    }}
</script>

</body>
</html>"""
        return html
