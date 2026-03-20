<div align="center">

# 🛡️ DarkProbe

### *Intelligent Attack Surface Analysis Engine*

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Security Tool](https://img.shields.io/badge/Category-Security%20Scanner-red?style=for-the-badge&logo=hackaday&logoColor=white)](.)

---

**DarkProbe** is a production-ready, modular web application vulnerability scanner built in Python.  
It detects common web vulnerabilities and generates professional, branded reports.

*A modern, lightweight alternative to tools like Burp Suite, Nikto, and OWASP ZAP.*

</div>

---

## ⚡ Features

| Module | Description |
|--------|-------------|
| 🕷️ **Recon Engine** | Intelligent web crawler — discovers URLs, forms, and parameterized endpoints |
| 💉 **SQL Engine** | SQL injection scanner — error-based, time-based blind, union-based detection |
| 📜 **Script Engine** | XSS scanner — reflected, form-based, and DOM-based detection |
| 🌐 **Network Recon** | TCP port scanner — service detection with banner grabbing |
| 📁 **Dir Scanner** | Directory brute-force — discovers hidden paths and admin panels |
| 🔒 **Header Analysis** | Security header audit — checks for 7+ missing security headers |
| 📊 **Reporting System** | Professional JSON + HTML reports with dark-themed branding |
| 🖥️ **Web Dashboard** | Flask-based UI with real-time scan progress and results display |

---

## 🏗️ Architecture

```
DarkProbe/
├── scanner/
│   ├── core/
│   │   ├── crawler.py       # Recon Engine — link & form discovery
│   │   ├── requester.py     # HTTP layer — sessions, retries, rate limiting
│   │   └── analyzer.py      # Intelligence Core — pattern matching & severity
│   ├── modules/
│   │   ├── sqli.py           # SQL Injection scanner
│   │   ├── xss.py            # Cross-Site Scripting scanner
│   │   ├── ports.py          # Port scanner
│   │   ├── dirbrute.py       # Directory brute-forcer
│   │   └── headers.py        # Security header analyzer
│   └── utils/
│       ├── logger.py         # Color-coded structured logging
│       └── helpers.py        # URL utilities, payload loading
├── payloads/
│   ├── sqli.txt              # SQL injection payloads (33+)
│   ├── xss.txt               # XSS payloads (30+)
│   └── dirs.txt              # Directory wordlist (85+)
├── reports/
│   └── generator.py          # JSON + branded HTML report generation
├── logs/
│   └── darkprobe.log         # Structured scan logs
├── main.py                   # CLI entry point
├── app.py                    # Flask web dashboard
└── requirements.txt
```

---

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/DarkProbe.git
cd DarkProbe

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

### CLI Scanner

```bash
# Basic scan
python main.py --url http://target.com

# Full scan with custom options
python main.py --url http://target.com --threads 10 --depth 5 --output report.html

# Scan with rate limiting (avoid detection)
python main.py --url http://target.com --delay 0.5

# Scan specific modules only
python main.py --url http://target.com --no-ports --no-dirs

# Use proxy (e.g., Burp Suite)
python main.py --url http://target.com --proxy http://127.0.0.1:8080
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--url, -u` | Target URL (required) | — |
| `--threads, -t` | Concurrent threads | 5 |
| `--depth, -d` | Maximum crawl depth | 3 |
| `--max-urls` | Maximum URLs to crawl | 100 |
| `--output, -o` | Output report filename | Auto-generated |
| `--format, -f` | Report format: html, json, both | both |
| `--timeout` | Request timeout (seconds) | 10 |
| `--delay` | Delay between requests (rate limiting) | 0 |
| `--proxy` | Proxy URL | None |
| `--verify-ssl` | Verify SSL certificates | Off |
| `--no-sqli` | Skip SQL injection scanning | — |
| `--no-xss` | Skip XSS scanning | — |
| `--no-ports` | Skip port scanning | — |
| `--no-dirs` | Skip directory brute-forcing | — |
| `--no-headers` | Skip header analysis | — |

### CLI Output Example

```
[2025-01-15 14:30:00] [INFO] Initializing DarkProbe scan against: http://target.com
[2025-01-15 14:30:01] [INFO] PHASE 1: Reconnaissance — Crawling target
[2025-01-15 14:30:05] [INFO] Crawl complete: 23 URLs, 4 forms, 7 parameterized URLs
[2025-01-15 14:30:05] [INFO] PHASE 2: Vulnerability Scanning
[2025-01-15 14:30:06] [INFO] Starting module: DarkProbe SQL Engine
[2025-01-15 14:30:12] [WARN] [VULNERABLE] SQL Injection (Error-Based) detected at /login [Severity: HIGH]
[2025-01-15 14:30:15] [INFO] Starting module: DarkProbe Script Engine
[2025-01-15 14:30:18] [WARN] [VULNERABLE] Reflected XSS detected at /search [Severity: HIGH]
[2025-01-15 14:30:20] [INFO] PHASE 3: Generating Reports
[2025-01-15 14:30:20] [INFO] Scan completed. Found 5 vulnerability(ies) in 20.00s
```

### Web Dashboard

```bash
# Start the web dashboard
python app.py

# Open in browser: http://127.0.0.1:5000
```

The web dashboard provides:
- 🎯 Target URL input with module toggles
- 📊 Real-time scan progress with live logs
- 📋 Interactive results table with severity badges
- 📥 One-click HTML/JSON report downloads

---

## 📊 Reports

### HTML Report
- Premium dark-themed design with DarkProbe branding
- Interactive expandable vulnerability rows
- Severity badges, crawl statistics, and type breakdown
- Responsive layout — works on all screen sizes

### JSON Report
- Machine-readable structured output
- Full vulnerability metadata (type, severity, evidence, payload, recommendation)
- Scan configuration and crawl statistics
- Suitable for CI/CD pipeline integration

---

## 🧪 Testing

Test DarkProbe against intentionally vulnerable applications:

- **DVWA** — Damn Vulnerable Web Application
- **WebGoat** — OWASP WebGoat
- **Juice Shop** — OWASP Juice Shop
- **bWAPP** — Buggy Web Application

```bash
# Example: Test against local DVWA
python main.py --url http://localhost/dvwa --threads 10
```

---

## 🔒 Security Best Practices

- ✅ Request timeouts prevent hanging connections
- ✅ Visited URL set prevents infinite crawling loops
- ✅ Depth limits prevent excessive recursion
- ✅ Rate limiting to avoid triggering WAFs/IDS
- ✅ Graceful exception handling on malformed responses
- ✅ Thread-safe HTTP session management
- ✅ SSL warning suppression for security testing contexts

---

## ⚠️ Ethical Disclaimer

> **DarkProbe is intended for authorized security testing only.**
>
> Unauthorized scanning of systems you do not own or have explicit written permission to test is **illegal** and unethical. Always obtain proper authorization before conducting any security assessment.
>
> The developers assume no liability for misuse of this tool.

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with ⚡ by the DarkProbe Team**

*Intelligent Attack Surface Analysis Engine — v1.0.0*

</div>
