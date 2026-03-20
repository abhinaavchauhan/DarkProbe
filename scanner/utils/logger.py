"""
DarkProbe Logging System
========================
Structured logging with file and console output.
Timestamps, severity levels, and color-coded console messages.
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False


class DarkProbeFormatter(logging.Formatter):
    """Custom formatter with color-coded severity levels for console output."""

    if COLORAMA_AVAILABLE:
        LEVEL_COLORS = {
            logging.DEBUG: Fore.CYAN,
            logging.INFO: Fore.GREEN,
            logging.WARNING: Fore.YELLOW,
            logging.ERROR: Fore.RED,
            logging.CRITICAL: Fore.RED + Style.BRIGHT,
        }
    else:
        LEVEL_COLORS = {}

    LEVEL_LABELS = {
        logging.DEBUG: "DEBUG",
        logging.INFO: "INFO",
        logging.WARNING: "WARN",
        logging.ERROR: "ERROR",
        logging.CRITICAL: "CRITICAL",
    }

    def __init__(self, use_color: bool = True):
        super().__init__()
        self.use_color = use_color and COLORAMA_AVAILABLE

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        label = self.LEVEL_LABELS.get(record.levelno, "UNKNOWN")

        if self.use_color:
            color = self.LEVEL_COLORS.get(record.levelno, "")
            reset = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
            prefix = f"{Fore.WHITE}[{timestamp}]{reset} {color}[{label}]{reset}"
        else:
            prefix = f"[{timestamp}] [{label}]"

        message = record.getMessage()
        return f"{prefix} {message}"


class ScanEventLogger:
    """Specialized logger for scan events with DarkProbe branding."""

    BANNER = r"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║     ██████╗  █████╗ ██████╗ ██╗  ██╗██████╗ ██████╗  ██████╗ ██████╗ ███████╗  ║
    ║     ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝  ║
    ║     ██║  ██║███████║██████╔╝█████╔╝ ██████╔╝██████╔╝██║   ██║██████╔╝█████╗    ║
    ║     ██║  ██║██╔══██║██╔══██╗██╔═██╗ ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝    ║
    ║     ██████╔╝██║  ██║██║  ██║██║  ██╗██║     ██║  ██║╚██████╔╝██████╔╝███████╗  ║
    ║     ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝  ║
    ║                                                              ║
    ║          ⚡ Intelligent Attack Surface Analysis Engine ⚡     ║
    ║                        v1.0.0                                ║
    ╚══════════════════════════════════════════════════════════════╝
    """

    def __init__(self, log_dir: str = "logs", log_file: str = "darkprobe.log"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger("darkprobe")
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()

        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(DarkProbeFormatter(use_color=True))
        self.logger.addHandler(console_handler)

        # File handler without colors
        file_handler = logging.FileHandler(
            self.log_dir / log_file, mode="a", encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(DarkProbeFormatter(use_color=False))
        self.logger.addHandler(file_handler)

    def print_banner(self):
        """Print the DarkProbe ASCII banner."""
        if COLORAMA_AVAILABLE:
            print(f"{Fore.CYAN}{self.BANNER}{Style.RESET_ALL}")
        else:
            print(self.BANNER)

    def info(self, message: str):
        self.logger.info(message)

    def debug(self, message: str):
        self.logger.debug(message)

    def warning(self, message: str):
        self.logger.warning(message)

    def error(self, message: str):
        self.logger.error(message)

    def critical(self, message: str):
        self.logger.critical(message)

    def scan_start(self, target: str):
        self.info(f"Initializing DarkProbe scan against: {target}")

    def scan_complete(self, vuln_count: int, duration: float):
        self.info(
            f"Scan completed. Found {vuln_count} vulnerability(ies) in {duration:.2f}s"
        )

    def vulnerability_found(self, vuln_type: str, url: str, severity: str):
        severity_upper = severity.upper()
        if COLORAMA_AVAILABLE:
            color_map = {
                "HIGH": Fore.RED + Style.BRIGHT,
                "MEDIUM": Fore.YELLOW,
                "LOW": Fore.CYAN,
            }
            color = color_map.get(severity_upper, Fore.WHITE)
            msg = f"[VULNERABLE] {vuln_type} detected at {url} [Severity: {severity_upper}]"
        else:
            msg = f"[VULNERABLE] {vuln_type} detected at {url} [Severity: {severity_upper}]"
        self.logger.warning(msg)

    def module_start(self, module_name: str):
        self.info(f"Starting module: {module_name}")

    def module_complete(self, module_name: str, findings: int):
        self.info(f"Module {module_name} completed with {findings} finding(s)")

    def crawl_found(self, url: str):
        self.debug(f"Discovered URL: {url}")

    def crawl_form(self, action: str, method: str):
        self.debug(f"Discovered form: action={action}, method={method}")


# Global logger instance
logger = ScanEventLogger()
