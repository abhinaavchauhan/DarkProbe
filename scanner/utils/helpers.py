"""
DarkProbe Utility Helpers
=========================
URL manipulation, validation, payload loading, and shared utility functions.
"""

import os
import re
from pathlib import Path
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs, urlencode
from typing import List, Dict, Optional, Tuple


def validate_url(url: str) -> Optional[str]:
    """
    Validate and normalize a URL.
    Returns the normalized URL or None if invalid.
    """
    url = url.strip()

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None

        # Rebuild clean URL
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            parsed.query,
            ""  # Remove fragment
        ))
        return normalized
    except Exception:
        return None


def is_same_domain(url: str, base_url: str) -> bool:
    """Check if a URL belongs to the same domain as the base URL."""
    try:
        url_domain = urlparse(url).netloc.lower()
        base_domain = urlparse(base_url).netloc.lower()
        return url_domain == base_domain
    except Exception:
        return False


def normalize_url(url: str, base_url: str) -> Optional[str]:
    """Resolve a potentially relative URL against a base URL."""
    try:
        resolved = urljoin(base_url, url)
        parsed = urlparse(resolved)
        # Remove fragments
        clean = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            ""
        ))
        return clean
    except Exception:
        return None


def extract_domain(url: str) -> str:
    """Extract the domain (netloc) from a URL."""
    return urlparse(url).netloc


def extract_path(url: str) -> str:
    """Extract the path component from a URL."""
    return urlparse(url).path


def get_query_params(url: str) -> Dict[str, List[str]]:
    """Extract query parameters from a URL."""
    return parse_qs(urlparse(url).query)


def inject_payload_into_url(url: str, payload: str) -> List[str]:
    """
    Inject a payload into each GET parameter of a URL.
    Returns a list of URLs, each with one parameter replaced by the payload.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        return []

    injected_urls = []
    for param_name in params:
        modified_params = dict(params)
        modified_params[param_name] = [payload]
        new_query = urlencode(modified_params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            ""
        ))
        injected_urls.append(new_url)

    return injected_urls


def load_payloads(filepath: str) -> List[str]:
    """
    Load payloads from a text file (one payload per line).
    Skips blank lines and comments (lines starting with #).
    """
    payloads = []
    path = Path(filepath)

    if not path.exists():
        return payloads

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    payloads.append(line)
    except Exception:
        pass

    return payloads


def get_payload_path(payload_type: str) -> str:
    """Get the full path to a payload file by type (sqli, xss, dirs)."""
    base_dir = Path(__file__).resolve().parent.parent.parent / "payloads"
    return str(base_dir / f"{payload_type}.txt")


def sanitize_input(value: str) -> str:
    """Basic input sanitization to remove dangerous metacharacters for logging."""
    # Remove control characters
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)


def truncate_string(s: str, max_length: int = 200) -> str:
    """Truncate a string to max length with ellipsis."""
    if len(s) <= max_length:
        return s
    return s[:max_length] + "..."


def format_duration(seconds: float) -> str:
    """Format seconds into a human-readable duration string."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m {secs:.2f}s"


def get_severity_color(severity: str) -> str:
    """Return CSS color class for severity level."""
    severity_colors = {
        "high": "#ff4444",
        "medium": "#ffaa00",
        "low": "#44aaff",
        "info": "#888888",
    }
    return severity_colors.get(severity.lower(), "#888888")


# Common port-to-service mapping
PORT_SERVICE_MAP: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    27017: "MongoDB",
}
