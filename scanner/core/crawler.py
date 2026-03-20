"""
DarkProbe Recon Engine (Crawler)
================================
Intelligent web crawler that discovers internal links and forms.
Handles relative URLs, avoids duplicate crawling, and respects depth limits.
"""

from urllib.parse import urlparse, urljoin
from typing import List, Set, Dict, Optional, Tuple
from dataclasses import dataclass, field
from bs4 import BeautifulSoup

from scanner.core.requester import Requester
from scanner.utils.logger import logger
from scanner.utils.helpers import is_same_domain, normalize_url


@dataclass
class FormData:
    """Represents an HTML form discovered during crawling."""
    url: str
    action: str
    method: str
    inputs: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs,
        }


@dataclass
class CrawlResult:
    """Complete result of a crawl session."""
    urls: Set[str] = field(default_factory=set)
    forms: List[FormData] = field(default_factory=list)
    urls_with_params: Set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "urls": list(self.urls),
            "forms": [f.to_dict() for f in self.forms],
            "urls_with_params": list(self.urls_with_params),
        }


class Crawler:
    """
    DarkProbe Recon Engine — Intelligent web crawler.
    
    Discovers:
    - Internal links (same-domain)
    - HTML forms (GET and POST)
    - URLs with query parameters (potential injection points)
    """

    # File extensions to skip
    SKIP_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".zip", ".tar", ".gz", ".rar",
        ".mp3", ".mp4", ".avi", ".mov",
        ".css", ".woff", ".woff2", ".ttf", ".eot",
    }

    def __init__(
        self,
        requester: Requester,
        max_depth: int = 3,
        max_urls: int = 100,
    ):
        self.requester = requester
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited: Set[str] = set()
        self.result = CrawlResult()

    def _should_skip(self, url: str) -> bool:
        """Check if a URL should be skipped."""
        parsed = urlparse(url)
        path = parsed.path.lower()

        # Skip non-HTTP schemes
        if parsed.scheme not in ("http", "https", ""):
            return True

        # Skip static file extensions
        for ext in self.SKIP_EXTENSIONS:
            if path.endswith(ext):
                return True

        # Skip already visited
        if url in self.visited:
            return True

        # Skip if we've hit the URL limit
        if len(self.visited) >= self.max_urls:
            return True

        return False

    def _extract_links(self, html: str, base_url: str) -> Set[str]:
        """Extract and normalize all internal links from HTML."""
        links = set()
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue

                full_url = normalize_url(href, base_url)
                if full_url and is_same_domain(full_url, base_url):
                    if not self._should_skip(full_url):
                        links.add(full_url)
        except Exception as e:
            logger.debug(f"Error extracting links: {e}")

        return links

    def _extract_forms(self, html: str, page_url: str) -> List[FormData]:
        """Extract all forms from an HTML page."""
        forms = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for form_tag in soup.find_all("form"):
                action = form_tag.get("action", "")
                method = form_tag.get("method", "get").upper()

                # Resolve form action URL
                if action:
                    action_url = normalize_url(action, page_url) or page_url
                else:
                    action_url = page_url

                # Extract form inputs
                inputs = []
                for input_tag in form_tag.find_all(["input", "textarea", "select"]):
                    input_data = {
                        "name": input_tag.get("name", ""),
                        "type": input_tag.get("type", "text"),
                        "value": input_tag.get("value", ""),
                    }
                    if input_data["name"]:
                        inputs.append(input_data)

                form = FormData(
                    url=page_url,
                    action=action_url,
                    method=method,
                    inputs=inputs,
                )
                forms.append(form)
                logger.crawl_form(action_url, method)

        except Exception as e:
            logger.debug(f"Error extracting forms: {e}")

        return forms

    def crawl(self, start_url: str, current_depth: int = 0) -> CrawlResult:
        """
        Recursively crawl a website starting from a URL.
        
        Args:
            start_url: The URL to start crawling from
            current_depth: Current recursion depth
            
        Returns:
            CrawlResult containing discovered URLs, forms, and parameterized URLs
        """
        if current_depth > self.max_depth:
            return self.result

        if self._should_skip(start_url):
            return self.result

        self.visited.add(start_url)
        self.result.urls.add(start_url)
        logger.crawl_found(start_url)

        # Check if URL has query parameters
        if "?" in start_url and "=" in start_url:
            self.result.urls_with_params.add(start_url)

        # Fetch page
        response = self.requester.get(start_url)
        if not response or not response.text:
            return self.result

        html = response.text

        # Extract forms
        forms = self._extract_forms(html, start_url)
        self.result.forms.extend(forms)

        # Extract and crawl links
        links = self._extract_links(html, start_url)
        for link in links:
            if len(self.visited) >= self.max_urls:
                logger.info(f"Reached maximum URL limit ({self.max_urls})")
                break
            self.crawl(link, current_depth + 1)

        return self.result

    def get_stats(self) -> Dict[str, int]:
        """Return crawl statistics."""
        return {
            "urls_found": len(self.result.urls),
            "forms_found": len(self.result.forms),
            "urls_with_params": len(self.result.urls_with_params),
            "visited": len(self.visited),
        }
