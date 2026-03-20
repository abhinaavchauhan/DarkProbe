"""
DarkProbe HTTP Requester
========================
Handles all HTTP interactions with rate limiting, retries, 
and session management. Acts as the network layer for all modules.
"""

import time
import random
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any
from scanner.utils.logger import logger


class Requester:
    """
    Thread-safe HTTP requester with rate limiting, retries,
    custom headers, and configurable timeouts.
    """

    DEFAULT_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }

    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 2,
        delay: float = 0.0,
        verify_ssl: bool = False,
        custom_headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
    ):
        self.timeout = timeout
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.request_count = 0

        # Build session with retry strategy
        self.session = requests.Session()

        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD"],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set headers
        headers = dict(self.DEFAULT_HEADERS)
        if custom_headers:
            headers.update(custom_headers)
        self.session.headers.update(headers)

        # Set proxy
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        # Suppress SSL warnings
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _rate_limit(self):
        """Apply rate limiting delay between requests."""
        if self.delay > 0:
            jitter = random.uniform(0, self.delay * 0.3)
            time.sleep(self.delay + jitter)

    def get(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> Optional[requests.Response]:
        """
        Perform a GET request with error handling.
        Returns Response object or None on failure.
        """
        self._rate_limit()
        self.request_count += 1

        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=allow_redirects,
            )
            logger.debug(f"GET {url} → {response.status_code}")
            return response
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout on GET {url}")
            return None
        except requests.exceptions.ConnectionError:
            logger.debug(f"Connection error on GET {url}")
            return None
        except requests.exceptions.TooManyRedirects:
            logger.debug(f"Too many redirects on GET {url}")
            return None
        except Exception as e:
            logger.debug(f"Request error on GET {url}: {str(e)}")
            return None

    def post(
        self,
        url: str,
        data: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        allow_redirects: bool = True,
    ) -> Optional[requests.Response]:
        """
        Perform a POST request with error handling.
        Returns Response object or None on failure.
        """
        self._rate_limit()
        self.request_count += 1

        try:
            response = self.session.post(
                url,
                data=data,
                json=json_data,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=allow_redirects,
            )
            logger.debug(f"POST {url} → {response.status_code}")
            return response
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout on POST {url}")
            return None
        except requests.exceptions.ConnectionError:
            logger.debug(f"Connection error on POST {url}")
            return None
        except requests.exceptions.TooManyRedirects:
            logger.debug(f"Too many redirects on POST {url}")
            return None
        except Exception as e:
            logger.debug(f"Request error on POST {url}: {str(e)}")
            return None

    def head(self, url: str) -> Optional[requests.Response]:
        """Perform a HEAD request (useful for checking URL existence)."""
        self._rate_limit()
        self.request_count += 1

        try:
            response = self.session.head(
                url, timeout=self.timeout, verify=self.verify_ssl
            )
            return response
        except Exception:
            return None

    def get_response_time(self, url: str) -> Optional[float]:
        """Measure response time for a URL."""
        try:
            start = time.time()
            self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            return time.time() - start
        except Exception:
            return None

    def close(self):
        """Close the session and release resources."""
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
