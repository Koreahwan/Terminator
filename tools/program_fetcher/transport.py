"""HTTP transport for program fetchers.

Stdlib only (urllib + gzip). Keeps a polite, identifiable UA so rate-limiters
on HackerOne / Bugcrowd / Immunefi can throttle us cleanly instead of blocking.

Retries on 429/5xx with exponential backoff.
Surfaces 4xx as TransportError so handlers can decide whether to fall back.
"""

from __future__ import annotations

import gzip
import json
import time
import urllib.error
import urllib.request
from typing import Any, Optional


DEFAULT_UA = (
    "Terminator-ProgramFetcher/1.0 "
    "(+https://github.com/R00T-Kim/Terminator; authorized security research)"
)
DEFAULT_TIMEOUT = 20.0  # seconds
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 1.5


class TransportError(Exception):
    """Raised when a GET fails after all retries or returns a hard 4xx."""

    def __init__(self, url: str, status: int, message: str):
        self.url = url
        self.status = status
        self.message = message
        super().__init__(f"{status} {url}: {message}")


def http_get(
    url: str,
    *,
    accept: str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    headers: Optional[dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    backoff: float = DEFAULT_BACKOFF,
    ua: str = DEFAULT_UA,
) -> tuple[int, str, dict[str, str]]:
    """GET a URL. Returns (status, body_text, response_headers).

    Raises TransportError on non-retryable 4xx or after all retries exhausted
    on 429/5xx. Network errors (DNS, connection refused, read timeout) also
    raise TransportError after retries.
    """
    req_headers = {
        "User-Agent": ua,
        "Accept": accept,
        "Accept-Encoding": "gzip",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if headers:
        req_headers.update(headers)

    last_error: Optional[str] = None
    last_status = 0

    for attempt in range(retries + 1):
        req = urllib.request.Request(url, headers=req_headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding", "").lower() == "gzip":
                    raw = gzip.decompress(raw)
                charset = _extract_charset(resp.headers.get("Content-Type", ""))
                body = raw.decode(charset, errors="replace")
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status, body, resp_headers
        except urllib.error.HTTPError as e:
            status = e.code
            last_status = status
            try:
                raw = e.read()
                if e.headers.get("Content-Encoding", "").lower() == "gzip":
                    raw = gzip.decompress(raw)
                body = raw.decode("utf-8", errors="replace")
            except Exception:
                body = ""
            # 429 or 5xx: retryable.
            if status == 429 or (500 <= status <= 599):
                last_error = f"HTTP {status}: retrying"
                _sleep_backoff(attempt, backoff)
                continue
            # 4xx non-429: hard fail, let caller decide to fall back.
            raise TransportError(url, status, body[:500] or str(e)) from e
        except urllib.error.URLError as e:
            last_error = f"URLError: {e.reason}"
            _sleep_backoff(attempt, backoff)
            continue
        except (TimeoutError, OSError) as e:
            last_error = f"{type(e).__name__}: {e}"
            _sleep_backoff(attempt, backoff)
            continue

    raise TransportError(
        url,
        last_status,
        last_error or "all retries exhausted",
    )


def http_post_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: Optional[dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    backoff: float = DEFAULT_BACKOFF,
    ua: str = DEFAULT_UA,
) -> tuple[int, str, dict[str, str]]:
    """POST a JSON body. Same retry + error semantics as http_get."""
    req_headers = {
        "User-Agent": ua,
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/json",
    }
    if headers:
        req_headers.update(headers)
    body_bytes = json.dumps(payload).encode("utf-8")

    last_error: Optional[str] = None
    last_status = 0

    for attempt in range(retries + 1):
        req = urllib.request.Request(
            url, data=body_bytes, headers=req_headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding", "").lower() == "gzip":
                    raw = gzip.decompress(raw)
                charset = _extract_charset(resp.headers.get("Content-Type", ""))
                body = raw.decode(charset, errors="replace")
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status, body, resp_headers
        except urllib.error.HTTPError as e:
            status = e.code
            last_status = status
            try:
                raw = e.read()
                body = raw.decode("utf-8", errors="replace")
            except Exception:
                body = ""
            if status == 429 or (500 <= status <= 599):
                last_error = f"HTTP {status}: retrying"
                _sleep_backoff(attempt, backoff)
                continue
            raise TransportError(url, status, body[:500] or str(e)) from e
        except urllib.error.URLError as e:
            last_error = f"URLError: {e.reason}"
            _sleep_backoff(attempt, backoff)
            continue
        except (TimeoutError, OSError) as e:
            last_error = f"{type(e).__name__}: {e}"
            _sleep_backoff(attempt, backoff)
            continue

    raise TransportError(
        url,
        last_status,
        last_error or "all retries exhausted",
    )


def _sleep_backoff(attempt: int, base: float) -> None:
    delay = base ** (attempt + 1)
    # Cap at 10s so a 3-retry loop never blocks longer than ~20s total.
    time.sleep(min(delay, 10.0))


def _extract_charset(content_type: str) -> str:
    """Pull charset from a Content-Type header; default utf-8."""
    if not content_type:
        return "utf-8"
    for part in content_type.split(";"):
        part = part.strip().lower()
        if part.startswith("charset="):
            return part.split("=", 1)[1].strip() or "utf-8"
    return "utf-8"
