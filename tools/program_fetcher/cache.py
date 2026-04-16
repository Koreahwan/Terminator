"""On-disk cache for program_fetcher results.

Cache key = sha1(url). File = <cache_dir>/<sha1>.json.
TTL = 24h by default. `--no-cache` bypasses entirely.

The cache stores the full FetchResult dict so a cold-start Phase 5.7 live
scope re-check can hit the cache and skip the network when the verdict is
still recent.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
from typing import Optional

from .base import Asset, FetchResult, ProgramData, SeverityRow


DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24h


def _key(url: str) -> str:
    return hashlib.sha1(url.encode("utf-8")).hexdigest()


def _path(url: str, cache_dir: str) -> Path:
    return Path(cache_dir) / f"{_key(url)}.json"


def load(url: str, cache_dir: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> Optional[FetchResult]:
    """Return cached FetchResult if present and fresh, else None."""
    p = _path(url, cache_dir)
    if not p.exists():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    cached_at_str = raw.get("_cached_at", "")
    if not cached_at_str:
        return None
    try:
        cached_at = datetime.datetime.strptime(cached_at_str, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    age = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - cached_at).total_seconds()
    if age > ttl_seconds:
        return None
    try:
        data = ProgramData.from_dict(raw["data"])
    except Exception:
        return None
    return FetchResult(
        data=data,
        verdict=raw.get("verdict", "HOLD"),
        confidence=float(raw.get("confidence", 0.0)),
        missing_fields=list(raw.get("missing_fields", [])),
        handlers_tried=list(raw.get("handlers_tried", [])),
        error=raw.get("error", ""),
    )


def save(url: str, result: FetchResult, cache_dir: str) -> None:
    """Persist a FetchResult to the cache directory."""
    p = _path(url, cache_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = result.to_dict()
    payload["_cached_at"] = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload["_cache_key"] = _key(url)
    payload["_url"] = url
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def clear(cache_dir: str) -> int:
    """Delete all cache entries. Returns count of files removed."""
    d = Path(cache_dir)
    if not d.exists():
        return 0
    count = 0
    for f in d.glob("*.json"):
        try:
            f.unlink()
            count += 1
        except OSError:
            continue
    return count
