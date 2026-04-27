"""Dispatch a program URL to the right platform handler.

Walks the handler chain in `HANDLERS` order: platform-specific first, then
generic as fallback. Returns the first FetchResult whose confidence clears
PASS_THRESHOLD, or the highest-confidence result if none pass (HOLD).

Each handler is a callable `(url) -> ProgramData` (raises on unrecoverable
error). The dispatcher catches exceptions, records them in
`handlers_tried`, and moves on.
"""

from __future__ import annotations

import datetime
import traceback
from typing import Callable
from urllib.parse import urlparse

from .base import (
    FetchResult,
    ProgramData,
    PASS,
    HOLD,
    FAIL,
    PASS_THRESHOLD,
    HOLD_THRESHOLD,
)


HandlerFn = Callable[[str], ProgramData]


def detect_platform(url: str) -> str:
    """Return canonical platform name from URL, or 'generic' if unknown."""
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        return "generic"
    if not host:
        return "generic"

    # Normalize www. prefix.
    if host.startswith("www."):
        host = host[4:]

    if host.endswith("hackerone.com"):
        return "hackerone"
    if host.endswith("bugcrowd.com"):
        return "bugcrowd"
    if host.endswith("immunefi.com"):
        return "immunefi"
    if host.endswith("intigriti.com") or host == "app.intigriti.com":
        return "intigriti"
    if host.endswith("yeswehack.com"):
        return "yeswehack"
    if host.endswith("hackenproof.com"):
        return "hackenproof"
    if host.endswith("huntr.com") or host.endswith("huntr.dev"):
        return "huntr"
    if host == "github.com" or host.endswith(".github.com") or host.endswith("githubusercontent.com"):
        return "github_md"
    if host.endswith("hckrt.com") or host.endswith("hackrate.com"):
        return "hackrate"
    if host.endswith("compass-security.com"):
        return "compass"
    if host.endswith("inspectiv.com"):
        return "inspectiv"
    if host.endswith("yogosha.com"):
        return "yogosha"
    if host.endswith("cobalt.io"):
        return "cobalt"
    if host.endswith("synack.com"):
        return "synack"
    if host.endswith("gobugfree.com"):
        return "gobugfree"
    if host.endswith("patchday.io"):
        return "patchday"
    if host.endswith("findthegap.co.kr"):
        return "findthegap"
    return "generic"


def _handler_order(platform: str) -> list[str]:
    """Return the ordered list of handler names to try for a given platform.

    Platform-specific handler first, then generic as a last resort. We never
    try the *wrong* platform handler — if detect_platform returns "hackerone"
    we do NOT try bugcrowd.
    """
    if platform == "generic":
        return ["generic"]
    return [platform, "generic"]


def _load_handlers() -> dict[str, HandlerFn]:
    """Import handlers lazily. Missing handlers map to a stub that raises.

    This lets dispatch.py be importable even before all platform files are
    implemented (useful during development and for the stub phase of the
    skeleton).
    """
    handlers: dict[str, HandlerFn] = {}

    def _try_import(name: str, attr: str = "fetch") -> None:
        try:
            mod = __import__(
                f"tools.program_fetcher.{name}", fromlist=[attr]
            )
            fn = getattr(mod, attr, None)
            if callable(fn):
                handlers[name] = fn
        except Exception:
            # Handler file missing or broken — skip. dispatch.fetch will
            # log it in handlers_tried.
            pass

    for name in (
        "hackerone",
        "bugcrowd",
        "immunefi",
        "intigriti",
        "yeswehack",
        "hackenproof",
        "huntr",
        "github_md",
        "hackrate",
        "compass",
        "inspectiv",
        "yogosha",
        "cobalt",
        "synack",
        "gobugfree",
        "patchday",
        "findthegap",
        "generic",
    ):
        _try_import(name)
    return handlers


def fetch(url: str, *, use_cache: bool = True, cache_dir: str = "") -> FetchResult:
    """Dispatch `url` through platform handlers and return a FetchResult.

    `use_cache` / `cache_dir` are honored by the cache layer (cache.py);
    dispatch itself doesn't touch disk.
    """
    # Cache check up front.
    cached: FetchResult | None = None
    if use_cache and cache_dir:
        try:
            from .cache import load as cache_load  # noqa: WPS433
            cached = cache_load(url, cache_dir)
        except Exception:
            cached = None
    if cached is not None:
        return cached

    platform = detect_platform(url)
    handler_names = _handler_order(platform)
    handlers = _load_handlers()

    tried: list[dict] = []
    best: ProgramData | None = None
    best_confidence = 0.0

    for name in handler_names:
        fn = handlers.get(name)
        if fn is None:
            tried.append(
                {"handler": name, "status": "not_implemented", "confidence": 0.0}
            )
            continue
        try:
            data = fn(url)
        except Exception as e:
            tried.append(
                {
                    "handler": name,
                    "status": "exception",
                    "error": f"{type(e).__name__}: {e}",
                    "trace": traceback.format_exc(limit=2),
                    "confidence": 0.0,
                }
            )
            continue

        conf = float(data.confidence or 0.0)
        tried.append(
            {"handler": name, "status": "ok", "confidence": conf}
        )
        if not data.fetched_at:
            data.fetched_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        if not data.source:
            data.source = name
        if conf > best_confidence:
            best = data
            best_confidence = conf
        if conf >= PASS_THRESHOLD:
            break

    # Validate and build the FetchResult.
    from .validator import validate  # local import to avoid cycle

    if best is None:
        # No handler succeeded. Return an empty ProgramData with FAIL.
        empty = ProgramData(platform=platform, program_url=url)
        result = FetchResult(
            data=empty,
            verdict=FAIL,
            confidence=0.0,
            missing_fields=["all"],
            handlers_tried=tried,
            error="no handler succeeded",
        )
        return result

    verdict, confidence, missing, _warnings = validate(best)
    result = FetchResult(
        data=best,
        verdict=verdict,
        confidence=confidence,
        missing_fields=missing,
        handlers_tried=tried,
    )

    # Save to cache if caller provided one.
    if use_cache and cache_dir and verdict in (PASS, HOLD):
        try:
            from .cache import save as cache_save  # noqa: WPS433
            cache_save(url, result, cache_dir)
        except Exception:
            pass

    return result
