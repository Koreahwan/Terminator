#!/usr/bin/env python3
"""Raw endpoint inventory helpers."""

from __future__ import annotations

from collections import OrderedDict

from .models import SurfaceItem


def dedupe_preserve(items: list[SurfaceItem]) -> list[SurfaceItem]:
    by_key: OrderedDict[tuple[str, str, tuple[str, ...]], SurfaceItem] = OrderedDict()
    for idx, item in enumerate(items, start=1):
        item.raw_rank = item.raw_rank or idx
        key = (item.method.upper(), item.url or item.path, tuple(sorted(item.params)))
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = item
            continue
        sources = sorted({existing.source, item.source})
        existing.source = "+".join(source for source in sources if source)
        existing.params = sorted(set(existing.params) | set(item.params))
        existing.body_fields = sorted(set(existing.body_fields) | set(item.body_fields))
        if existing.status_code is None:
            existing.status_code = item.status_code
        if existing.auth_hint == "unknown" and item.auth_hint != "unknown":
            existing.auth_hint = item.auth_hint
    return list(by_key.values())
