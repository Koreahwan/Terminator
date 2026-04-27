#!/usr/bin/env python3
"""Normalize recon artifacts into SurfaceItem objects."""

from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .models import SurfaceItem
from .raw_inventory import dedupe_preserve

URL_RE = re.compile(r"https?://[^\s\"'<>|]+", re.I)
PATH_RE = re.compile(r"(?<![\w])/(?:api/)?[A-Za-z0-9._~!$&'()*+,;=:@/%?-]+")
PATH_PARAM_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}|:([A-Za-z_][A-Za-z0-9_]*)")
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _params_from_url(url: str) -> list[str]:
    params: set[str] = set()
    try:
        parts = urlsplit(url)
        params.update(k for k, _ in parse_qsl(parts.query, keep_blank_values=True))
        params.update(_params_from_path(parts.path or url))
    except ValueError:
        params.update(_params_from_path(url))
    return sorted(params)


def _params_from_path(path: str) -> set[str]:
    params: set[str] = set()
    for match in PATH_PARAM_RE.finditer(path):
        params.add(match.group(1) or match.group(2))
    return params


def _path_from_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        return parts.path or "/"
    except ValueError:
        return url


def _item_from_url(url: str, *, source: str, rank: int = 0, method: str = "GET") -> SurfaceItem:
    return SurfaceItem(method=method.upper(), url=url, path=_path_from_url(url), params=_params_from_url(url), source=source, raw_rank=rank)


def load_inputs(paths: list[Path], *, endpoint_map: Path | None = None) -> list[SurfaceItem]:
    items: list[SurfaceItem] = []
    if endpoint_map:
        items.extend(parse_endpoint_map(endpoint_map))
    for path in paths:
        if not path.exists():
            continue
        lowered = path.name.lower()
        if lowered.endswith(".json") or lowered.endswith(".har"):
            items.extend(parse_json_file(path))
        elif lowered.endswith(".xml"):
            items.extend(parse_burp_xml(path))
        elif lowered.endswith((".yaml", ".yml")):
            items.extend(parse_text_file(path, source="yaml"))
        elif "endpoint_map" in lowered or lowered.endswith(".md"):
            items.extend(parse_endpoint_map(path))
        else:
            items.extend(parse_text_file(path, source=path.stem))
    return dedupe_preserve(items)


def parse_text_file(path: Path, *, source: str | None = None) -> list[SurfaceItem]:
    text = path.read_text(encoding="utf-8", errors="replace")
    output: list[SurfaceItem] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        method = "GET"
        parts = stripped.split()
        if parts and parts[0].upper() in METHODS and len(parts) > 1:
            method = parts[0].upper()
            candidate = parts[1]
        else:
            url_match = URL_RE.search(stripped)
            match = url_match or PATH_RE.search(stripped)
            candidate = match.group(0) if match else stripped
        candidate = candidate.rstrip(".,)")
        if candidate.startswith("/") or candidate.startswith("http"):
            output.append(SurfaceItem(method=method, url=candidate if candidate.startswith("http") else "", path=_path_from_url(candidate), params=_params_from_url(candidate), source=source or path.stem, raw_rank=idx, notes=stripped[:300]))
    return output


def parse_endpoint_map(path: Path) -> list[SurfaceItem]:
    text = path.read_text(encoding="utf-8", errors="replace")
    items: list[SurfaceItem] = []
    headers: list[str] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or "|" not in stripped:
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if set(cells[0]) <= {"-", ":"}:
            continue
        upper = [cell.upper() for cell in cells]
        if "ENDPOINT" in upper or "PATH" in upper or "URL" in upper:
            headers = upper
            continue
        endpoint_idx = headers.index("ENDPOINT") if "ENDPOINT" in headers else 0
        method_idx = headers.index("METHOD") if "METHOD" in headers else 1 if len(cells) > 1 and cells[1].upper() in METHODS else -1
        auth_idx = headers.index("AUTH") if "AUTH" in headers else -1
        status_idx = headers.index("STATUS") if "STATUS" in headers else -1
        endpoint = cells[endpoint_idx] if endpoint_idx < len(cells) else cells[0]
        method = cells[method_idx].upper() if method_idx >= 0 and method_idx < len(cells) and cells[method_idx].upper() in METHODS else "GET"
        auth = cells[auth_idx] if auth_idx >= 0 and auth_idx < len(cells) else "unknown"
        status_code = None
        if status_idx >= 0 and status_idx < len(cells):
            m = re.search(r"\b(\d{3})\b", cells[status_idx])
            status_code = int(m.group(1)) if m else None
        if endpoint.startswith("http"):
            items.append(_item_from_url(endpoint, source="endpoint_map", rank=idx, method=method))
            items[-1].auth_hint = auth
            items[-1].status_code = status_code
        elif endpoint.startswith("/"):
            items.append(SurfaceItem(method=method, path=endpoint, params=_params_from_url(endpoint), source="endpoint_map", raw_rank=idx, auth_hint=auth, status_code=status_code, notes=stripped[:300]))
    if items:
        return items
    return parse_text_file(path, source="endpoint_map")


def parse_json_file(path: Path) -> list[SurfaceItem]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return parse_text_file(path, source=path.stem)
    if isinstance(data, dict) and "log" in data and isinstance(data["log"], dict):
        return parse_har(data)
    if _looks_like_openapi(data):
        return parse_openapi(data, source="openapi")
    if _looks_like_postman(data):
        return parse_postman(data)
    items: list[SurfaceItem] = []
    _walk_json(data, items, source=path.stem)
    return items


def _walk_json(value: Any, items: list[SurfaceItem], *, source: str, method: str = "GET") -> None:
    if isinstance(value, dict):
        local_method = str(value.get("method") or value.get("httpMethod") or method).upper()
        for key in ("url", "uri", "endpoint", "path", "target"):
            if key in value and isinstance(value[key], str):
                candidate = value[key]
                if candidate.startswith("http"):
                    items.append(_item_from_url(candidate, source=source, method=local_method))
                elif candidate.startswith("/"):
                    items.append(SurfaceItem(method=local_method if local_method in METHODS else "GET", path=candidate, params=_params_from_url(candidate), source=source))
        for child in value.values():
            _walk_json(child, items, source=source, method=local_method)
    elif isinstance(value, list):
        for child in value:
            _walk_json(child, items, source=source, method=method)
    elif isinstance(value, str):
        for match in URL_RE.finditer(value):
            items.append(_item_from_url(match.group(0).rstrip(".,)"), source=source, method=method))


def _looks_like_openapi(data: Any) -> bool:
    return isinstance(data, dict) and isinstance(data.get("paths"), dict) and ("openapi" in data or "swagger" in data)


def parse_openapi(data: dict[str, Any], *, source: str) -> list[SurfaceItem]:
    items: list[SurfaceItem] = []
    for path, methods in data.get("paths", {}).items():
        if not isinstance(methods, dict):
            continue
        for method, spec in methods.items():
            if method.upper() not in METHODS:
                continue
            params: set[str] = set()
            body_fields: set[str] = set()
            if isinstance(spec, dict):
                for param in spec.get("parameters", []) or []:
                    if isinstance(param, dict) and param.get("name"):
                        params.add(str(param["name"]))
                request_body = spec.get("requestBody", {})
                body_fields.update(_schema_fields(request_body))
            items.append(SurfaceItem(method=method.upper(), path=path, params=sorted(params), body_fields=sorted(body_fields), source=source))
    return items


def _schema_fields(value: Any) -> set[str]:
    fields: set[str] = set()
    if isinstance(value, dict):
        props = value.get("properties")
        if isinstance(props, dict):
            fields.update(str(k) for k in props)
        for child in value.values():
            fields.update(_schema_fields(child))
    elif isinstance(value, list):
        for child in value:
            fields.update(_schema_fields(child))
    return fields


def _looks_like_postman(data: Any) -> bool:
    return isinstance(data, dict) and "item" in data and isinstance(data.get("info"), dict)


def parse_postman(data: dict[str, Any]) -> list[SurfaceItem]:
    items: list[SurfaceItem] = []

    def walk(entries: list[Any]) -> None:
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if "item" in entry:
                walk(entry.get("item") or [])
                continue
            req = entry.get("request")
            if not isinstance(req, dict):
                continue
            method = str(req.get("method") or "GET").upper()
            raw_url = req.get("url")
            if isinstance(raw_url, dict):
                url = raw_url.get("raw") or "/" + "/".join(raw_url.get("path") or [])
                params = [q.get("key") for q in raw_url.get("query", []) if isinstance(q, dict) and q.get("key")]
            else:
                url = str(raw_url or "")
                params = _params_from_url(url)
            if url.startswith("http"):
                item = _item_from_url(url, source="postman", method=method)
            else:
                item = SurfaceItem(method=method, path=url if url.startswith("/") else f"/{url}", params=sorted(set(params)), source="postman")
            items.append(item)

    walk(data.get("item") or [])
    return items


def parse_har(data: dict[str, Any]) -> list[SurfaceItem]:
    items: list[SurfaceItem] = []
    for entry in data.get("log", {}).get("entries", []) or []:
        req = entry.get("request", {}) if isinstance(entry, dict) else {}
        resp = entry.get("response", {}) if isinstance(entry, dict) else {}
        url = req.get("url")
        if not isinstance(url, str):
            continue
        item = _item_from_url(url, source="har", method=str(req.get("method") or "GET"))
        item.status_code = int(resp.get("status")) if isinstance(resp.get("status"), int) else None
        items.append(item)
    return items


def parse_burp_xml(path: Path) -> list[SurfaceItem]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return parse_text_file(path, source="burp")
    items: list[SurfaceItem] = []
    for node in root.findall(".//item"):
        url = (node.findtext("url") or "").strip()
        method = (node.findtext("method") or "GET").strip().upper()
        status_text = (node.findtext("status") or "").strip()
        if not url:
            request = node.findtext("request") or ""
            if node.find("request") is not None and node.find("request").get("base64") == "true":
                try:
                    request = base64.b64decode(request).decode("utf-8", errors="replace")
                except Exception:
                    request = ""
            m = re.search(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)", request, re.M)
            if m:
                method, url = m.group(1), m.group(2)
        if not url:
            continue
        item = _item_from_url(url, source="burp", method=method)
        item.status_code = int(status_text) if status_text.isdigit() else None
        items.append(item)
    return items
