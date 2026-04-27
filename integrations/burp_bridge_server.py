#!/usr/bin/env python3
"""Passive Burp metadata bridge for Terminator.

The bridge accepts scoped request/response metadata only. It does not replay,
modify, or actively scan traffic.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "csrf-token",
}
SESSION_HEADER_MARKERS = ("session", "token", "secret", "csrf", "xsrf", "auth")
DEFAULT_MAX_PAYLOAD_BYTES = 64 * 1024
SENSITIVE_QUERY_MARKERS = (
    "access_token",
    "auth",
    "bearer",
    "code",
    "cookie",
    "csrf",
    "jwt",
    "key",
    "password",
    "refresh_token",
    "secret",
    "session",
    "sid",
    "token",
)


def redact_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    redacted: dict[str, str] = {}
    for key, value in (headers or {}).items():
        lowered = str(key).lower()
        if lowered in SENSITIVE_HEADERS or any(marker in lowered for marker in SESSION_HEADER_MARKERS):
            redacted[str(key)] = "[REDACTED]"
        else:
            redacted[str(key)] = str(value)
    return redacted


def scope_host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def is_allowed_url(url: str, allowed_hosts: set[str]) -> bool:
    host = scope_host(url)
    normalized = {h.lower().rstrip(".") for h in allowed_hosts}
    return bool(host) and host in normalized


def redact_url_query(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    pairs = []
    changed = False
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        lowered = key.lower()
        if any(marker in lowered for marker in SENSITIVE_QUERY_MARKERS):
            pairs.append((key, "[REDACTED]"))
            changed = True
        else:
            pairs.append((key, value))
    if not changed:
        return url
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


def sanitize_observation(payload: dict[str, Any], *, allowed_hosts: set[str]) -> tuple[int, dict[str, Any]]:
    url = str(payload.get("url") or "")
    if not is_allowed_url(url, allowed_hosts):
        return 403, {"error": "out_of_scope"}
    method = str(payload.get("method") or "GET").upper()
    status_code = payload.get("status_code")
    body_length = payload.get("body_length")
    observation = {
        "source": "burp",
        "method": method,
        "url": redact_url_query(url),
        "status_code": int(status_code) if type(status_code) is int else None,
        "request_headers": redact_headers(payload.get("request_headers") or {}),
        "response_headers": redact_headers(payload.get("response_headers") or {}),
        "body_saved": False,
        "body_length": int(body_length) if type(body_length) is int else None,
        "content_type": str(payload.get("content_type") or ""),
        "timestamp": str(payload.get("timestamp") or datetime.now(timezone.utc).isoformat()),
    }
    return 200, observation


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def build_handler(*, allowed_hosts: set[str], out_path: Path, max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES):
    class BurpBridgeHandler(BaseHTTPRequestHandler):
        server_version = "TerminatorBurpBridge/1.0"

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/burp/observe":
                self._send_json(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                self._send_json(400, {"error": "invalid_content_length"})
                return
            if length <= 0 or length > max_payload_bytes:
                self._send_json(413, {"error": "payload_too_large"})
                return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
            except json.JSONDecodeError:
                self._send_json(400, {"error": "invalid_json"})
                return
            if not isinstance(payload, dict):
                self._send_json(400, {"error": "invalid_payload"})
                return
            status, sanitized = sanitize_observation(payload, allowed_hosts=allowed_hosts)
            if status == 200:
                append_jsonl(out_path, sanitized)
                self._send_json(200, {"status": "stored"})
            else:
                self._send_json(status, sanitized)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    return BurpBridgeHandler


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="Bind host. Defaults to localhost only.")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--scope-host", action="append", required=True, help="Allowed exact host. Repeat for multiple hosts.")
    parser.add_argument("--out", default="recon_output/burp_stream.jsonl")
    parser.add_argument("--max-payload-bytes", type=int, default=DEFAULT_MAX_PAYLOAD_BYTES)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.host not in {"127.0.0.1", "localhost"}:
        print("Refusing non-local bind host by default. Use a local tunnel/proxy if needed.", flush=True)
        return 2
    handler = build_handler(
        allowed_hosts=set(args.scope_host or []),
        out_path=Path(args.out),
        max_payload_bytes=args.max_payload_bytes,
    )
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"burp bridge listening on http://{args.host}:{args.port}/burp/observe", flush=True)
    print(f"writing scoped redacted metadata to {args.out}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
