#!/usr/bin/env python3
"""Multi-channel notification manager — Discord, Telegram, Slack, Email.

AIDA-inspired: pipeline events trigger notifications on configured channels.
"""

from __future__ import annotations

import argparse
import json
import os
import smtplib
import sys
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

CONFIG_PATH = Path(__file__).parent / "notification_config.yaml"

SEVERITY_EMOJI = {
    "CRITICAL": "[!!!]",
    "HIGH": "[!!]",
    "MEDIUM": "[!]",
    "LOW": "[.]",
    "INFO": "[i]",
}


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    import yaml
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f) or {}


def _post_json(url: str, payload: dict, headers: dict | None = None) -> bool:
    data = json.dumps(payload).encode()
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = Request(url, data=data, headers=hdrs, method="POST")
    try:
        resp = urlopen(req, timeout=10)
        return 200 <= resp.status < 300
    except Exception:
        return False


def notify_discord(webhook_url: str, message: str, **kwargs) -> bool:
    return _post_json(webhook_url, {"content": message[:2000]})


def notify_telegram(bot_token: str, chat_id: str, message: str, **kwargs) -> bool:
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    return _post_json(url, {
        "chat_id": chat_id,
        "text": message[:4096],
        "parse_mode": "Markdown",
    })


def notify_slack(webhook_url: str, message: str, **kwargs) -> bool:
    return _post_json(webhook_url, {"text": message[:4000]})


def notify_email(
    smtp_host: str, smtp_port: int, username: str, password: str,
    to_addr: str, message: str, subject: str = "Terminator Alert", **kwargs
) -> bool:
    try:
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = username
        msg["To"] = to_addr
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
        return True
    except Exception:
        return False


CHANNEL_HANDLERS = {
    "discord": notify_discord,
    "telegram": notify_telegram,
    "slack": notify_slack,
    "email": notify_email,
}


def notify(channel: str, message: str, severity: str = "", **extra) -> bool:
    config = _load_config()
    ch_conf = config.get("channels", {}).get(channel, {})
    if not ch_conf:
        print(f"Channel '{channel}' not configured in {CONFIG_PATH}", file=sys.stderr)
        return False
    handler = CHANNEL_HANDLERS.get(channel)
    if not handler:
        print(f"Unknown channel: {channel}", file=sys.stderr)
        return False
    prefix = SEVERITY_EMOJI.get(severity, "")
    full_msg = f"{prefix} {message}" if prefix else message
    return handler(message=full_msg, **ch_conf, **extra)


def notify_all(message: str, severity: str = "", **extra) -> dict[str, bool]:
    config = _load_config()
    results = {}
    for ch_name in config.get("channels", {}):
        results[ch_name] = notify(ch_name, message, severity, **extra)
    return results


def notify_finding(title: str, severity: str, target: str = "", cvss: str = "") -> dict:
    msg = f"*Finding: {title}*\nSeverity: {severity}\nTarget: {target}"
    if cvss:
        msg += f"\nCVSS: {cvss}"
    return notify_all(msg, severity)


def notify_gate(gate_name: str, verdict: str, target: str = "", reason: str = "") -> dict:
    sev = "HIGH" if verdict == "KILL" else "INFO"
    msg = f"*Gate {gate_name}: {verdict}*\nTarget: {target}"
    if reason:
        msg += f"\nReason: {reason}"
    return notify_all(msg, sev)


def cmd_test(args):
    ok = notify(args.channel, f"Terminator test notification ({args.channel})", "INFO")
    print(f"{'OK' if ok else 'FAILED'}: {args.channel}")


def cmd_send(args):
    ok = notify(args.channel, args.message, args.severity)
    print(f"{'OK' if ok else 'FAILED'}")


def cmd_broadcast(args):
    results = notify_all(args.message, args.severity)
    for ch, ok in results.items():
        print(f"  {ch}: {'OK' if ok else 'FAILED'}")


def main():
    p = argparse.ArgumentParser(description="Terminator notification manager")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("test", help="Send test notification")
    s.add_argument("channel", choices=list(CHANNEL_HANDLERS.keys()))

    s = sub.add_parser("send", help="Send notification to channel")
    s.add_argument("channel", choices=list(CHANNEL_HANDLERS.keys()))
    s.add_argument("message")
    s.add_argument("--severity", default="INFO")

    s = sub.add_parser("broadcast", help="Send to all configured channels")
    s.add_argument("message")
    s.add_argument("--severity", default="INFO")

    args = p.parse_args()
    {"test": cmd_test, "send": cmd_send, "broadcast": cmd_broadcast}[args.command](args)


if __name__ == "__main__":
    main()
