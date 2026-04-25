#!/usr/bin/env python3
"""
Platform auto-login helper for Phase 5.8 auto-fill.
Reads credentials from ~/.config/bounty-credentials.json
Outputs login steps as JSON for Playwright MCP orchestration.

Usage:
  python3 tools/platform_autologin.py check <platform>
  python3 tools/platform_autologin.py get-creds <platform>
  python3 tools/platform_autologin.py login-steps <platform>
"""

import json
import os
import sys
from pathlib import Path

CREDS_PATH = Path.home() / ".config" / "bounty-credentials.json"

# Platform-specific snapshot ref hints for login forms
LOGIN_REFS = {
    "bugcrowd": {
        "email_ref_hint": "Email",
        "password_ref_hint": "Password",
        "submit_ref_hint": "Log in",
    },
    "yeswehack": {
        "email_ref_hint": "Email",
        "password_ref_hint": "Password",
        "submit_ref_hint": "Log in",
    },
    "hackenproof": {
        "email_ref_hint": "Email",
        "password_ref_hint": "Password",
        "submit_ref_hint": "Log in",
    },
    "intigriti": {
        "email_ref_hint": "Email",
        "password_ref_hint": "Password",
        "submit_ref_hint": "Log in",
    },
}

# Platforms with persistent sessions (no auto-login needed usually)
PERSISTENT_SESSION = ["immunefi", "intigriti", "hackerone"]

# Platforms that CANNOT auto-login (OTP/2FA required)
MANUAL_LOGIN_ONLY = ["bugcrowd"]


def load_creds():
    if not CREDS_PATH.exists():
        print(json.dumps({"error": f"Credentials file not found: {CREDS_PATH}"}))
        sys.exit(1)
    return json.loads(CREDS_PATH.read_text())


def check_platform(platform: str):
    """Output platform login info for orchestrator."""
    platform = platform.lower()

    if platform in MANUAL_LOGIN_ONLY:
        print(json.dumps({
            "platform": platform,
            "auto_login": False,
            "reason": "otp_required",
            "action": "prompt_user_login"
        }))
        return

    creds = load_creds()
    if platform not in creds:
        print(json.dumps({
            "platform": platform,
            "auto_login": False,
            "reason": "no_credentials",
            "action": "prompt_user_login"
        }))
        return

    info = creds[platform]
    if not isinstance(info, dict) or not info.get("auto_login"):
        print(json.dumps({
            "platform": platform,
            "auto_login": False,
            "reason": "auto_login_disabled",
            "action": "prompt_user_login"
        }))
        return

    refs = LOGIN_REFS.get(platform, {})
    print(json.dumps({
        "platform": platform,
        "auto_login": True,
        "login_url": info.get("login_url", ""),
        "check_url": info.get("check_url", ""),
        "check_title_contains": info.get("check_title_contains", ""),
        "refs": refs,
        "action": "auto_login"
    }))


def get_creds(platform: str):
    """Output credentials for a platform (email + password only)."""
    creds = load_creds()
    platform = platform.lower()
    if platform not in creds:
        print(json.dumps({"error": f"No credentials for {platform}"}))
        sys.exit(1)
    info = creds[platform]
    if not isinstance(info, dict):
        print(json.dumps({"error": f"Invalid credentials format for {platform}"}))
        sys.exit(1)
    import tempfile, stat
    cred_data = json.dumps({
        "platform": platform,
        "email": info.get("email", ""),
        "password": info.get("password", ""),
    })
    fd, cred_path = tempfile.mkstemp(prefix=f"cred_{platform}_", suffix=".json")
    os.write(fd, cred_data.encode())
    os.close(fd)
    os.chmod(cred_path, stat.S_IRUSR)
    print(json.dumps({"credential_file": cred_path}))


def login_steps(platform: str):
    """Output full login procedure as step-by-step MCP instructions."""
    creds = load_creds()
    platform = platform.lower()
    if platform not in creds:
        print(json.dumps({"error": f"No credentials for {platform}"}))
        sys.exit(1)
    info = creds[platform]
    if not isinstance(info, dict):
        print(json.dumps({"error": f"Invalid credentials format for {platform}"}))
        sys.exit(1)

    refs = LOGIN_REFS.get(platform, {})
    steps = [
        {
            "step": 1,
            "action": "navigate",
            "tool": "mcp__playwright__browser_navigate",
            "params": {"url": info.get("login_url", "")},
            "description": f"Navigate to {platform} login page",
        },
        {
            "step": 2,
            "action": "snapshot",
            "tool": "mcp__playwright__browser_snapshot",
            "description": "Check if already logged in or on login form",
        },
        {
            "step": 3,
            "action": "fill_email",
            "tool": "mcp__playwright__browser_fill_form",
            "params_hint": {
                "ref_hint": refs.get("email_ref_hint", "Email"),
                "value": info.get("email", ""),
            },
            "description": "Fill email field",
        },
        {
            "step": 4,
            "action": "fill_password",
            "tool": "mcp__playwright__browser_fill_form",
            "params_hint": {
                "ref_hint": refs.get("password_ref_hint", "Password"),
                "value": info.get("password", ""),
            },
            "description": "Fill password field",
        },
        {
            "step": 5,
            "action": "submit",
            "tool": "mcp__playwright__browser_click",
            "params_hint": {
                "ref_hint": refs.get("submit_ref_hint", "Log in"),
            },
            "description": "Click login button",
        },
        {
            "step": 6,
            "action": "verify",
            "tool": "mcp__playwright__browser_snapshot",
            "check": {
                "url_contains": info.get("check_url", ""),
                "title_contains": info.get("check_title_contains", ""),
            },
            "description": "Verify login success",
        },
    ]
    print(json.dumps({
        "platform": platform,
        "login_url": info.get("login_url", ""),
        "check_url": info.get("check_url", ""),
        "steps": steps,
    }, indent=2))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} check|get-creds|login-steps <platform>")
        sys.exit(1)

    cmd = sys.argv[1]
    platform = sys.argv[2]

    if cmd == "check":
        check_platform(platform)
    elif cmd == "get-creds":
        get_creds(platform)
    elif cmd == "login-steps":
        login_steps(platform)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
