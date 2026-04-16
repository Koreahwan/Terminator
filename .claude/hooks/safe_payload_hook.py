#!/usr/bin/env python3
"""PreToolUse:Bash — Payload safety enforcement hook.

Reads stdin JSON with tool_name and tool_input.command.
Returns JSON with permissionDecision for dangerous commands.
"""
import json, sys, re

BLOCKLIST_PATTERNS = [
    r'\brm\s+(-rf?|--recursive)\s+/',
    r'\bdd\s+.*of=/dev/',
    r'\bmkfs\b',
    r'\bformat\b',
    r'>\s*/dev/sd[a-z]',
    r'\bshutdown\b',
    r'\breboot\b',
    r'\bsystemctl\s+(stop|disable)\s+(ssh|firewall|iptables)',
    r'\biptables\s+-F',
    r':(){.*};:',
    r'\bchmod\s+777\s+/',
    r'\bwget\s+.*\|\s*(ba)?sh',
    r'\bcurl\s+.*\|\s*(ba)?sh',
]

SAFE_COMMANDS = {'id', 'whoami', 'hostname', 'uname', 'cat /etc/passwd',
                 'cat /etc/hostname', 'env', 'printenv', 'pwd', 'ls'}

def check_command(command: str) -> tuple:
    cmd_stripped = command.strip()
    if cmd_stripped in SAFE_COMMANDS:
        return "allow", ""
    for pattern in BLOCKLIST_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return "deny", f"Blocked: matches dangerous pattern"
    return "allow", ""

def main():
    try:
        input_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        print(json.dumps({}))
        return

    tool_name = input_data.get("tool_name", "")
    if tool_name != "Bash":
        print(json.dumps({}))
        return

    command = input_data.get("tool_input", {}).get("command", "")
    if not command:
        print(json.dumps({}))
        return

    decision, reason = check_command(command)
    if decision == "deny":
        output = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}
        print(json.dumps(output))
    else:
        print(json.dumps({}))

if __name__ == "__main__":
    main()
