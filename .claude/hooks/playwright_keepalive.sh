#!/bin/bash
# Playwright MCP keepalive hook
# Ensures the isolated Chrome bounty profile is running before Playwright tool calls
# Called as PreToolUse hook for mcp__playwright__* tools

PROFILE_DIR="<project-root>/.config/playwright-bounty-profile"
CHROME_EXE="/mnt/c/Program Files/Google/Chrome/Application/chrome.exe"
PORT=9333
LOCK_FILE="/tmp/playwright_bounty_chrome.lock"

# Only act if the tool call is a playwright tool
# The hook matcher already filters for this, but double-check
[[ "$TOOL_NAME" != mcp__playwright__* ]] && exit 0

# Check if Chrome with bounty profile is already running
if pgrep -f "playwright-bounty-profile" > /dev/null 2>&1; then
    exit 0
fi

# Not running — launch it
if [ -f "$CHROME_EXE" ]; then
    "$CHROME_EXE" --user-data-dir="C:\\Users\\KH\\.config\\playwright-bounty-profile" --remote-debugging-port=$PORT &>/dev/null &
    sleep 2
fi

exit 0
