#!/usr/bin/env bash
# Offline security audit of Claude Code MCP + agent/skill configs.
# Complements invariantlabs/snyk-agent-scan (requires SNYK_TOKEN + cloud).
#
# Usage: ./scripts/audit_mcp_config.sh [--json]
# Exit: 0 = clean, 1 = warnings, 2 = critical findings

set -euo pipefail
JSON_OUT=0
[[ "${1:-}" == "--json" ]] && JSON_OUT=1

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_MCP="${PROJECT_ROOT}/.claude/mcp.json"
USER_MCP="${HOME}/.claude/mcp.json"
TMP_FINDINGS=$(mktemp)
trap "rm -f $TMP_FINDINGS" EXIT

# Each finding written as: severity|check|message
add_finding() {
    echo "$1|$2|$3" >> "$TMP_FINDINGS"
}

# ===== A. MCP server collision =====
python3 <<EOF >> "$TMP_FINDINGS" 2>/dev/null
import json, pathlib
servers = {}
for p in ["$PROJECT_MCP", "$USER_MCP"]:
    try:
        for name in json.load(open(p)).get("mcpServers", {}):
            if name in servers:
                print(f"critical|A.MCP_collision|'{name}' in both {servers[name]} and {p}")
            servers[name] = p
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"warning|A.MCP_parse|Could not parse {p}: {e}")
EOF

# ===== B. MCP command path existence =====
python3 <<EOF >> "$TMP_FINDINGS" 2>/dev/null
import json, shutil, os
for p in ["$PROJECT_MCP", "$USER_MCP"]:
    if not os.path.exists(p): continue
    try: cfg = json.load(open(p))
    except: continue
    for name, spec in cfg.get("mcpServers", {}).items():
        cmd = spec.get("command", "")
        if not cmd: continue
        if cmd.startswith("/"):
            if not os.path.isfile(cmd):
                print(f"warning|B.MCP_cmd_missing|Server '{name}' command '{cmd}' not found")
        else:
            if not shutil.which(cmd):
                print(f"warning|B.MCP_cmd_missing|Server '{name}' command '{cmd}' not in PATH")
EOF

# ===== C. Embedded secrets in MCP =====
for p in "$PROJECT_MCP" "$USER_MCP"; do
    [[ -f "$p" ]] || continue
    if grep -qE '"(api[_-]?key|token|secret|password)"\s*:\s*"[^"]{8,}"' "$p" 2>/dev/null; then
        add_finding "critical" "C.MCP_secrets" "Literal secret field detected in $p"
    fi
    if grep -qE '(ghp_|AKIA|sk-[A-Za-z0-9]{20,})' "$p" 2>/dev/null; then
        add_finding "critical" "C.MCP_secrets" "Known API token pattern in $p"
    fi
done

# ===== D. Agent/Skill name collision =====
python3 <<EOF >> "$TMP_FINDINGS" 2>/dev/null
import pathlib, re
from collections import defaultdict
locations = defaultdict(list)
proj_root = pathlib.Path("$PROJECT_ROOT")
roots = [
    ("agent", proj_root/".claude/agents"),
    ("skill", proj_root/".claude/skills"),
    ("plugin", pathlib.Path.home()/".claude/plugins/marketplaces"),
]
for kind, root in roots:
    if not root.exists(): continue
    for md in root.rglob("*.md"):
        try:
            with open(md) as f:
                for line in f:
                    m = re.match(r'^name:\s*(\S+)', line)
                    if m:
                        try:
                            rel = md.relative_to(proj_root)
                        except ValueError:
                            rel = md
                        locations[m.group(1)].append(f"{kind}:{rel}")
                        break
        except: pass
for name, locs in locations.items():
    if len(locs) > 1:
        kinds = {loc.split(':')[0] for loc in locs}
        # agent vs skill same-name is design pattern (e.g. scout) — ignore
        if kinds == {"agent","skill"} and len(locs) == 2:
            continue
        # Plugin-only collisions between third-party marketplaces — not our concern
        if kinds == {"plugin"}:
            continue
        # Only report if our repo (agent/skill) collides with an installed plugin
        print(f"warning|D.name_collision|'{name}' in: {', '.join(locs)}")
EOF

# ===== E. Prompt-injection markers =====
hits=$(grep -rEn "ignore (all|previous|prior) instructions|you are (now|actually|secretly) (a different|another)|disregard (all )?system prompt" \
    --include="*.md" "$PROJECT_ROOT/.claude" 2>/dev/null \
    | grep -v "example\|sample\|demo\|do not\|must not\|never\|forbidden\|iron rule" || true)
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    add_finding "warning" "E.prompt_injection" "$line"
done <<<"$hits"

# ===== F. Hook/settings JSON validity =====
if [[ -f "$HOME/.claude/settings.json" ]]; then
    if ! python3 -c "import json; json.load(open('$HOME/.claude/settings.json'))" 2>/dev/null; then
        add_finding "critical" "F.settings_json" "User settings.json is not valid JSON"
    fi
fi

# ===== G. Agent model assignments =====
while IFS= read -r md; do
    if ! head -20 "$md" | grep -qE "^model:\s*(opus|sonnet|haiku)"; then
        rel=${md#$PROJECT_ROOT/}
        add_finding "warning" "G.model_missing" "Agent $rel missing explicit model declaration"
    fi
done < <(find "$PROJECT_ROOT/.claude/agents" -name "*.md" -type f -not -path "*/_reference/*" 2>/dev/null)

# ========= Report =========
criticals=$(grep -c "^critical|" "$TMP_FINDINGS" 2>/dev/null || true)
warnings=$(grep -c "^warning|" "$TMP_FINDINGS" 2>/dev/null || true)
criticals=$(echo "${criticals:-0}" | tr -d '\n ')
warnings=$(echo "${warnings:-0}" | tr -d '\n ')
[[ -z "$criticals" ]] && criticals=0
[[ -z "$warnings" ]] && warnings=0

if [[ $JSON_OUT -eq 1 ]]; then
    python3 -c "
import sys, json
findings = []
with open('$TMP_FINDINGS') as f:
    for line in f:
        parts = line.rstrip('\n').split('|', 2)
        if len(parts) == 3:
            findings.append({'severity':parts[0],'check':parts[1],'message':parts[2]})
print(json.dumps({'criticals':$criticals,'warnings':$warnings,'findings':findings}, indent=2))
"
else
    echo "========================================"
    echo "MCP/Agent/Skill Audit — $(date -Iseconds)"
    echo "========================================"
    if [[ -s "$TMP_FINDINGS" ]]; then
        while IFS='|' read -r sev check msg; do
            printf '[%-8s] %-30s %s\n' "$sev" "$check" "$msg"
        done < "$TMP_FINDINGS"
    else
        echo "[CLEAN] No findings."
    fi
    echo ""
    echo "Summary: $criticals critical, $warnings warning"
fi

if ((criticals > 0)); then exit 2; fi
if ((warnings > 0)); then exit 1; fi
exit 0
