#!/usr/bin/env bash
# Update external wordlist/payload repos kept outside the Terminator tree.
#
# Managed paths:
#   ~/SecLists                 — danielmiessler/SecLists (~2.5 GB, 6K+ wordlists)
#   ~/PayloadsAllTheThings     — swisskyrepo/PayloadsAllTheThings (~13 MB curated payloads)
#   ~/nuclei-templates         — projectdiscovery/nuclei-templates (maintained by nuclei CLI itself)
#
# Usage: ./scripts/update_external_wordlists.sh [seclists|pat|all]
# Default: all

set -euo pipefail
MODE="${1:-all}"

update_repo() {
    local name="$1" path="$2" url="$3" shallow="$4"
    echo "=== $name ($path) ==="
    if [ -d "$path/.git" ]; then
        cd "$path"
        local before
        before=$(git rev-parse HEAD)
        git pull --ff-only 2>&1 | tail -3
        local after
        after=$(git rev-parse HEAD)
        if [ "$before" = "$after" ]; then
            echo "  (up-to-date)"
        else
            echo "  updated ${before:0:8} -> ${after:0:8}"
        fi
        cd - >/dev/null
    else
        echo "  cloning fresh"
        if [ "$shallow" = "yes" ]; then
            git clone --depth=1 "$url" "$path"
        else
            git clone "$url" "$path"
        fi
    fi
    du -sh "$path" 2>&1 | head -1
}

case "$MODE" in
    seclists|sl)
        update_repo SecLists "$HOME/SecLists" "https://github.com/danielmiessler/SecLists.git" "yes"
        ;;
    pat|payloadsallthethings)
        update_repo PayloadsAllTheThings "$HOME/PayloadsAllTheThings" "https://github.com/swisskyrepo/PayloadsAllTheThings.git" "no"
        ;;
    all)
        update_repo SecLists "$HOME/SecLists" "https://github.com/danielmiessler/SecLists.git" "yes"
        update_repo PayloadsAllTheThings "$HOME/PayloadsAllTheThings" "https://github.com/swisskyrepo/PayloadsAllTheThings.git" "no"
        ;;
    *)
        echo "usage: $0 [seclists|pat|all]" >&2
        exit 2
        ;;
esac
