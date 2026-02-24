#!/usr/bin/env bash
# Rebuild the Knowledge FTS5 database
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
echo "[*] Rebuilding knowledge database..."
python3 tools/knowledge_indexer.py build
echo "[*] Done. Stats:"
python3 tools/knowledge_indexer.py stats
