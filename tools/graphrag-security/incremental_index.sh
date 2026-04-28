#!/bin/bash
# incremental_index.sh — Add a file to GraphRAG index incrementally
# Usage: ./incremental_index.sh <file_path> [type]
# type: challenge, technique, finding, writeup, firmware, exploit (default: general)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GRAPHRAG_BIN=""

if command -v graphrag &>/dev/null; then
    GRAPHRAG_BIN="$(command -v graphrag)"
elif [[ -x "$PROJECT_ROOT/.venv/bin/graphrag" ]]; then
    GRAPHRAG_BIN="$PROJECT_ROOT/.venv/bin/graphrag"
fi

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <file_path> [type]" >&2
    echo "Types: challenge, technique, finding, writeup, firmware, exploit, general" >&2
    exit 1
fi

FILE_PATH="$1"
DOC_TYPE="${2:-general}"

# Validate file exists
if [[ ! -f "$FILE_PATH" ]]; then
    echo "Error: File not found: $FILE_PATH" >&2
    exit 1
fi

BASENAME=$(basename "$FILE_PATH")
BASENAME_NOEXT="${BASENAME%.*}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

INPUT_DIR="$SCRIPT_DIR/input"
mkdir -p "$INPUT_DIR"

TARGET_FILE="$INPUT_DIR/incr_${BASENAME_NOEXT}.txt"

# Create input file with YAML front-matter + content
{
    echo "---"
    echo "source: ${FILE_PATH}"
    echo "type: ${DOC_TYPE}"
    echo "indexed_at: ${TIMESTAMP}"
    echo "basename: ${BASENAME}"
    echo "---"
    echo ""
    cat "$FILE_PATH"
} > "$TARGET_FILE"

echo "[incremental_index] Prepared: $TARGET_FILE (type=$DOC_TYPE)"

# Run graphrag update
if [[ -z "$GRAPHRAG_BIN" ]]; then
    echo "[incremental_index] WARNING: graphrag not found in PATH or repo .venv, skipping index update" >&2
    exit 0
fi

echo "[incremental_index] Running: $GRAPHRAG_BIN update --root $SCRIPT_DIR"
if ! "$GRAPHRAG_BIN" update --root "$SCRIPT_DIR" 2>&1; then
    echo "[incremental_index] WARNING: graphrag update failed" >&2
    exit 1
fi

echo "[incremental_index] GraphRAG index updated successfully"

# Sync to Neo4j if running
if docker ps 2>/dev/null | grep -q neo4j; then
    echo "[incremental_index] Neo4j detected, syncing..."
    NEO4J_SYNC="$SCRIPT_DIR/neo4j_sync.py"
    if [[ -f "$NEO4J_SYNC" ]]; then
        if python3 "$NEO4J_SYNC" 2>&1; then
            echo "[incremental_index] Neo4j sync completed"
        else
            echo "[incremental_index] WARNING: Neo4j sync failed (non-fatal)" >&2
        fi
    else
        echo "[incremental_index] WARNING: neo4j_sync.py not found at $NEO4J_SYNC" >&2
    fi
else
    echo "[incremental_index] Neo4j not running, skipping sync"
fi

echo "[incremental_index] Done: $BASENAME ($DOC_TYPE)"
