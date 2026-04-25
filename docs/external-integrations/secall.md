# seCall Integration

`seCall` is a local-first search engine for AI agent sessions. It can ingest
Claude Code, Codex CLI, Gemini CLI, ChatGPT export, and claude.ai export logs,
then expose them through CLI, REST, Obsidian vault files, and MCP.

This repository integrates it as an external tool. Do not vendor seCall source
into Terminator: seCall is AGPL-3.0, and keeping it as a user-installed binary
avoids mixing licensing boundaries with this repository's own code.

## Install

```bash
./scripts/install_secall.sh
```

The installer pins the audited upstream commit in `SECALL_REF` by default. To
test another revision:

```bash
SECALL_REF=main ./scripts/install_secall.sh
```

The installer builds the external Rust CLI with `cargo install`. On lean WSL or
container images it also handles two common build gaps:

- If `pkg-config` is missing but OpenSSL headers/libs exist under `/usr`, it
  exports `OPENSSL_INCLUDE_DIR` and `OPENSSL_LIB_DIR`.
- If `ort-sys` cannot fetch ONNX Runtime from its CDN, it prefetches Microsoft
  ONNX Runtime `1.22.0` into `~/.cache/terminator/onnxruntime/` and sets
  `ORT_LIB_LOCATION`.

Override `OPENSSL_DIR`, `OPENSSL_LIB_DIR`, `ORT_VERSION`, `ORT_ROOT`, or
`ORT_LIB_LOCATION` before running the installer when you need a different local
toolchain layout.

## Local State

The wrapper uses Terminator-local paths by default:

| Purpose | Path |
| --- | --- |
| Config | `.secall/config.toml` |
| SQLite index | `.secall/index.sqlite` |
| Vault markdown | `.secall/vault/` |
| ONNX Runtime build cache | `~/.cache/terminator/onnxruntime/` |

`.secall/` is intentionally ignored by git because it contains local session
history and regenerated indexes.

Use `--global-config` with `tools/secall_bridge.py` when you explicitly want
seCall's normal global config and cache locations.

## Commands

```bash
# Check install and local state paths
python3 tools/secall_bridge.py doctor

# Initialize local state without vector embeddings
python3 tools/secall_bridge.py init

# Ingest Claude/Codex/Gemini sessions auto-detected under the user profile
python3 tools/secall_bridge.py ingest --auto

# Search prior agent conversations with BM25 only
python3 tools/secall_bridge.py recall "bounty report scorer"

# Get a full session by ID
python3 tools/secall_bridge.py get <session-id> --full
```

The wrapper defaults to BM25 and disables seCall semantic graph extraction during
ingest/sync. That keeps setup light and avoids accidental Ollama/model startup.
Pass `--semantic` to `ingest` or `sync` only after configuring a graph backend.

## MCP

Generate an MCP server snippet:

```bash
python3 tools/secall_bridge.py mcp-config
```

Add the emitted `secall` block to a local MCP config only after `secall` is
installed. The main `.mcp.json` is not updated by default because missing
optional binaries can break client startup.

## ToolSpec Usage

The ToolSpec registry includes:

| Tool ID | Purpose |
| --- | --- |
| `secall-session-recall` | Search past AI agent sessions |
| `secall-session-ingest` | Ingest new local agent session logs |
| `secall-status` | Check seCall index health |

Use `knowledge-fts-*` for security corpus lookup and `secall-session-recall` for
remembering previous agent discussions, decisions, fixes, and handoffs.
