#!/usr/bin/env python3
"""MCP server for local document-to-Markdown conversion via MarkItDown."""
from __future__ import annotations

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

try:
    from markitdown import MarkItDown
except ImportError:
    MarkItDown = None


mcp = FastMCP("markitdown-mcp")

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SUPPORTED_EXTENSIONS = (
    ".pdf",
    ".docx",
    ".pptx",
    ".xlsx",
    ".xls",
    ".html",
    ".htm",
    ".csv",
    ".json",
    ".xml",
    ".txt",
    ".epub",
    ".zip",
)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _allowed_roots() -> list[Path]:
    roots = [PROJECT_ROOT]
    raw_extra = os.environ.get("MARKITDOWN_MCP_ALLOWED_ROOTS", "")
    for raw_root in raw_extra.split(os.pathsep):
        if not raw_root.strip():
            continue
        roots.append(Path(raw_root).expanduser().resolve())

    deduped: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        resolved = root.resolve()
        if resolved not in seen:
            deduped.append(resolved)
            seen.add(resolved)
    return deduped


def _resolve_input_path(path: str, expect_dir: bool = False) -> Path:
    if not path.strip():
        raise ValueError("Path is required.")

    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = (Path.cwd() / candidate).resolve()
    else:
        candidate = candidate.resolve()

    if not candidate.exists():
        raise ValueError(f"Path not found: {candidate}")

    allowed_roots = _allowed_roots()
    if not any(_is_relative_to(candidate, root) for root in allowed_roots):
        allowed_str = ", ".join(str(root) for root in allowed_roots)
        raise PermissionError(f"Path is outside allowed roots: {candidate}. Allowed roots: {allowed_str}")

    if expect_dir:
        if not candidate.is_dir():
            raise ValueError(f"Expected a directory path: {candidate}")
    elif not candidate.is_file():
        raise ValueError(f"Expected a file path: {candidate}")

    return candidate


def _ensure_supported_extension(path: Path) -> None:
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported extension '{path.suffix}'. Supported: {', '.join(SUPPORTED_EXTENSIONS)}"
        )


def _get_converter() -> MarkItDown:
    if MarkItDown is None:
        raise RuntimeError(
            "markitdown is not installed. Install it with: pip install 'markitdown[all]'"
        )
    return MarkItDown()


def _result_to_markdown(result: object) -> tuple[str, str]:
    for attr in ("text_content", "markdown"):
        value = getattr(result, attr, None)
        if isinstance(value, str) and value.strip():
            title = getattr(result, "title", None) or ""
            return value.strip(), title

    if isinstance(result, str) and result.strip():
        return result.strip(), ""

    raise RuntimeError("MarkItDown returned no usable markdown content.")


def _truncate_text(text: str, max_chars: int) -> tuple[str, bool]:
    if max_chars <= 0 or len(text) <= max_chars:
        return text, False
    return text[:max_chars], True


def _convert_path(path: Path, max_chars: int) -> dict:
    _ensure_supported_extension(path)
    result = _get_converter().convert(str(path))
    markdown, title = _result_to_markdown(result)
    preview, truncated = _truncate_text(markdown, max_chars)
    stat = path.stat()
    return {
        "path": str(path),
        "title": title or path.stem,
        "extension": path.suffix.lower(),
        "size_bytes": stat.st_size,
        "char_count": len(markdown),
        "truncated": truncated,
        "markdown": preview,
    }


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def list_supported_formats() -> str:
    """List document formats accepted by the local MarkItDown conversion server."""
    return json.dumps(
        {
            "server": "markitdown-mcp",
            "mode": "local-file-only",
            "supported_extensions": list(SUPPORTED_EXTENSIONS),
            "allowed_roots": [str(root) for root in _allowed_roots()],
        },
        indent=2,
    )


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def convert_file(path: str, max_chars: int = 20000) -> str:
    """Convert one local document file to Markdown.

    Args:
        path: Absolute or repo-relative file path within an allowed root
        max_chars: Maximum markdown characters to return (0 = no truncation)
    """
    try:
        resolved = _resolve_input_path(path)
        payload = _convert_path(resolved, max_chars=max_chars)
        return json.dumps(payload, indent=2, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"error": str(exc), "path": path}, indent=2, ensure_ascii=False)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True))
def convert_directory(directory: str, glob: str = "*", max_files: int = 20, max_chars_per_file: int = 12000) -> str:
    """Convert multiple local documents under one directory.

    Args:
        directory: Absolute or repo-relative directory path within an allowed root
        glob: Glob pattern to match files (e.g. '*.pdf', '*.docx', '**/*.pdf')
        max_files: Maximum number of matched files to convert
        max_chars_per_file: Maximum markdown characters returned per file
    """
    try:
        resolved_dir = _resolve_input_path(directory, expect_dir=True)
        candidates = sorted(
            path for path in resolved_dir.glob(glob)
            if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS
        )[:max_files]

        items = [_convert_path(path.resolve(), max_chars=max_chars_per_file) for path in candidates]
        return json.dumps(
            {
                "directory": str(resolved_dir),
                "glob": glob,
                "converted_count": len(items),
                "items": items,
            },
            indent=2,
            ensure_ascii=False,
        )
    except Exception as exc:
        return json.dumps(
            {"error": str(exc), "directory": directory, "glob": glob},
            indent=2,
            ensure_ascii=False,
        )


if __name__ == "__main__":
    mcp.run()
