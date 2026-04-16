from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_server_module():
    server_path = (
        Path(__file__).resolve().parents[1]
        / "tools"
        / "mcp-servers"
        / "markitdown-mcp"
        / "server.py"
    )
    spec = importlib.util.spec_from_file_location("markitdown_mcp_server", server_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_resolve_input_path_rejects_outside_allowed_roots(tmp_path: Path) -> None:
    module = _load_server_module()
    outside_file = tmp_path / "outside.pdf"
    outside_file.write_text("demo", encoding="utf-8")

    try:
        module._resolve_input_path(str(outside_file))
    except PermissionError as exc:
        assert "outside allowed roots" in str(exc)
    else:
        raise AssertionError("Expected outside path to be rejected")


def test_convert_file_returns_markdown_payload(monkeypatch, tmp_path: Path) -> None:
    module = _load_server_module()
    monkeypatch.setattr(module, "PROJECT_ROOT", tmp_path)

    sample = tmp_path / "sample.pdf"
    sample.write_bytes(b"%PDF fake test payload")

    class FakeResult:
        markdown = "# Sample\n\nConverted"
        text_content = markdown
        title = "Custom Title"

    class FakeConverter:
        def convert(self, path: str) -> FakeResult:
            assert path.endswith("sample.pdf")
            return FakeResult()

    monkeypatch.setattr(module, "_get_converter", lambda: FakeConverter())

    payload = json.loads(module.convert_file(str(sample), max_chars=0))

    assert payload["title"] == "Custom Title"
    assert payload["extension"] == ".pdf"
    assert payload["char_count"] == len("# Sample\n\nConverted")
    assert payload["truncated"] is False
    assert payload["markdown"] == "# Sample\n\nConverted"


def test_convert_directory_limits_results(monkeypatch, tmp_path: Path) -> None:
    module = _load_server_module()
    monkeypatch.setattr(module, "PROJECT_ROOT", tmp_path)

    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    (docs_dir / "a.pdf").write_bytes(b"%PDF a")
    (docs_dir / "b.docx").write_bytes(b"docx bytes")
    (docs_dir / "ignore.md").write_text("ignore", encoding="utf-8")

    class FakeResult:
        title = None

        def __init__(self, name: str):
            self.markdown = f"# {name}"
            self.text_content = self.markdown

    class FakeConverter:
        def convert(self, path: str) -> FakeResult:
            return FakeResult(Path(path).name)

    monkeypatch.setattr(module, "_get_converter", lambda: FakeConverter())

    payload = json.loads(module.convert_directory(str(docs_dir), glob="*", max_files=1, max_chars_per_file=0))

    assert payload["converted_count"] == 1
    assert len(payload["items"]) == 1
    assert payload["items"][0]["extension"] in {".pdf", ".docx"}
