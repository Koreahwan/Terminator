from __future__ import annotations

import sys
import types
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools import index_pdf_articles


def test_detect_document_extension_uses_content_type_when_url_has_no_suffix() -> None:
    extension = index_pdf_articles.detect_document_extension(
        "https://example.com/download?id=42",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document; charset=binary",
    )

    assert extension == ".docx"


def test_extract_document_text_prefers_markitdown(monkeypatch, tmp_path: Path) -> None:
    class FakeResult:
        text_content = "# Title\n\nStructured markdown"

    class FakeMarkItDown:
        def convert(self, path: str) -> FakeResult:
            assert path.endswith(".docx")
            return FakeResult()

    monkeypatch.setitem(sys.modules, "markitdown", types.SimpleNamespace(MarkItDown=FakeMarkItDown))
    monkeypatch.setattr(index_pdf_articles, "extract_text_pypdf", lambda _: "plain fallback")

    content, backend = index_pdf_articles.extract_document_text(tmp_path / "sample.docx")

    assert backend == "markitdown"
    assert content == "# Title\n\nStructured markdown"


def test_extract_document_text_falls_back_to_pypdf_for_pdf(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delitem(sys.modules, "markitdown", raising=False)
    monkeypatch.setattr(index_pdf_articles.importlib, "import_module", lambda name: (_ for _ in ()).throw(ImportError()))
    monkeypatch.setattr(index_pdf_articles, "extract_text_pypdf", lambda _: "plain fallback")

    content, backend = index_pdf_articles.extract_document_text(tmp_path / "sample.pdf")

    assert backend == "pypdf"
    assert content == "plain fallback"


def test_extract_document_text_returns_empty_for_non_pdf_without_markitdown(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delitem(sys.modules, "markitdown", raising=False)
    monkeypatch.setattr(index_pdf_articles.importlib, "import_module", lambda name: (_ for _ in ()).throw(ImportError()))
    monkeypatch.setattr(index_pdf_articles, "extract_text_pypdf", lambda _: "plain fallback")

    content, backend = index_pdf_articles.extract_document_text(tmp_path / "sample.docx")

    assert backend == "none"
    assert content == ""


def test_extract_document_text_falls_back_when_markitdown_conversion_fails(monkeypatch, tmp_path: Path) -> None:
    class BrokenMarkItDown:
        def convert(self, path: str) -> str:
            raise RuntimeError("boom")

    monkeypatch.setitem(sys.modules, "markitdown", types.SimpleNamespace(MarkItDown=BrokenMarkItDown))
    monkeypatch.setattr(index_pdf_articles, "extract_text_pypdf", lambda _: "plain fallback")

    content, backend = index_pdf_articles.extract_document_text(tmp_path / "sample.pdf")

    assert backend == "pypdf"
    assert content == "plain fallback"
