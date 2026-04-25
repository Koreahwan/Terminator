from pathlib import Path

from tools import areuai_bridge


FIXTURES = Path(__file__).parent / "fixtures" / "areuai"


def test_bridge_finds_global_install_or_fallback():
    assert areuai_bridge.doctor()["fallback_taxonomy_version"]


def test_analyze_ai_fixture_fails():
    text = (FIXTURES / "en_ai_fail.md").read_text(encoding="utf-8")
    result = areuai_bridge.analyze_text(text)
    assert result["score"] >= 6
    assert result["verdict"] == "FAIL"
    assert result["spans"]


def test_analyze_human_fixture_passes_due_to_evidence():
    text = (FIXTURES / "en_human_pass.md").read_text(encoding="utf-8")
    result = areuai_bridge.analyze_text(text)
    assert result["score"] <= 2
    assert result["verdict"] == "PASS"


def test_korean_fixture_detects_translationese():
    text = (FIXTURES / "ko_ai_fail.md").read_text(encoding="utf-8")
    result = areuai_bridge.analyze_text(text)
    assert result["score"] >= 5
    assert any(span["category"] in {"translationese", "ai_idiom", "ko_ai_idiom"} for span in result["spans"])


def test_scrub_preserves_code_url_cvss_and_file_line():
    text = (FIXTURES / "preserve_sample.md").read_text(encoding="utf-8")
    cleaned = areuai_bridge.scrub_text(text)
    assert "curl -i https://api.example.test/v1/users/42" in cleaned
    assert "src/auth/check.ts:42" in cleaned
    assert "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" in cleaned
    assert "https://api.example.test/docs" in cleaned


def test_evade_lowers_score_and_preserves_facts():
    text = (FIXTURES / "evade_before.md").read_text(encoding="utf-8")
    before = areuai_bridge.analyze_text(text)["score"]
    evaded = areuai_bridge.evade_text(text, ["zerogpt"])
    after = areuai_bridge.analyze_text(evaded)["score"]
    assert after < before
    assert "attacker" in evaded.lower()

