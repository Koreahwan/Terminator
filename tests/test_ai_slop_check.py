import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from bb_preflight import kill_gate_1


def _make_rules(tmp_path, platform="Generic"):
    (tmp_path / "program_rules_summary.md").write_text(f"""
## Platform
{platform}
## In-Scope Assets
- https://target.com
## Severity Scope
- Critical, High, Medium, Low
## Out-of-Scope
(empty)
## Submission Rules
Standard.
## Asset Scope Constraints
None.
## Known Issues
None.
""")


def test_slop_template_language_warn(tmp_path, capsys):
    _make_rules(tmp_path)
    kill_gate_1(str(tmp_path),
        finding="it is worth noting that this showcases a critical flaw furthermore it may allow",
        severity="medium",
        impact="it should be noted this could leverage the robust system")
    assert "AI-SLOP RISK" in capsys.readouterr().out


def test_slop_clean_finding_no_warn(tmp_path, capsys):
    _make_rules(tmp_path)
    kill_gate_1(str(tmp_path),
        finding="Reflected XSS on search page",
        severity="medium",
        impact="attacker can execute arbitrary JavaScript in victim browser")
    assert "AI-SLOP RISK" not in capsys.readouterr().out


def test_slop_emoji_spam_warn(tmp_path, capsys):
    _make_rules(tmp_path)
    # 6 emojis — score = 3
    kill_gate_1(str(tmp_path),
        finding="🚀 Critical RCE 🔥 in 💥 main 🎯 endpoint 🛡️ exploit 💯",
        severity="critical",
        impact="RCE")
    out = capsys.readouterr().out
    assert "AI-SLOP RISK" in out


def test_slop_mixed_below_threshold_no_warn(tmp_path, capsys):
    _make_rules(tmp_path)
    # Only 1 marker, 0 emojis — score=1
    kill_gate_1(str(tmp_path),
        finding="SSRF leverage of open redirect",
        severity="high",
        impact="internal network scan")
    assert "AI-SLOP RISK" not in capsys.readouterr().out
