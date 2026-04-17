import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from bb_preflight import kill_gate_1


def _make_rules(tmp_path, scope_body):
    (tmp_path / "program_rules_summary.md").write_text(f"""
## Platform
Generic
## In-Scope Assets
{scope_body}
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


def test_scope_drift_main_only_subdomain_warn(tmp_path, capsys):
    _make_rules(tmp_path, "- https://target.com")
    kill_gate_1(str(tmp_path),
        finding="SQL injection on dev.target.com admin panel",
        severity="high",
        impact="database access")
    out = capsys.readouterr().out
    assert "SCOPE DRIFT" in out


def test_scope_drift_wildcard_no_warn(tmp_path, capsys):
    _make_rules(tmp_path, "- *.target.com")
    kill_gate_1(str(tmp_path),
        finding="SQL injection on dev.target.com",
        severity="high",
        impact="database access")
    out = capsys.readouterr().out
    assert "SCOPE DRIFT" not in out


def test_scope_drift_exact_match_no_warn(tmp_path, capsys):
    _make_rules(tmp_path, "- https://target.com")
    kill_gate_1(str(tmp_path),
        finding="SQL injection on target.com login",
        severity="high",
        impact="database access")
    out = capsys.readouterr().out
    assert "SCOPE DRIFT" not in out


def test_scope_drift_unrelated_domain_no_warn(tmp_path, capsys):
    _make_rules(tmp_path, "- https://target.com")
    kill_gate_1(str(tmp_path),
        finding="SQL injection on unrelated-vendor.io",
        severity="high",
        impact="vendor's own domain")
    out = capsys.readouterr().out
    # unrelated-vendor.io 는 target.com 하위가 아니니까 SCOPE DRIFT 발화 안 함
    assert "SCOPE DRIFT" not in out
