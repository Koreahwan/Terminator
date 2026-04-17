"""Tests for poc_pattern_check() — kill-gate-2 static PoC analysis.

Covers the three Paradex #72418/#72759 anti-patterns:
  1. try/except with hardcoded fallback literal in handler
  2. bare except (or except Exception) swallowing on-chain call failure
  3. assert comparing only Python arithmetic literals (no live on-chain read)

Infrastructure files (setup_*, devnet_*, infra_*) must be skipped.
"""
import sys
from pathlib import Path

import pytest

# Make sure tools/ is importable without package install
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from bb_preflight import poc_pattern_check

FIXTURES = Path(__file__).parent / "fixtures" / "poc_patterns"


# ---------------------------------------------------------------------------
# Test 1: try/except + hardcoded literal fallback → HARD_KILL
# ---------------------------------------------------------------------------
def test_tryexcept_fallback_hard_kill(tmp_path):
    """PoC assigns a hardcoded tuple/literal in except handler → HARD_KILL."""
    poc = tmp_path / "poc.py"
    poc.write_text(
        """\
def exploit():
    try:
        result = contract.functions.drain(target).call()
        return result
    except Exception:
        # hardcoded fallback masks failure
        result = (True, 1000000000000000000)
        return result
"""
    )
    warns, kills = poc_pattern_check(str(tmp_path))
    assert kills, f"Expected at least one HARD_KILL, got none. warns={warns}"
    assert any("POC PATTERN" in k for k in kills), kills


# ---------------------------------------------------------------------------
# Test 2: bare except + on-chain interaction → HARD_KILL
# ---------------------------------------------------------------------------
def test_bare_except_onchain_hard_kill(tmp_path):
    """Bare except swallowing an on-chain call (w3., contract.) → HARD_KILL."""
    poc = tmp_path / "exploit.py"
    poc.write_text(
        """\
def run():
    try:
        balance = contract.call("balanceOf", attacker)
        tx = w3.eth.send_transaction({"to": victim, "value": balance})
        receipt = w3.eth.wait_for_transaction_receipt(tx)
    except:
        print("failed")
        exit(0)
"""
    )
    warns, kills = poc_pattern_check(str(tmp_path))
    assert kills, f"Expected HARD_KILL for bare except + on-chain, got none. warns={warns}"
    assert any("POC PATTERN" in k for k in kills), kills


# ---------------------------------------------------------------------------
# Test 3: infra setup file → SKIPPED (no findings)
# ---------------------------------------------------------------------------
def test_infra_tryexcept_allowed(tmp_path):
    """setup_devnet.py try/except for process management must be skipped."""
    poc = tmp_path / "setup_devnet.py"
    poc.write_text(
        """\
import subprocess
def start():
    try:
        proc = subprocess.Popen(["starknet-devnet", "--port", "5050"])
        proc.wait(timeout=5)
    except Exception:
        retry_count = 3
        print(f"retrying {retry_count}")
"""
    )
    warns, kills = poc_pattern_check(str(tmp_path))
    assert not kills, f"Infrastructure file should not trigger HARD_KILL: {kills}"
    assert not warns, f"Infrastructure file should not trigger WARNs: {warns}"


# ---------------------------------------------------------------------------
# Test 4: assert with only Python arithmetic literals → WARN
# ---------------------------------------------------------------------------
def test_arithmetic_only_assert_warn(tmp_path):
    """assert deposit - fee == expected (all literals) → WARN."""
    poc = tmp_path / "poc.py"
    poc.write_text(
        """\
def verify():
    deposit = 1000
    fee = 10
    expected = 990
    assert deposit - fee == expected
    assert 2 + 2 == 4
"""
    )
    warns, kills = poc_pattern_check(str(tmp_path))
    assert warns, f"Expected WARN for arithmetic-only assert, got none. kills={kills}"
    assert any("ARITHMETIC ASSERT" in w for w in warns), warns
    assert not kills, f"Should be WARN only, not HARD_KILL: {kills}"


# ---------------------------------------------------------------------------
# Test 5: on-chain read + assert on live state → PASS (no findings)
# ---------------------------------------------------------------------------
def test_live_state_assert_pass(tmp_path):
    """result = contract.call(); assert result == expected → PASS (has live call)."""
    poc = tmp_path / "poc.py"
    poc.write_text(
        """\
def run_exploit():
    balance_before = contract.call("balanceOf", attacker)
    tx_hash = contract.functions.attack(victim).transact()
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    balance_after = contract.call("balanceOf", attacker)
    assert balance_after > balance_before, "Attack did not increase balance"
    assert receipt["status"] == 1, "Transaction reverted"
"""
    )
    warns, kills = poc_pattern_check(str(tmp_path))
    assert not kills, f"Live-state PoC should not trigger HARD_KILL: {kills}"
    # The assert uses live contract.call() on lhs — no arithmetic-only warning expected
    arith_warns = [w for w in warns if "ARITHMETIC ASSERT" in w]
    assert not arith_warns, f"Live-state assert should not produce ARITHMETIC ASSERT warns: {arith_warns}"


# ---------------------------------------------------------------------------
# Test 6: contextlib.suppress(Exception) bypass (NH1 follow-up)
# ---------------------------------------------------------------------------
def test_contextlib_suppress_exception_hard_kill(tmp_path):
    """`with contextlib.suppress(Exception)` swallowing on-chain call → HARD_KILL.

    Adversarial hunter could replace try/except with contextlib.suppress to
    bypass the AST walker. The check must cover both forms.
    """
    poc = tmp_path / "poc.py"
    poc.write_text(
        """\
import contextlib

def exploit():
    with contextlib.suppress(Exception):
        result = contract.functions.drain(target).call()
        return result
    return (True, 10**18)
"""
    )
    warns, kills = poc_pattern_check(str(tmp_path))
    assert kills, f"Expected HARD_KILL via contextlib.suppress path, got none. warns={warns}"
    assert any("suppress" in k.lower() for k in kills), kills


def test_contextlib_suppress_specific_exception_allowed(tmp_path):
    """`with contextlib.suppress(ValueError)` is narrow → no HARD_KILL."""
    poc = tmp_path / "poc.py"
    poc.write_text(
        """\
import contextlib

def parse_log(entry):
    with contextlib.suppress(ValueError):
        return int(entry)
    return None
"""
    )
    warns, kills = poc_pattern_check(str(tmp_path))
    suppress_kills = [k for k in kills if "suppress" in k.lower()]
    assert not suppress_kills, f"Narrow suppress should not HARD_KILL: {suppress_kills}"
