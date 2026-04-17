"""Fixture: assert comparing only Python literals — should trigger WARN."""

def verify_exploit():
    deposit = 1000
    fee = 10
    expected = 990
    # This assert never touches the chain — purely arithmetic simulation
    assert deposit - fee == expected
    assert 2 + 2 == 4
