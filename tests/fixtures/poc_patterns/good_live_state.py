"""Fixture: on-chain read with assertion on live state — should PASS."""

def run_exploit():
    balance_before = contract.call("balanceOf", attacker)
    tx_hash = contract.functions.attack(victim).transact()
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    balance_after = contract.call("balanceOf", attacker)
    assert balance_after > balance_before, "Attack did not increase balance"
    assert receipt["status"] == 1, "Transaction reverted"
