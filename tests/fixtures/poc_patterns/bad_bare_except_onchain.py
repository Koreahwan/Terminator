"""Fixture: bare except swallowing on-chain call failure — should trigger HARD_KILL."""
import requests

def run_poc():
    try:
        # on-chain interaction
        balance = contract.call("balanceOf", attacker_addr)
        tx = w3.eth.send_transaction({"to": victim, "value": balance})
        receipt = w3.eth.wait_for_transaction_receipt(tx)
    except:
        print("Transaction failed, continuing anyway")
        exit(0)
