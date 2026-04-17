"""Fixture: try/except with hardcoded fallback — should trigger HARD_KILL."""

def exploit():
    try:
        result = contract.functions.drain(target_addr).call()
        return result
    except Exception:
        # Silently fall back to hardcoded value — masks failure
        result = (True, 1000000000000000000)
        return result
