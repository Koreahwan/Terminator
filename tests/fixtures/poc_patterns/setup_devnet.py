"""Fixture: infrastructure file — should be SKIPPED by poc_pattern_check."""

def start_devnet():
    try:
        import subprocess
        proc = subprocess.Popen(["starknet-devnet", "--port", "5050"])
        proc.wait(timeout=5)
    except Exception:
        # Infrastructure retry — acceptable
        retry_count = 3
        print(f"Devnet start failed, retrying {retry_count} times")
