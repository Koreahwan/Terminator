#!/usr/bin/env python3
"""
ecxor solver v2 - improved key recovery using English frequency scoring
"""

import base64
import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rfc8032 import point_add, point_compress, point_mul, G

CHALLENGE_DIR = os.path.dirname(os.path.abspath(__file__))

print("[*] Building lookup table n*G for n in 0..510 ...")

lookup = {}
current = (0, 1, 1, 0)  # 0*G = identity
for n in range(511):
    compressed = point_compress(current)
    lookup[compressed] = n
    current = point_add(current, G)

print(f"[*] Lookup table built: {len(lookup)} entries")

# Read ciphertext
with open(os.path.join(CHALLENGE_DIR, 'ciphertext'), 'rb') as f:
    ctxt = f.read().strip()

parts = ctxt.split(b';')
print(f"[*] Ciphertext has {len(parts)} points")

# Get discrete logs for all ciphertext points
sums = []
for part in parts:
    compressed = base64.b64decode(part)
    n = lookup.get(compressed)
    sums.append(n)

print(f"[*] Discrete logs computed. Sums[:10] = {sums[:10]}")

# Known prefix: "flag{"
known_prefix = "flag{"
key = [None] * 12

for i, ch in enumerate(known_prefix):
    if sums[i] is not None:
        key_byte = sums[i] - ord(ch)
        if 0 <= key_byte <= 255:
            key[i % 12] = key_byte
            print(f"[*] key[{i % 12}] = {key_byte}")

print(f"[*] Key from prefix: {key}")

# English letter frequency scoring (higher = more English-like)
# Common letters in English text + flag content
ENGLISH_FREQ = {}
# Letters a-z weighted by English frequency
for ch in 'etaoinshrdlcumwfgypbvkjxqzETAOINSHRDLCUMWFGYPBVKJXQZ':
    ENGLISH_FREQ[ch] = 3
# Common punctuation and digits
for ch in ' .,!?-_0123456789{}':
    ENGLISH_FREQ[ch] = 2
# Other printable
for i in range(32, 127):
    ch = chr(i)
    if ch not in ENGLISH_FREQ:
        ENGLISH_FREQ[ch] = 1

def score_char(c):
    """Score a character for likelihood of being in plaintext."""
    return ENGLISH_FREQ.get(c, 0)

# For unknown key bytes, use English frequency scoring
unknown_key_positions = [k for k in range(12) if key[k] is None]
print(f"[*] Unknown key positions: {unknown_key_positions}")

for k in unknown_key_positions:
    position_sums = [(i, sums[i]) for i in range(len(sums)) if i % 12 == k and sums[i] is not None]

    best_key = None
    best_score = -1

    for kb in range(256):
        score = 0
        for i, s in position_sums:
            char_val = s - kb
            if 0 <= char_val <= 127:
                ch = chr(char_val)
                score += score_char(ch)
            # non-printable = 0 score
        if score > best_score:
            best_score = score
            best_key = kb

    key[k] = best_key
    # Show top chars for this key
    chars = []
    for i, s in position_sums[:5]:
        cv = s - best_key
        chars.append(chr(cv) if 0 <= cv <= 127 else '?')
    print(f"[*] key[{k}] = {best_key} (score={best_score}, sample chars: {''.join(chars)})")

print(f"[*] Recovered key: {key}")

# Decrypt
plaintext = []
for i, s in enumerate(sums):
    if s is not None:
        kb = key[i % 12]
        char_val = s - kb
        if 0 <= char_val <= 127:
            plaintext.append(chr(char_val))
        else:
            plaintext.append('?')
    else:
        plaintext.append('?')

full_text = ''.join(plaintext)
print(f"[*] Full decryption (first 120): {repr(full_text[:120])}")

# The flag is the first "flag{...}" with a proper closing brace
# Find the real closing brace: after flag{ the content should end with }
# Look for flag{ ... } where content is printable
flag_match = re.search(r'flag\{[^\}]*\}', full_text)
if flag_match:
    flag = flag_match.group(0)
    # Validate: all chars in flag should be printable ASCII
    if all(32 <= ord(c) <= 126 for c in flag):
        print(f"[+] FLAG: {flag}")
    else:
        print(f"[!] Flag has non-printable chars: {repr(flag)}")
        flag = flag_match.group(0)

print(f"\n[*] Full decryption:")
print(full_text)

# Write flag
if flag_match:
    flag = flag_match.group(0)
    with open(os.path.join(CHALLENGE_DIR, 'flag_found.txt'), 'w') as f:
        f.write(flag + '\n')
    print(f"\n[+] Written to flag_found.txt: {flag}")
