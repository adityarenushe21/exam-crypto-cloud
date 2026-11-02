# ExamVault capstone project | Aditya Renushe | MIT World Peace University, Pune
# Module: secure upload, post-quantum encryption and cloud storage
# SPDX-License-Identifier: MIT
r"""
Milestone 2 - Demo 4: SHA3-256 (digest / fingerprint), on its own.

STORY
- SHA3-256 turns ANY bytes (a 5 KB file or a 50 MB PDF) into a fixed 32-byte
  digest. Same bytes -> same digest, on any computer. Change 1 bit -> totally
  different digest.
- In our design we hash the ENCRYPTED file (ciphertext), so the digest can go
  to Harsh's blockchain without revealing anything about the paper.
- A digest alone does NOT prove who made the file: anyone can recompute it.
  That is why Demo 5 signs it with ML-DSA-65.

Run from the project root (venv active):
    python scripts\demos\demo_04_sha3.py
"""

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import hashes

OUT = Path("output")
OUT.mkdir(exist_ok=True)


def sha3_256_bytes(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA3_256())
    h.update(data)
    return h.finalize()


def sha3_256_file(path: Path, chunk_size: int = 64 * 1024) -> bytes:
    """Reads the file in 64 KB chunks, so big PDFs don't need to fit in memory."""
    h = hashes.Hash(hashes.SHA3_256())
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.finalize()


def bits_different(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


print("=" * 64)
print("DEMO 4: SHA3-256")
print("=" * 64)

# ---- 1. Official NIST test vectors (proves the library is correct) -------
vectors = {
    b"": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    b"abc": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
}
print("\n[1] NIST FIPS 202 test vectors")
vector_ok = True
for msg, expected in vectors.items():
    got = sha3_256_bytes(msg).hex()
    vector_ok &= got == expected
    print(f"    SHA3-256({msg!r:<6}) = {got[:24]}...  match: {got == expected}")

# ---- 2. Hash the encrypted file from Demo 3 ------------------------------
enc_path = OUT / "fake_paper.enc"
if not enc_path.exists():
    enc_path.write_bytes(b"FAKE CIPHERTEXT BYTES " * 200)
    print(f"\n[2] (Demo 3 output not found - created a stand-in {enc_path})")
digest = sha3_256_file(enc_path)
digest_again = sha3_256_file(enc_path)
print(f"\n[2] Digest of {enc_path} ({enc_path.stat().st_size} bytes)")
print(f"    raw bytes  : {len(digest)} bytes")
print(f"    hex        : {digest.hex()}")
print(f"    same twice?  {digest == digest_again}  (deterministic)")

# ---- 3. One bit changed -> completely different digest -------------------
original = enc_path.read_bytes()
modified = bytearray(original)
modified[0] ^= 0x01
tampered_path = OUT / "fake_paper_TAMPERED.enc"
tampered_path.write_bytes(bytes(modified))
digest_tampered = sha3_256_file(tampered_path)
diff_bits = bits_different(digest, digest_tampered)
print(f"\n[3] Flip 1 bit in the file, hash again")
print(f"    original : {digest.hex()[:32]}...")
print(f"    tampered : {digest_tampered.hex()[:32]}...")
print(f"    digest bits changed: {diff_bits}/256 (about half = 'avalanche effect')")

# ---- 4. SHA3-256 vs SHA-256 vs Keccak-256 (important for Harsh) ----------
sha256_abc = hashlib.sha256(b"abc").hexdigest()
sha3_abc = sha3_256_bytes(b"abc").hex()
# Ethereum keccak256("abc") - published reference value (not computed here,
# because our crypto library deliberately doesn't include Ethereum's Keccak).
keccak_abc = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
print("\n[4] Three DIFFERENT algorithms, same input 'abc'")
print(f"    SHA-256     (PPT, old) : {sha256_abc[:32]}...")
print(f"    SHA3-256    (Option A) : {sha3_abc[:32]}...")
print(f"    Keccak-256  (Solidity) : {keccak_abc[:32]}...")
all_differ = len({sha256_abc, sha3_abc, keccak_abc}) == 3
print(f"    all three different?   {all_differ}")
print("    -> Tell Harsh: the contract should STORE our SHA3-256 value as bytes32,")
print("       not recompute it with Solidity's keccak256().")

# ---- 5. How the digest is handed to the blockchain -----------------------
print("\n[5] Format for the blockchain interface (PROPOSED - confirm with Harsh)")
print(f"    hash_algorithm  : SHA3-256")
print(f"    hashed bytes    : the exact encrypted file bytes (ciphertext + GCM tag)")
print(f"    bytes32 value   : 0x{digest.hex()}")

# ---- 6. Why a hash alone is not enough -----------------------------------
attacker_digest = sha3_256_bytes(bytes(modified))
print("\n[6] Attacker swaps the file AND recomputes the hash")
print(f"    attacker's new hash looks valid? {attacker_digest == digest_tampered}")
print("    LESSON: anyone can compute SHA3-256. To stop this, the digest must be")
print("    SIGNED (Demo 5, ML-DSA-65) or anchored on the blockchain (Harsh).")

checks = [
    vector_ok,
    digest == digest_again and len(digest) == 32,
    digest != digest_tampered,
    80 <= diff_bits <= 176,
    all_differ,
]
print("\n" + "-" * 64)
print(f"RESULT: {sum(checks)}/{len(checks)} expected behaviours observed")
print("DEMO 4 PASSED" if all(checks) else "DEMO 4 FAILED - send this output for troubleshooting")
