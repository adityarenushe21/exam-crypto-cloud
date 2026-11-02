r"""
Milestone 2 - Demo 3: AES-256-GCM (file encryption + tamper detection), on its own.

STORY
- AES-256-GCM encrypts the exam paper bytes with a 32-byte key.
  (In Milestone 3 this key will come from ML-KEM + HKDF. Here we just make one.)
- Every encryption needs a NONCE: 12 random bytes, NEVER reused with the same key.
  The nonce is not secret; it is stored next to the ciphertext.
- AAD ("additional authenticated data") = public labels like the paper ID.
  They are NOT encrypted, but if they change, decryption fails.
- Output = ciphertext + 16-byte TAG. The tag is a seal: change one bit of the
  ciphertext, tag, nonce, AAD or key -> decryption refuses (InvalidTag).

Uses FAKE test data only. Files go into the git-ignored output\ folder.

Run from the project root (venv active):
    python scripts\demos\demo_03_aesgcm.py
Optional - try your own NON-confidential test file:
    python scripts\demos\demo_03_aesgcm.py path\to\sample.pdf
"""

import hashlib
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OUT = Path("output")
OUT.mkdir(exist_ok=True)

print("=" * 64)
print("DEMO 3: AES-256-GCM")
print("=" * 64)

# ---- 1. Get the "paper" bytes -------------------------------------------
if len(sys.argv) > 1:
    source = Path(sys.argv[1])
    plaintext = source.read_bytes()
    print(f"\n[1] Using your test file: {source.name} ({len(plaintext)} bytes)")
else:
    plaintext = (b"%PDF-FAKE\nEXAM PAPER - FAKE TEST DATA\n"
                 b"Q1. Explain ML-KEM in one line.\nQ2. Why is nonce reuse dangerous?\n") * 50
    source = OUT / "fake_paper.txt"
    source.write_bytes(plaintext)
    print(f"\n[1] Created fake paper: {source} ({len(plaintext)} bytes)")

# ---- 2. Key, nonce, AAD ---------------------------------------------------
key = AESGCM.generate_key(bit_length=256)          # 32 bytes, SECRET
nonce = os.urandom(12)                              # 96-bit, fresh, not secret
paper_id = "PAPER-TEST-0001"
aad = f"exam-crypto-cloud|v1|paper_id={paper_id}".encode("utf-8")   # PROPOSED format
aesgcm = AESGCM(key)
print(f"\n[2] key {len(key)} B (secret) | nonce {len(nonce)} B (stored) | AAD: {aad.decode()}")

# ---- 3. Encrypt -----------------------------------------------------------
ciphertext = aesgcm.encrypt(nonce, plaintext, aad)  # = encrypted bytes + 16-byte tag
enc_path = OUT / "fake_paper.enc"
enc_path.write_bytes(ciphertext)
print(f"\n[3] Encrypted -> {enc_path}")
print(f"    plaintext {len(plaintext)} B -> ciphertext+tag {len(ciphertext)} B "
      f"(+{len(ciphertext) - len(plaintext)} B = GCM tag)")
print(f"    readable text inside .enc? {b'EXAM PAPER' in ciphertext}")

# ---- 4. Decrypt correctly -------------------------------------------------
recovered = aesgcm.decrypt(nonce, enc_path.read_bytes(), aad)
ok_roundtrip = recovered == plaintext
print(f"\n[4] Decrypt with correct key/nonce/AAD -> identical to original? {ok_roundtrip}")
print(f"    SHA3-256 original : {hashlib.sha3_256(plaintext).hexdigest()[:16]}...")
print(f"    SHA3-256 recovered: {hashlib.sha3_256(recovered).hexdigest()[:16]}...")

# ---- 5. Same file, encrypted again with a NEW nonce -----------------------
ciphertext2 = aesgcm.encrypt(os.urandom(12), plaintext, aad)
ok_fresh = ciphertext2 != ciphertext
print(f"\n[5] Same file + same key + NEW nonce -> different ciphertext? {ok_fresh}")


# ---- 6. Attacks: each must raise InvalidTag -------------------------------
def must_fail(label, k, n, ct, a):
    try:
        AESGCM(k).decrypt(n, ct, a)
        print(f"    [!!] {label:<34} -> DECRYPTED (BAD)")
        return False
    except InvalidTag:
        print(f"    [ok] {label:<34} -> InvalidTag, no plaintext returned")
        return True


def flip(data: bytes, index: int) -> bytes:
    b = bytearray(data)
    b[index] ^= 0x01
    return bytes(b)


print("\n[6] Tampering / wrong-input attempts")
attacks = [
    must_fail("1 bit flipped in ciphertext", key, nonce, flip(ciphertext, 100), aad),
    must_fail("1 bit flipped in tag (last 16 B)", key, nonce, flip(ciphertext, -1), aad),
    must_fail("ciphertext truncated", key, nonce, ciphertext[:-20], aad),
    must_fail("wrong key", AESGCM.generate_key(bit_length=256), nonce, ciphertext, aad),
    must_fail("wrong nonce", key, os.urandom(12), ciphertext, aad),
    must_fail("AAD says another paper_id", key, nonce, ciphertext,
              b"exam-crypto-cloud|v1|paper_id=PAPER-TEST-9999"),
]

print("\n    LESSON: AES-GCM is 'all or nothing'. Any change -> InvalidTag and")
print("    zero plaintext. This is what catches the wrong-key case ML-KEM can't.")
print("    NEVER reuse a nonce with the same key: that can leak plaintext and")
print("    let an attacker forge tags.")

checks = [ok_roundtrip, ok_fresh, b"EXAM PAPER" not in ciphertext, *attacks]
print("\n" + "-" * 64)
print(f"RESULT: {sum(checks)}/{len(checks)} expected behaviours observed")
print("DEMO 3 PASSED" if all(checks) else "DEMO 3 FAILED - send this output for troubleshooting")
