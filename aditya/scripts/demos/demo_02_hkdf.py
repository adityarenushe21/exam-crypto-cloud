# ExamVault capstone project | Aditya Renushe | MIT World Peace University, Pune
# Module: secure upload, post-quantum encryption and cloud storage
# SPDX-License-Identifier: MIT
r"""
Milestone 2 - Demo 2: HKDF-SHA-256 (key derivation), on its own.

STORY
- Demo 1 gave the uploader and the release service the SAME 32-byte shared secret.
- HKDF turns that secret into the actual AES-256 key, and "labels" the key with
  what it is for (protocol version, purpose, which paper).
- Inputs:
    ikm  (input key material) = ML-KEM shared secret  -> SECRET
    salt = 32 random bytes, stored next to the paper  -> NOT secret
    info = context label, e.g. protocol + paper ID    -> NOT secret
- Output: 32 bytes = an AES-256 key. Same inputs always give the same key,
  so the release service can re-derive it later.

The info format below is a PROPOSAL for Milestone 3, not a final decision.

DEMO ONLY: we print the first few hex characters of keys so you can compare them.
Real application code must NEVER print or log keys or secrets.

Run from the project root (venv active):
    python scripts\demos\demo_02_hkdf.py
"""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL = "exam-crypto-cloud"
VERSION = "v1"
PURPOSE = "aes-256-gcm-content-key"


def build_info(paper_id: str) -> bytes:
    """Context label. Changing ANY part gives a completely different key."""
    return f"{PROTOCOL}|{VERSION}|{PURPOSE}|paper_id={paper_id}".encode("utf-8")


def derive_aes_key(shared_secret: bytes, salt: bytes, paper_id: str) -> bytes:
    """HKDF-SHA-256 -> 32-byte AES-256 key. An HKDF object can be used only once."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=build_info(paper_id))
    return hkdf.derive(shared_secret)


def short(b: bytes) -> str:
    return b.hex()[:16] + "..."


print("=" * 64)
print("DEMO 2: HKDF-SHA-256")
print("=" * 64)

# Reuse the Demo 1 flow to get a real ML-KEM shared secret on both sides.
release_private = MLKEM768PrivateKey.generate()
uploader_secret, kem_ciphertext = release_private.public_key().encapsulate()
release_secret = release_private.decapsulate(kem_ciphertext)

paper_id = "PAPER-TEST-0001"          # fake ID for the demo
salt = os.urandom(32)                 # fresh random salt per paper, stored with it
print(f"\n[1] Inputs")
print(f"    shared secret (from ML-KEM): 32 bytes  {short(uploader_secret)}  SECRET")
print(f"    salt (random, stored)      : {len(salt)} bytes  {short(salt)}  not secret")
print(f"    info (context label)       : {build_info(paper_id).decode()}")

# Uploader derives the key at upload time.
uploader_key = derive_aes_key(uploader_secret, salt, paper_id)
# Release service re-derives it later from ITS copy of the secret + stored salt.
release_key = derive_aes_key(release_secret, salt, paper_id)
print(f"\n[2] Derived AES-256 key")
print(f"    uploader key     : {len(uploader_key)} bytes  {short(uploader_key)}")
print(f"    release svc key  : {len(release_key)} bytes  {short(release_key)}")
print(f"    SAME key on both sides? {uploader_key == release_key}")

# Each input matters.
key_other_salt = derive_aes_key(uploader_secret, os.urandom(32), paper_id)
key_other_paper = derive_aes_key(uploader_secret, salt, "PAPER-TEST-0002")
other_secret, _ = release_private.public_key().encapsulate()
key_other_secret = derive_aes_key(other_secret, salt, paper_id)
print(f"\n[3] Change one input at a time -> is the key different?")
print(f"    different salt     : {key_other_salt != uploader_key}")
print(f"    different paper_id : {key_other_paper != uploader_key}   (key is bound to ONE paper)")
print(f"    different secret   : {key_other_secret != uploader_key}")

# Reusing an HKDF object is not allowed (library protects you).
hkdf_once = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=build_info(paper_id))
hkdf_once.derive(uploader_secret)
try:
    hkdf_once.derive(uploader_secret)
    reuse_blocked = False
except Exception as exc:  # cryptography raises AlreadyFinalized
    reuse_blocked = True
    print(f"\n[4] Reusing the same HKDF object -> blocked ({type(exc).__name__})")

print("\n    LESSON: the salt and info are stored/known publicly; only the shared")
print("    secret is secret. The release service needs secret + salt + paper_id")
print("    to rebuild the exact same AES key.")

checks = [
    uploader_key == release_key,
    len(uploader_key) == 32,
    key_other_salt != uploader_key,
    key_other_paper != uploader_key,
    key_other_secret != uploader_key,
    reuse_blocked,
]
print("\n" + "-" * 64)
print(f"RESULT: {sum(checks)}/{len(checks)} expected behaviours observed")
print("DEMO 2 PASSED" if all(checks) else "DEMO 2 FAILED - send this output for troubleshooting")
