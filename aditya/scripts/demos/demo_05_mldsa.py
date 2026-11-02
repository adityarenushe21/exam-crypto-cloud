r"""
Milestone 2 - Demo 5: ML-DSA-65 (digital signature), on its own.

STORY
- The EXAMINATION AUTHORITY owns an ML-DSA-65 signing key pair.
    private key -> signs (SECRET, stays with the authority/upload service)
    public key  -> verifies (given to the release service in advance = "trusted")
- We sign a MANIFEST: a small record that binds together the paper ID,
  release time and the SHA3-256 digest of the encrypted file.
- If anyone changes the manifest (e.g. moves the release time earlier) or
  swaps the encrypted file, verification fails.
- This is a DIFFERENT key pair from the ML-KEM one. Never reuse keys across jobs.

The manifest fields and serialization below are a PROPOSAL for Milestone 3.

Run from the project root (venv active):
    python scripts\demos\demo_05_mldsa.py
"""

import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA65PrivateKey,
    MLDSA65PublicKey,
)

CONTEXT = b"exam-crypto-cloud/manifest/v1"   # domain separation label (<= 255 bytes)


def canonical_bytes(manifest: dict) -> bytes:
    """One exact byte form: sorted keys, no spaces, ASCII only, UTF-8.
    Signing 'pretty' JSON is unsafe: same data could produce different bytes."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def key_id(pub: MLDSA65PublicKey) -> str:
    return hashlib.sha3_256(pub.public_bytes_raw()).hexdigest()[:16]


def verifies(pub, signature, data, context=CONTEXT) -> bool:
    try:
        pub.verify(signature, data, context)
        return True
    except InvalidSignature:
        return False


print("=" * 64)
print("DEMO 5: ML-DSA-65")
print("=" * 64)

# ---- 1. Authority key pair -------------------------------------------------
authority_private = MLDSA65PrivateKey.generate()
authority_public = authority_private.public_key()
trusted_public_bytes = authority_public.public_bytes_raw()   # shared in advance
print("\n[1] Examination authority signing key pair")
print(f"    private seed : {len(authority_private.private_bytes_raw())} bytes (SECRET)")
print(f"    public key   : {len(trusted_public_bytes)} bytes (given to release service)")
print(f"    signer key ID: {key_id(authority_public)}")

# ---- 2. Build the manifest -------------------------------------------------
enc_path = Path("output") / "fake_paper.enc"
cipher_digest = (hashlib.sha3_256(enc_path.read_bytes()).hexdigest()
                 if enc_path.exists() else hashlib.sha3_256(b"stand-in").hexdigest())
manifest = {
    "schema_version": "1",
    "paper_id": "PAPER-TEST-0001",
    "release_at_utc": "2026-12-01T09:00:00Z",
    "hash_algorithm": "SHA3-256",
    "ciphertext_sha3_256_hex": cipher_digest,
    "signature_algorithm": "ML-DSA-65",
    "signer_key_id": key_id(authority_public),
}
signed_bytes = canonical_bytes(manifest)
print("\n[2] Manifest (canonical bytes that get signed):")
print(f"    {signed_bytes.decode()[:90]}...")
print(f"    length: {len(signed_bytes)} bytes")

# ---- 3. Sign ----------------------------------------------------------------
signature = authority_private.sign(signed_bytes, CONTEXT)
print(f"\n[3] Signed with context '{CONTEXT.decode()}'")
print(f"    signature size: {len(signature)} bytes")

# ---- 4. Release service verifies with the TRUSTED public key --------------
release_view = MLDSA65PublicKey.from_public_bytes(trusted_public_bytes)
ok_valid = verifies(release_view, signature, signed_bytes)
print(f"\n[4] Release service verifies with trusted public key -> valid? {ok_valid}")

# Same manifest written with different key order / spacing -> same canonical bytes
reordered = dict(reversed(list(manifest.items())))
ok_canonical = canonical_bytes(reordered) == signed_bytes
print(f"    same data, different key order -> same signed bytes? {ok_canonical}")

# ---- 5. Attacks -------------------------------------------------------------
print("\n[5] Attacks - each must FAIL verification")


def attack(label, pub, sig, data, context=CONTEXT):
    rejected = not verifies(pub, sig, data, context)
    print(f"    [{'ok' if rejected else '!!'}] {label:<40} -> {'rejected' if rejected else 'ACCEPTED (BAD)'}")
    return rejected


early = dict(manifest, release_at_utc="2026-11-01T09:00:00Z")
swapped = dict(manifest, ciphertext_sha3_256_hex=hashlib.sha3_256(b"attacker file").hexdigest())
bad_sig = bytearray(signature)
bad_sig[50] ^= 0x01
attacker_private = MLDSA65PrivateKey.generate()
attacker_sig = attacker_private.sign(canonical_bytes(early), CONTEXT)

attacks = [
    attack("release time moved 1 month earlier", release_view, signature, canonical_bytes(early)),
    attack("encrypted-file digest swapped", release_view, signature, canonical_bytes(swapped)),
    attack("1 bit flipped in signature", release_view, bytes(bad_sig), signed_bytes),
    attack("wrong context label", release_view, signature, signed_bytes, b"some-other-purpose"),
    attack("attacker signs fake manifest w/ own key", release_view, attacker_sig, canonical_bytes(early)),
]

# ---- 6. Save / reload the signing key --------------------------------------
seed = authority_private.private_bytes_raw()          # 32 bytes
reloaded = MLDSA65PrivateKey.from_seed_bytes(seed)
sig_after_reload = reloaded.sign(signed_bytes, CONTEXT)
ok_reload = (key_id(reloaded.public_key()) == key_id(authority_public)
             and verifies(release_view, sig_after_reload, signed_bytes))
print(f"\n[6] Signing key saved as {len(seed)}-byte seed and reloaded")
print(f"    same key ID and new signature still valid? {ok_reload}")
print(f"    two signatures of same data identical? {sig_after_reload == signature}"
      "  (False is expected: hedged/randomized signing; both are valid)")

print("\n    LESSON: the signature proves the manifest was signed by whoever holds")
print("    the private key that matches the TRUSTED public key. The public key")
print("    must come from a trusted source - never from the manifest itself.")
print("    (Attack 5 only fails because the release service ignores the")
print("    attacker's public key and uses the one it already trusts.)")

checks = [ok_valid, ok_canonical, *attacks, ok_reload]
print("\n" + "-" * 64)
print(f"RESULT: {sum(checks)}/{len(checks)} expected behaviours observed")
print("DEMO 5 PASSED" if all(checks) else "DEMO 5 FAILED - send this output for troubleshooting")
