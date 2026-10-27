r"""
Milestone 2 - Demo 1: ML-KEM-768 (key encapsulation), on its own.

STORY
- The RELEASE SERVICE owns an ML-KEM key pair.
    public key  -> can be given to anyone (the uploader needs it)
    private key -> must stay secret inside the release service
- The UPLOADER uses only the public key to "encapsulate":
    it gets (shared_secret, kem_ciphertext).
    shared_secret stays with the uploader; kem_ciphertext is stored with the paper.
- Later, the RELEASE SERVICE "decapsulates" kem_ciphertext with its private key
  and gets the SAME shared_secret back.
- ML-KEM does NOT encrypt the PDF. It only gives both sides the same 32-byte secret.

DEMO ONLY: we print the first few hex characters of secrets so you can see they
match. Real application code must NEVER print or log secrets.

Run from the project root (venv active):
    python scripts\demos\demo_01_mlkem.py
"""

import hashlib

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)


def short(b: bytes) -> str:
    """First 16 hex chars only - enough to compare, not the whole value."""
    return b.hex()[:16] + "..."


def key_id(public_key: MLKEM768PublicKey) -> str:
    """A short, public identifier for a public key (a 'fingerprint')."""
    return hashlib.sha3_256(public_key.public_bytes_raw()).hexdigest()[:16]


print("=" * 64)
print("DEMO 1: ML-KEM-768")
print("=" * 64)

# 1. Release service creates its key pair (done once, then stored safely).
release_private = MLKEM768PrivateKey.generate()
release_public = release_private.public_key()
print("\n[1] Release service key pair created")
print(f"    public key size : {len(release_public.public_bytes_raw())} bytes (safe to share)")
print(f"    private seed    : {len(release_private.private_bytes_raw())} bytes (SECRET)")
print(f"    public key ID   : {key_id(release_public)}")

# 2. Uploader gets ONLY the public key (as raw bytes, like reading it from a file).
public_bytes_given_to_uploader = release_public.public_bytes_raw()
uploader_view_of_public = MLKEM768PublicKey.from_public_bytes(public_bytes_given_to_uploader)

# 3. Uploader encapsulates.
uploader_secret, kem_ciphertext = uploader_view_of_public.encapsulate()
print("\n[2] Uploader encapsulated using the PUBLIC key only")
print(f"    shared secret   : {len(uploader_secret)} bytes  {short(uploader_secret)}  (stays with uploader)")
print(f"    KEM ciphertext  : {len(kem_ciphertext)} bytes (stored next to the encrypted paper)")

# 4. Release service decapsulates.
release_secret = release_private.decapsulate(kem_ciphertext)
print("\n[3] Release service decapsulated using its PRIVATE key")
print(f"    shared secret   : {len(release_secret)} bytes  {short(release_secret)}")
print(f"    SAME as uploader? {release_secret == uploader_secret}")

# 5. Encapsulating again gives a NEW secret every time (fresh per paper).
second_secret, second_ct = uploader_view_of_public.encapsulate()
print("\n[4] Encapsulating a second time (e.g. for the next paper)")
print(f"    new secret differs from first? {second_secret != uploader_secret}")
print(f"    new ciphertext differs?        {second_ct != kem_ciphertext}")

# 6. Wrong private key: NO error is raised - you just get a different, useless secret.
attacker_private = MLKEM768PrivateKey.generate()
wrong_secret = attacker_private.decapsulate(kem_ciphertext)
print("\n[5] Someone decapsulates with the WRONG private key")
print(f"    error raised?   No - ML-KEM returns a random-looking value instead")
print(f"    matches real secret? {wrong_secret == uploader_secret}")

# 7. Tampered KEM ciphertext: also no error, also a different secret.
tampered = bytearray(kem_ciphertext)
tampered[10] ^= 0x01
tampered_secret = release_private.decapsulate(bytes(tampered))
print("\n[6] KEM ciphertext tampered (1 bit flipped), correct private key")
print(f"    matches real secret? {tampered_secret == uploader_secret}")
print("    LESSON: ML-KEM never says 'wrong'. The AES-GCM tag check (Demo 3)")
print("    is what detects a wrong key or tampering, so decryption fails safely.")

# 8. Saving and reloading the private key (needed so old papers stay decryptable).
saved_seed = release_private.private_bytes_raw()          # 64 bytes
reloaded_private = MLKEM768PrivateKey.from_seed_bytes(saved_seed)
reloaded_secret = reloaded_private.decapsulate(kem_ciphertext)
print("\n[7] Private key saved as a 64-byte seed and reloaded (simulated restart)")
print(f"    same public key ID? {key_id(reloaded_private.public_key()) == key_id(release_public)}")
print(f"    still recovers the secret? {reloaded_secret == uploader_secret}")
print("    (Milestone 3 will store this seed in a protected, git-ignored file.)")

checks = [
    release_secret == uploader_secret,
    len(uploader_secret) == 32 and len(kem_ciphertext) == 1088,
    second_secret != uploader_secret,
    wrong_secret != uploader_secret,
    tampered_secret != uploader_secret,
    reloaded_secret == uploader_secret,
]
print("\n" + "-" * 64)
print(f"RESULT: {sum(checks)}/{len(checks)} expected behaviours observed")
print("DEMO 1 PASSED" if all(checks) else "DEMO 1 FAILED - send this output for troubleshooting")
