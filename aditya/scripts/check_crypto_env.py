r"""
Milestone 1 environment check for the exam-crypto-cloud project.

What this script does (and does NOT do):
- It checks that you are running inside the project's virtual environment.
- It prints the Python, cryptography and OpenSSL versions actually in use.
- It runs one tiny self-test for each Option A algorithm:
  ML-KEM-768, HKDF-SHA-256, AES-256-GCM, SHA3-256, ML-DSA-65.
- It uses throw-away keys created in memory. Nothing is saved to disk,
  no network calls are made, and no AWS service is touched.

Run from the project root (with the venv active):
    python scripts\check_crypto_env.py
"""

import os
import sys

results = []  # list of (name, passed: bool, detail: str)


def record(name, passed, detail=""):
    results.append((name, passed, detail))
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


print("=" * 64)
print("exam-crypto-cloud : Milestone 1 crypto environment check")
print("=" * 64)

# ---------------------------------------------------------------- 1. venv
in_venv = sys.prefix != sys.base_prefix
print(f"Python version   : {sys.version.split()[0]}")
print(f"Python executable: {sys.executable}")
record("Running inside a virtual environment", in_venv,
       "" if in_venv else "activate .venv first (see README)")

# ---------------------------------------------------------- 2. library
try:
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    print(f"cryptography     : {cryptography.__version__}")
    print(f"Crypto backend   : {backend.openssl_version_text()}")
    major = int(cryptography.__version__.split(".")[0])
    record("cryptography >= 48 (needed for ML-KEM/ML-DSA in pip wheels)",
           major >= 48, f"found {cryptography.__version__}")
except Exception as exc:  # library missing entirely
    record("Import cryptography", False, repr(exc))
    print("\nStopping: install requirements first (pip install -r requirements.txt)")
    sys.exit(1)

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm

# ------------------------------------------------------------ 3. ML-KEM-768
try:
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

    recipient_private = MLKEM768PrivateKey.generate()          # receiver's key pair
    recipient_public = recipient_private.public_key()
    sender_secret, kem_ciphertext = recipient_public.encapsulate()  # sender side
    receiver_secret = recipient_private.decapsulate(kem_ciphertext)  # receiver side
    ok = (sender_secret == receiver_secret and len(sender_secret) == 32
          and len(kem_ciphertext) == 1088
          and len(recipient_public.public_bytes_raw()) == 1184)
    record("ML-KEM-768 encapsulate/decapsulate", ok,
           f"shared secret {len(sender_secret)} B, KEM ciphertext {len(kem_ciphertext)} B")
except UnsupportedAlgorithm as exc:
    record("ML-KEM-768 encapsulate/decapsulate", False, f"backend does not support it: {exc}")
    sender_secret = None
except Exception as exc:
    record("ML-KEM-768 encapsulate/decapsulate", False, repr(exc))
    sender_secret = None

# ---------------------------------------------------------- 4. HKDF-SHA-256
aes_key = None
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    ikm = sender_secret if sender_secret else os.urandom(32)  # fall back so other tests still run
    salt = os.urandom(32)
    info = b"exam-crypto-cloud/v1/aes-256-gcm-key/env-check"

    def derive():
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)

    k1, k2 = derive(), derive()
    other = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                 info=b"different-context").derive(ikm)
    ok = len(k1) == 32 and k1 == k2 and k1 != other
    aes_key = k1
    record("HKDF-SHA-256 derive 32-byte key", ok,
           "same inputs -> same key; different info -> different key")
except Exception as exc:
    record("HKDF-SHA-256 derive 32-byte key", False, repr(exc))

# ----------------------------------------------------------- 5. AES-256-GCM
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = aes_key or AESGCM.generate_key(bit_length=256)
    aead = AESGCM(key)
    nonce = os.urandom(12)                      # 96-bit nonce, fresh every time
    aad = b"exam-crypto-cloud/v1|paper-id=TEST"
    plaintext = b"Sample exam paper bytes (FAKE TEST DATA)"
    ct = aead.encrypt(nonce, plaintext, aad)    # ciphertext + 16-byte tag
    roundtrip = aead.decrypt(nonce, ct, aad) == plaintext

    tampered = bytearray(ct)
    tampered[0] ^= 0x01                          # flip one bit
    try:
        aead.decrypt(nonce, bytes(tampered), aad)
        tamper_rejected = False
    except InvalidTag:
        tamper_rejected = True

    try:
        aead.decrypt(nonce, ct, b"wrong-aad")
        aad_rejected = False
    except InvalidTag:
        aad_rejected = True

    record("AES-256-GCM encrypt/decrypt", roundtrip and len(key) == 32,
           f"plaintext {len(plaintext)} B -> ciphertext+tag {len(ct)} B")
    record("AES-256-GCM rejects tampered ciphertext", tamper_rejected, "InvalidTag raised")
    record("AES-256-GCM rejects wrong AAD", aad_rejected, "InvalidTag raised")
except Exception as exc:
    record("AES-256-GCM", False, repr(exc))

# -------------------------------------------------------------- 6. SHA3-256
try:
    from cryptography.hazmat.primitives import hashes

    def sha3_256_hex(data: bytes) -> str:
        h = hashes.Hash(hashes.SHA3_256())
        h.update(data)
        return h.finalize().hex()

    # Official NIST test vector: SHA3-256("abc")
    expected = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    got = sha3_256_hex(b"abc")
    record("SHA3-256 matches NIST test vector for 'abc'", got == expected, got)
    record("SHA3-256 changes when input changes",
           sha3_256_hex(b"abc") != sha3_256_hex(b"abd"))
except Exception as exc:
    record("SHA3-256", False, repr(exc))

# ------------------------------------------------------------- 7. ML-DSA-65
try:
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

    signer_private = MLDSA65PrivateKey.generate()
    signer_public = signer_private.public_key()
    message = b'{"exam_id":"TEST-001","release_at_utc":"2026-12-01T09:00:00Z"}'
    context = b"exam-crypto-cloud/manifest/v1"
    signature = signer_private.sign(message, context)
    signer_public.verify(signature, message, context)   # raises if bad
    record("ML-DSA-65 sign/verify", True,
           f"signature {len(signature)} B, public key {len(signer_public.public_bytes_raw())} B")

    try:
        signer_public.verify(signature, message.replace(b"09:00", b"08:00"), context)
        modified_rejected = False
    except InvalidSignature:
        modified_rejected = True
    record("ML-DSA-65 rejects modified message", modified_rejected, "InvalidSignature raised")

    try:
        signer_public.verify(signature, message, b"wrong-context")
        ctx_rejected = False
    except InvalidSignature:
        ctx_rejected = True
    record("ML-DSA-65 rejects wrong context", ctx_rejected, "InvalidSignature raised")
except UnsupportedAlgorithm as exc:
    record("ML-DSA-65 sign/verify", False, f"backend does not support it: {exc}")
except Exception as exc:
    record("ML-DSA-65 sign/verify", False, repr(exc))

# ---------------------------------------------------------------- summary
passed = sum(1 for _, ok, _ in results if ok)
print("-" * 64)
print(f"RESULT: {passed}/{len(results)} checks passed")
if passed == len(results):
    print("ALL CHECKS PASSED - environment is ready for Milestone 2.")
    sys.exit(0)
print("SOME CHECKS FAILED - copy this whole output and send it for troubleshooting.")
sys.exit(1)
