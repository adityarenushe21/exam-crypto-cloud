"""The combined Option A pipeline: seal (upload side) and verify/release (release side).

SEAL ORDER
  1. authorize (exam_authority)   2. validate input
  3. new paper_id / next version  4. ML-KEM encapsulate to release public key
  5. HKDF -> AES key              6. AES-256-GCM encrypt (fresh nonce, AAD)
  7. SHA3-256(ciphertext)         8. build manifest, ML-DSA-65 sign
  9. store ciphertext + manifest (write-once). Plaintext is never stored.

RELEASE ORDER (fail closed at the first problem)
  1. authorize (release_officer)
  2. load + strictly validate manifest
  3. signer_key_id == trusted key, verify ML-DSA signature
  4. recompute SHA3-256 of stored ciphertext, compare with SIGNED digest
  5. release time check using the SIGNED release_at_utc
  6. on-chain authorization (Harsh's ExamVault): status RELEASED by custodian
     threshold, and the chain's masterHash == our signed ciphertext digest
  7. only now unlock the ML-KEM private key, decapsulate, HKDF, AES-GCM decrypt
"""

import re
import secrets
from datetime import datetime

from . import aead, authz, kdf, kem, signatures
from . import constants as C
from . import manifest as mf
from .encoding import b64d, b64e, format_utc, parse_utc, utc_now
from .errors import (ExamCryptoError, CIPHERTEXT_DIGEST_MISMATCH, FILE_TOO_LARGE, INVALID_INPUT,
                     MANIFEST_MALFORMED,
                     NOT_A_PDF, PAPER_NOT_FOUND, RELEASE_TIME_NOT_REACHED, UNTRUSTED_SIGNER,
                     WRONG_RECIPIENT_KEY)
from .hashing import digests_equal, key_id, sha3_256_hex
from .storage import object_keys

_ID_RE = re.compile(C.ID_PATTERN)


def new_paper_id() -> str:
    return "pap_" + secrets.token_hex(8)       # opaque, reveals nothing about the exam


# ======================================================================= SEAL
def seal_paper(*, storage, recipient_public, signer_private, plaintext: bytes,
               exam_id: str, release_at_utc: str, actor: dict,
               paper_id: str | None = None, now: datetime | None = None) -> dict:
    authz.require(actor, "seal")
    now = now or utc_now()

    # -- validate input
    if not isinstance(plaintext, bytes) or len(plaintext) == 0:
        raise ExamCryptoError(INVALID_INPUT, "empty file")
    if len(plaintext) > C.MAX_UPLOAD_BYTES:
        raise ExamCryptoError(FILE_TOO_LARGE, f"limit is {C.MAX_UPLOAD_BYTES} bytes")
    if not plaintext.startswith(C.PDF_MAGIC):
        raise ExamCryptoError(NOT_A_PDF, "file does not start with %PDF-")
    if not isinstance(exam_id, str) or not _ID_RE.match(exam_id):
        raise ExamCryptoError(INVALID_INPUT, "exam_id: 1-64 chars of A-Z a-z 0-9 _ -")
    release_dt = parse_utc(release_at_utc)
    if release_dt <= now:
        raise ExamCryptoError(INVALID_INPUT, "release_at_utc must be in the future")
    release_at_utc = format_utc(release_dt)

    # -- id and version
    if paper_id is None:
        paper_id = new_paper_id()
        version = 1
    else:
        if not _ID_RE.match(paper_id):
            raise ExamCryptoError(INVALID_INPUT, "bad paper_id")
        existing = storage.versions(paper_id)
        if not existing:
            raise ExamCryptoError(PAPER_NOT_FOUND, f"{paper_id} has no versions yet")
        version = max(existing) + 1
    ct_key, mf_key = object_keys(paper_id, version)

    # -- crypto
    shared_secret, kem_ct = kem.encapsulate(recipient_public)
    salt = secrets.token_bytes(C.HKDF_SALT_BYTES)
    info = kdf.hkdf_info(paper_id, version)
    content_key = kdf.derive_content_key(shared_secret, salt, info)
    aad = aead.build_aad(paper_id, version, exam_id, release_at_utc)
    nonce, ciphertext = aead.encrypt(content_key, plaintext, aad)
    del shared_secret, content_key                      # not stored anywhere

    signer_public = signer_private.public_key()
    manifest = {
        "schema_version": C.SCHEMA_VERSION,
        "paper_id": paper_id,
        "paper_version": version,
        "exam_id": exam_id,
        "created_at_utc": format_utc(now),
        "release_at_utc": release_at_utc,
        "content_type": "application/pdf",
        "plaintext_size": len(plaintext),
        "kem_algorithm": C.KEM_ALGORITHM,
        "recipient_key_id": key_id(recipient_public.public_bytes_raw()),
        "kem_ciphertext_b64": b64e(kem_ct),
        "kdf_algorithm": C.KDF_ALGORITHM,
        "hkdf_salt_b64": b64e(salt),
        "hkdf_info": info,
        "aead_algorithm": C.AEAD_ALGORITHM,
        "aes_gcm_nonce_b64": b64e(nonce),
        "aad": aad,
        "hash_algorithm": C.HASH_ALGORITHM,
        "ciphertext_sha3_256_hex": sha3_256_hex(ciphertext),
        "signature_algorithm": C.SIGNATURE_ALGORITHM,
        "signature_context": C.SIGNATURE_CONTEXT,
        "signer_key_id": key_id(signer_public.public_bytes_raw()),
    }
    signature = signatures.sign(signer_private, mf.signed_bytes(manifest))

    # -- store (ciphertext first; manifest last marks the version complete)
    storage.put(ct_key, ciphertext)
    storage.put(mf_key, mf.to_envelope_bytes(manifest, b64e(signature)))

    return {
        "paper_id": paper_id,
        "paper_version": version,
        "status": "SEALED",
        "ciphertext_sha3_256_hex": manifest["ciphertext_sha3_256_hex"],
        "manifest_sha3_256_hex": sha3_256_hex(mf.signed_bytes(manifest)),
        "release_at_utc": release_at_utc,
        "signer_key_id": manifest["signer_key_id"],
        "recipient_key_id": manifest["recipient_key_id"],
    }


# ===================================================================== VERIFY
def _latest_version(storage, paper_id: str) -> int:
    versions = storage.versions(paper_id)
    if not versions:
        raise ExamCryptoError(PAPER_NOT_FOUND, f"{paper_id} not found")
    return max(versions)


def verify_paper(*, storage, paper_id: str, trusted_signer_public, actor: dict,
                 version: int | None = None) -> tuple[dict, bytes]:
    """Signature + integrity check only. Never touches the decryption key."""
    authz.require(actor, "verify")
    return _verify(storage, paper_id, trusted_signer_public, version)


def _verify(storage, paper_id, trusted_signer_public, version):
    if not isinstance(paper_id, str) or not _ID_RE.match(paper_id):
        raise ExamCryptoError(INVALID_INPUT, "bad paper_id")
    version = version or _latest_version(storage, paper_id)
    ct_key, mf_key = object_keys(paper_id, version)

    manifest, signature_b64 = mf.from_envelope_bytes(storage.get(mf_key))
    if manifest["paper_id"] != paper_id or manifest["paper_version"] != version:
        raise ExamCryptoError(INVALID_INPUT, "manifest does not belong to this object path")

    trusted_id = key_id(trusted_signer_public.public_bytes_raw())
    if not digests_equal(manifest["signer_key_id"], trusted_id):
        raise ExamCryptoError(UNTRUSTED_SIGNER, "manifest names a signer we do not trust")
    signatures.verify(trusted_signer_public, b64d(signature_b64), mf.signed_bytes(manifest))

    ciphertext = storage.get(ct_key)
    if not digests_equal(sha3_256_hex(ciphertext), manifest["ciphertext_sha3_256_hex"]):
        raise ExamCryptoError(CIPHERTEXT_DIGEST_MISMATCH, "stored ciphertext was changed")
    return manifest, ciphertext


# ==================================================================== RELEASE
def release_paper(*, storage, paper_id: str, trusted_signer_public, load_recipient_private,
                  actor: dict, version: int | None = None,
                  now: datetime | None = None, chain_authorize=None) -> tuple[dict, bytes]:
    """Returns (manifest, plaintext). load_recipient_private is a function that
    unlocks the ML-KEM private key; it is called ONLY after every check passed.
    chain_authorize(manifest) must raise ExamCryptoError if the blockchain does not
    authorize release (None = offline mode, used by unit tests and the CLI demo)."""
    authz.require(actor, "release")
    manifest, ciphertext = _verify(storage, paper_id, trusted_signer_public, version)

    # Derived labels must match what the signed IDs imply (defence in depth).
    expected_info = kdf.hkdf_info(manifest["paper_id"], manifest["paper_version"])
    expected_aad = aead.build_aad(manifest["paper_id"], manifest["paper_version"],
                                  manifest["exam_id"], manifest["release_at_utc"])
    if manifest["aad"] != expected_aad or manifest["hkdf_info"] != expected_info:
        raise ExamCryptoError(MANIFEST_MALFORMED, "manifest aad/hkdf_info inconsistent")

    now = now or utc_now()
    if now < parse_utc(manifest["release_at_utc"]):
        raise ExamCryptoError(RELEASE_TIME_NOT_REACHED,
                              f"paper opens at {manifest['release_at_utc']}")

    if chain_authorize is not None:
        chain_authorize(manifest)

    recipient_private = load_recipient_private()
    my_id = key_id(recipient_private.public_key().public_bytes_raw())
    if not digests_equal(manifest["recipient_key_id"], my_id):
        raise ExamCryptoError(WRONG_RECIPIENT_KEY, "paper was sealed for a different release key")

    shared_secret = kem.decapsulate(recipient_private, b64d(manifest["kem_ciphertext_b64"]))
    content_key = kdf.derive_content_key(shared_secret, b64d(manifest["hkdf_salt_b64"]),
                                         expected_info)
    plaintext = aead.decrypt(content_key, b64d(manifest["aes_gcm_nonce_b64"]),
                             ciphertext, expected_aad)
    return manifest, plaintext


# ============================================================== CHAIN CHECK
def check_chain_authorization(manifest: dict, chain_status: dict) -> None:
    """Fail closed unless the on-chain record says this exact paper was RELEASED."""
    from .blockchain import BLOCKING_STATUSES
    from .errors import (CHAIN_NOT_RELEASED, CHAIN_PAPER_BLOCKED, CHAIN_RECORD_MISMATCH,
                         CHAIN_UNKNOWN_PAPER)

    if not chain_status.get("found"):
        raise ExamCryptoError(CHAIN_UNKNOWN_PAPER, "paper is not registered on the blockchain")
    status = chain_status.get("status")
    if status in BLOCKING_STATUSES:
        raise ExamCryptoError(CHAIN_PAPER_BLOCKED, f"blockchain status is {status}")
    expected = "0x" + manifest["ciphertext_sha3_256_hex"]
    if not digests_equal(str(chain_status.get("master_hash", "")).lower(), expected):
        raise ExamCryptoError(CHAIN_RECORD_MISMATCH, "on-chain digest differs from stored paper")
    if int(chain_status.get("release_at_unix", 0)) < int(parse_utc(manifest["release_at_utc"]).timestamp()):
        raise ExamCryptoError(CHAIN_RECORD_MISMATCH, "on-chain release time is earlier than signed time")
    if status != "RELEASED":
        raise ExamCryptoError(CHAIN_NOT_RELEASED,
                              f"custodian approvals {chain_status.get('approvals', 0)}"
                              f"/{chain_status.get('threshold', '?')} (status {status})")
