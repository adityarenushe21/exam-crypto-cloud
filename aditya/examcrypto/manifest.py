"""Manifest format v1: exactly these fields, no more, no less.

Stored as manifest.json = {"manifest": {...}, "signature_b64": "..."}
The signature covers canonical_json(manifest) ONLY (never the signature itself).
"""

import json

from . import constants as C
from .encoding import canonical_json
from .errors import ExamCryptoError, MANIFEST_MALFORMED, UNSUPPORTED_VERSION

# field name -> expected Python type
FIELDS_V1 = {
    "schema_version": str,
    "paper_id": str,
    "paper_version": int,
    "exam_id": str,
    "created_at_utc": str,
    "release_at_utc": str,
    "content_type": str,
    "plaintext_size": int,
    "kem_algorithm": str,
    "recipient_key_id": str,
    "kem_ciphertext_b64": str,
    "kdf_algorithm": str,
    "hkdf_salt_b64": str,
    "hkdf_info": str,
    "aead_algorithm": str,
    "aes_gcm_nonce_b64": str,
    "aad": str,
    "hash_algorithm": str,
    "ciphertext_sha3_256_hex": str,
    "signature_algorithm": str,
    "signature_context": str,
    "signer_key_id": str,
}

# Fields whose value is fixed in v1. Anything else -> rejected.
FIXED_V1 = {
    "schema_version": C.SCHEMA_VERSION,
    "content_type": "application/pdf",
    "kem_algorithm": C.KEM_ALGORITHM,
    "kdf_algorithm": C.KDF_ALGORITHM,
    "aead_algorithm": C.AEAD_ALGORITHM,
    "hash_algorithm": C.HASH_ALGORITHM,
    "signature_algorithm": C.SIGNATURE_ALGORITHM,
    "signature_context": C.SIGNATURE_CONTEXT,
}


def signed_bytes(manifest: dict) -> bytes:
    validate(manifest)
    return canonical_json(manifest)


def validate(manifest: dict) -> None:
    if not isinstance(manifest, dict):
        raise ExamCryptoError(MANIFEST_MALFORMED, "manifest must be an object")
    if manifest.get("schema_version") != C.SCHEMA_VERSION:
        raise ExamCryptoError(UNSUPPORTED_VERSION,
                              f"schema_version {manifest.get('schema_version')!r} not supported")
    missing = FIELDS_V1.keys() - manifest.keys()
    extra = manifest.keys() - FIELDS_V1.keys()
    if missing or extra:
        raise ExamCryptoError(MANIFEST_MALFORMED,
                              f"missing={sorted(missing)} extra={sorted(extra)}")
    for name, typ in FIELDS_V1.items():
        value = manifest[name]
        if isinstance(value, bool) or not isinstance(value, typ):
            raise ExamCryptoError(MANIFEST_MALFORMED, f"{name} has wrong type")
    for name, expected in FIXED_V1.items():
        if manifest[name] != expected:
            raise ExamCryptoError(UNSUPPORTED_VERSION, f"{name}={manifest[name]!r} not supported")


def to_envelope_bytes(manifest: dict, signature_b64: str) -> bytes:
    envelope = {"manifest": manifest, "signature_b64": signature_b64}
    return json.dumps(envelope, indent=2, sort_keys=True).encode("utf-8")


def from_envelope_bytes(data: bytes) -> tuple[dict, str]:
    try:
        envelope = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExamCryptoError(MANIFEST_MALFORMED, "manifest.json is not valid JSON") from exc
    if (not isinstance(envelope, dict) or set(envelope) != {"manifest", "signature_b64"}
            or not isinstance(envelope["signature_b64"], str)):
        raise ExamCryptoError(MANIFEST_MALFORMED, "envelope must have manifest + signature_b64")
    validate(envelope["manifest"])
    return envelope["manifest"], envelope["signature_b64"]
