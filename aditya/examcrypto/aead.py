"""AES-256-GCM. Output format: ciphertext || 16-byte tag (library default)."""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import GCM_NONCE_BYTES, PROTOCOL, SCHEMA_VERSION
from .errors import ExamCryptoError, DECRYPTION_AUTHENTICATION_FAILED


def build_aad(paper_id: str, paper_version: int, exam_id: str, release_at_utc: str) -> str:
    """Public metadata that is authenticated (not encrypted) together with the paper."""
    return (f"{PROTOCOL}|v{SCHEMA_VERSION}|paper_id={paper_id}|paper_version={paper_version}"
            f"|exam_id={exam_id}|release_at_utc={release_at_utc}")


def encrypt(key: bytes, plaintext: bytes, aad: str) -> tuple[bytes, bytes]:
    """Returns (nonce, ciphertext_with_tag). A fresh random nonce every call."""
    nonce = os.urandom(GCM_NONCE_BYTES)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad.encode("ascii"))


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: str) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad.encode("ascii"))
    except InvalidTag as exc:
        raise ExamCryptoError(DECRYPTION_AUTHENTICATION_FAILED,
                              "AES-GCM tag check failed; no plaintext returned") from exc
