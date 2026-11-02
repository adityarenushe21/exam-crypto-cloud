# ExamVault capstone project | Aditya Renushe | MIT World Peace University, Pune
# Module: secure upload, post-quantum encryption and cloud storage
# SPDX-License-Identifier: MIT
"""ML-KEM-768 wrappers (library: pyca/cryptography). No crypto maths here."""

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)

KEM_CIPHERTEXT_BYTES = 1088


def encapsulate(recipient_public: MLKEM768PublicKey) -> tuple[bytes, bytes]:
    """Returns (shared_secret, kem_ciphertext)."""
    return recipient_public.encapsulate()


def decapsulate(recipient_private: MLKEM768PrivateKey, kem_ciphertext: bytes) -> bytes:
    if len(kem_ciphertext) != KEM_CIPHERTEXT_BYTES:
        raise ValueError("KEM ciphertext has wrong length")
    return recipient_private.decapsulate(kem_ciphertext)
