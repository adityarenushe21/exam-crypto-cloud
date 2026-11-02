"""ML-DSA-65 sign/verify with a fixed context string (domain separation)."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA65PrivateKey,
    MLDSA65PublicKey,
)

from .constants import SIGNATURE_CONTEXT
from .errors import ExamCryptoError, SIGNATURE_INVALID


def sign(private_key: MLDSA65PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message, SIGNATURE_CONTEXT.encode("ascii"))


def verify(public_key: MLDSA65PublicKey, signature: bytes, message: bytes) -> None:
    try:
        public_key.verify(signature, message, SIGNATURE_CONTEXT.encode("ascii"))
    except InvalidSignature as exc:
        raise ExamCryptoError(SIGNATURE_INVALID, "manifest signature check failed") from exc
