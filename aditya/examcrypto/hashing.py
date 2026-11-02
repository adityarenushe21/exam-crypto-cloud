"""SHA3-256 (FIPS 202). NOT the same as SHA-256 and NOT Ethereum keccak256."""

import hmac

from cryptography.hazmat.primitives import hashes


def sha3_256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA3_256())
    h.update(data)
    return h.finalize()


def sha3_256_hex(data: bytes) -> str:
    return sha3_256(data).hex()


def digests_equal(a_hex: str, b_hex: str) -> bool:
    """Constant-time comparison."""
    return hmac.compare_digest(a_hex.encode("ascii"), b_hex.encode("ascii"))


def key_id(raw_public_key: bytes) -> str:
    """Public fingerprint: first 16 bytes of SHA3-256(raw public key), hex."""
    return sha3_256(raw_public_key)[:16].hex()
