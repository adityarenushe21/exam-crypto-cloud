"""HKDF-SHA-256: ML-KEM shared secret -> 32-byte AES-256 key, bound to one paper version."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import AES_KEY_BYTES, PROTOCOL, SCHEMA_VERSION


def hkdf_info(paper_id: str, paper_version: int) -> str:
    return (f"{PROTOCOL}|v{SCHEMA_VERSION}|aes-256-gcm-content-key"
            f"|paper_id={paper_id}|paper_version={paper_version}")


def derive_content_key(shared_secret: bytes, salt: bytes, info: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=AES_KEY_BYTES,
                salt=salt, info=info.encode("ascii")).derive(shared_secret)
