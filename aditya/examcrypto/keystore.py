# ExamVault capstone project | Aditya Renushe | MIT World Peace University, Pune
# Module: secure upload, post-quantum encryption and cloud storage
# SPDX-License-Identifier: MIT
"""Local key storage for DEVELOPMENT ONLY.

- Private keys: PKCS#8 PEM, encrypted with a passphrase (BestAvailableEncryption).
- Public keys:  SubjectPublicKeyInfo PEM.
- Folder is git-ignored (keys/). Keys are created ONCE with `init-keys` and never
  regenerated automatically, otherwise old papers could not be decrypted.

Prototype limitation: both key pairs live in one folder with one passphrase.
In a real deployment the ML-DSA signing key belongs to the authority/upload
service and the ML-KEM decapsulation key to the release service, on separate
protected stores.
"""

import hashlib
import json
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey

from .errors import (ExamCryptoError, INVALID_INPUT, KEY_ALREADY_EXISTS, KEY_MISSING,
                     KEY_PASSPHRASE_INVALID)
from .hashing import key_id

RELEASE_PRIV = "release_mlkem768_private.pem"
RELEASE_PUB = "release_mlkem768_public.pem"
AUTHORITY_PRIV = "authority_mldsa65_private.pem"
AUTHORITY_PUB = "authority_mldsa65_public.pem"
AUDIT_PRIV = "audit_mldsa65_private.pem"
AUDIT_PUB = "audit_mldsa65_public.pem"
KDF_FILE = "key_protection.json"
ALL_FILES = (RELEASE_PRIV, RELEASE_PUB, AUTHORITY_PRIV, AUTHORITY_PUB, KDF_FILE)

# The PKCS#8 encryption in the crypto library uses PBKDF2-HMAC-SHA256 with only 2048
# iterations (checked with `openssl asn1parse`) and cannot be raised for PKCS#8. So the
# passphrase is first STRETCHED with scrypt (memory-hard, about 32 MB, tens of ms), and the
# result is used as the PKCS#8 password. The salt and parameters are stored (not secret) in
# key_protection.json. Folders created before this change have no such file and still load
# with the raw passphrase (legacy mode).
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1

MIN_PASSPHRASE = 12


class KeyStore:
    def __init__(self, folder: str | Path):
        self.folder = Path(folder)
        self._stretched = {}        # sha256(passphrase) -> stretched password, this process only

    # ---------------------------------------------------------------- create
    def init_keys(self, passphrase: bytes) -> dict:
        if len(passphrase) < MIN_PASSPHRASE:
            raise ExamCryptoError(INVALID_INPUT, f"passphrase must be >= {MIN_PASSPHRASE} chars")
        existing = [f for f in ALL_FILES if (self.folder / f).exists()]
        if existing:
            raise ExamCryptoError(KEY_ALREADY_EXISTS,
                                  f"refusing to overwrite existing keys: {existing}")
        self.folder.mkdir(parents=True, exist_ok=True)
        self._write(KDF_FILE, json.dumps({"kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
                                          "salt_hex": secrets.token_hex(16)}, indent=2).encode())
        enc = ser.BestAvailableEncryption(self._file_password(passphrase))

        kem = MLKEM768PrivateKey.generate()
        dsa = MLDSA65PrivateKey.generate()
        self._write(RELEASE_PRIV, kem.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, enc))
        self._write(RELEASE_PUB, kem.public_key().public_bytes(
            ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
        self._write(AUTHORITY_PRIV, dsa.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, enc))
        self._write(AUTHORITY_PUB, dsa.public_key().public_bytes(
            ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
        return self.key_ids()

    def _write(self, name: str, data: bytes) -> None:
        path = self.folder / name
        with open(path, "xb") as f:          # 'x' = fail if file already exists
            f.write(data)
        try:
            os.chmod(path, 0o600)            # best effort; limited effect on Windows
        except OSError:
            pass

    # ------------------------------------------------------------------ load
    def _read(self, name: str) -> bytes:
        path = self.folder / name
        if not path.exists():
            raise ExamCryptoError(KEY_MISSING, f"{name} not found in {self.folder} (run init-keys)")
        return path.read_bytes()

    def recipient_public(self) -> MLKEM768PublicKey:
        key = ser.load_pem_public_key(self._read(RELEASE_PUB))
        if not isinstance(key, MLKEM768PublicKey):
            raise ExamCryptoError(KEY_MISSING, "release public key is not ML-KEM-768")
        return key

    def signer_public(self) -> MLDSA65PublicKey:
        """The TRUSTED verification key (trust anchor)."""
        key = ser.load_pem_public_key(self._read(AUTHORITY_PUB))
        if not isinstance(key, MLDSA65PublicKey):
            raise ExamCryptoError(KEY_MISSING, "authority public key is not ML-DSA-65")
        return key

    def recipient_private(self, passphrase: bytes) -> MLKEM768PrivateKey:
        key = self._load_private(RELEASE_PRIV, passphrase)
        if not isinstance(key, MLKEM768PrivateKey):
            raise ExamCryptoError(KEY_MISSING, "release private key is not ML-KEM-768")
        return key

    def signer_private(self, passphrase: bytes) -> MLDSA65PrivateKey:
        key = self._load_private(AUTHORITY_PRIV, passphrase)
        if not isinstance(key, MLDSA65PrivateKey):
            raise ExamCryptoError(KEY_MISSING, "authority private key is not ML-DSA-65")
        return key

    def _load_private(self, name: str, passphrase: bytes):
        try:
            return ser.load_pem_private_key(self._read(name), password=self._file_password(passphrase))
        except (ValueError, TypeError) as exc:
            raise ExamCryptoError(KEY_PASSPHRASE_INVALID,
                                  f"could not unlock {name} (wrong passphrase?)") from exc

    # ------------------------------------------------------------- audit key
    def audit_private(self, passphrase: bytes, create_if_missing: bool = True) -> MLDSA65PrivateKey:
        """Separate ML-DSA-65 key that signs audit events (never used for papers).
        Created on first use, so existing key folders keep working."""
        if not (self.folder / AUDIT_PRIV).exists():
            if not create_if_missing:
                raise ExamCryptoError(KEY_MISSING, f"{AUDIT_PRIV} not found")
            key = MLDSA65PrivateKey.generate()
            enc = ser.BestAvailableEncryption(self._file_password(passphrase))
            self._write(AUDIT_PRIV, key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, enc))
            self._write(AUDIT_PUB, key.public_key().public_bytes(
                ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
        key = self._load_private(AUDIT_PRIV, passphrase)
        if not isinstance(key, MLDSA65PrivateKey):
            raise ExamCryptoError(KEY_MISSING, "audit private key is not ML-DSA-65")
        return key

    def audit_public(self) -> MLDSA65PublicKey:
        key = ser.load_pem_public_key(self._read(AUDIT_PUB))
        if not isinstance(key, MLDSA65PublicKey):
            raise ExamCryptoError(KEY_MISSING, "audit public key is not ML-DSA-65")
        return key

    # -------------------------------------------------------- passphrase stretching
    def _file_password(self, passphrase: bytes) -> bytes:
        cfg_path = self.folder / KDF_FILE
        if not cfg_path.exists():
            return passphrase                               # legacy key folder
        memo = hashlib.sha256(passphrase).hexdigest()
        if memo in self._stretched:
            return self._stretched[memo]
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        if cfg.get("kdf") != "scrypt":
            raise ExamCryptoError(KEY_MISSING, "unsupported key_protection.json")
        key = hashlib.scrypt(passphrase, salt=bytes.fromhex(cfg["salt_hex"]), n=int(cfg["n"]),
                             r=int(cfg["r"]), p=int(cfg["p"]), dklen=32, maxmem=128 * 1024 * 1024)
        self._stretched[memo] = key.hex().encode("ascii")
        return self._stretched[memo]

    @property
    def protection(self) -> str:
        return "scrypt-stretched" if (self.folder / KDF_FILE).exists() else "legacy (PBKDF2 2048 only)"

    def key_ids(self) -> dict:
        return {
            "recipient_key_id": key_id(self.recipient_public().public_bytes_raw()),
            "signer_key_id": key_id(self.signer_public().public_bytes_raw()),
        }
