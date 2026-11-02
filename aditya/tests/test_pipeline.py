# ExamVault capstone project | Aditya Renushe | MIT World Peace University, Pune
# Module: secure upload, post-quantum encryption and cloud storage
# SPDX-License-Identifier: MIT
r"""Milestone 3 tests (stdlib unittest - nothing extra to install).

Run from the project root:
    python -m unittest discover -s tests -v
Every test uses a temporary folder, fake PDFs and throw-away keys.
"""

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from examcrypto import manifest as mf
from examcrypto import pipeline, signatures
from examcrypto.encoding import b64d, b64e
from examcrypto.errors import ExamCryptoError
from examcrypto.hashing import key_id, sha3_256_hex
from examcrypto.keystore import KeyStore
from examcrypto.storage import LocalStorage, object_keys

PASS = b"test-passphrase-123"
BEFORE = datetime(2026, 11, 1, 0, 0, 0, tzinfo=timezone.utc)
RELEASE_AT = "2026-12-01T09:00:00Z"
AFTER = datetime(2026, 12, 1, 9, 0, 0, tzinfo=timezone.utc)
AUTHORITY = {"actor_id": "t-authority", "role": "exam_authority"}
OFFICER = {"actor_id": "t-officer", "role": "release_officer"}
AUDITOR = {"actor_id": "t-auditor", "role": "auditor"}
MARKER = b"SECRET-QUESTION-TEXT-XYZ"
PDF = b"%PDF-1.4\nFAKE EXAM PAPER\n" + MARKER + b"\n" * 100 + b"%%EOF\n"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.ks = KeyStore(self.tmp / "keys")
        self.ks.init_keys(PASS)
        self.storage = LocalStorage(self.tmp / "storage")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def seal(self, plaintext=PDF, **kw):
        args = dict(storage=self.storage, recipient_public=self.ks.recipient_public(),
                    signer_private=self.ks.signer_private(PASS), plaintext=plaintext,
                    exam_id="CS301-ENDSEM", release_at_utc=RELEASE_AT, actor=AUTHORITY,
                    now=BEFORE)
        args.update(kw)
        return pipeline.seal_paper(**args)

    def release(self, paper_id, now=AFTER, actor=OFFICER, ks=None, loader=None, version=None):
        ks = ks or self.ks
        return pipeline.release_paper(
            storage=self.storage, paper_id=paper_id, version=version,
            trusted_signer_public=ks.signer_public(),
            load_recipient_private=loader or (lambda: ks.recipient_private(PASS)),
            actor=actor, now=now)

    def assertReason(self, code, fn, *a, **kw):
        with self.assertRaises(ExamCryptoError) as cm:
            fn(*a, **kw)
        self.assertEqual(cm.exception.reason_code, code, str(cm.exception))

    # helpers to tamper with stored objects directly (simulating an attacker)
    def paths(self, paper_id, version=1):
        ct, m = object_keys(paper_id, version)
        return self.storage.root / ct, self.storage.root / m

    def rewrite_manifest(self, paper_id, change, resign_with=None):
        _, mpath = self.paths(paper_id)
        env = json.loads(mpath.read_text())
        change(env["manifest"])
        if resign_with is not None:
            env["signature_b64"] = b64e(signatures.sign(resign_with, mf.canonical_json(env["manifest"])))
        mpath.write_text(json.dumps(env))


class HappyPath(Base):
    def test_round_trip(self):
        r = self.seal()
        self.assertEqual(r["status"], "SEALED")
        self.assertEqual(r["paper_version"], 1)
        manifest, plaintext = self.release(r["paper_id"])
        self.assertEqual(plaintext, PDF)
        self.assertEqual(manifest["release_at_utc"], RELEASE_AT)

    def test_release_exactly_at_release_time_allowed(self):
        r = self.seal()
        _, plaintext = self.release(r["paper_id"], now=AFTER)
        self.assertEqual(plaintext, PDF)

    def test_verify_without_decryption_key(self):
        r = self.seal()
        manifest, _ = pipeline.verify_paper(storage=self.storage, paper_id=r["paper_id"],
                                            trusted_signer_public=self.ks.signer_public(),
                                            actor=AUDITOR)
        self.assertEqual(manifest["ciphertext_sha3_256_hex"], r["ciphertext_sha3_256_hex"])

    def test_keys_persist_across_restart(self):
        r = self.seal()
        restarted = KeyStore(self.tmp / "keys")      # brand-new object, reads from disk
        _, plaintext = self.release(r["paper_id"], ks=restarted)
        self.assertEqual(plaintext, PDF)

    def test_versioning(self):
        r1 = self.seal()
        pdf2 = PDF.replace(b"FAKE", b"FIXED")
        r2 = self.seal(plaintext=pdf2, paper_id=r1["paper_id"])
        self.assertEqual(r2["paper_version"], 2)
        self.assertEqual(self.release(r1["paper_id"])[1], pdf2)          # latest
        self.assertEqual(self.release(r1["paper_id"], version=1)[1], PDF)

    def test_fresh_randomness_each_seal(self):
        a, b = self.seal(), self.seal()
        self.assertNotEqual(a["paper_id"], b["paper_id"])
        self.assertNotEqual(a["ciphertext_sha3_256_hex"], b["ciphertext_sha3_256_hex"])

    def test_plaintext_never_stored(self):
        self.seal()
        for f in self.storage.root.rglob("*"):
            if f.is_file():
                self.assertNotIn(MARKER, f.read_bytes(), f"plaintext found in {f}")

    def test_stored_digest_matches_ciphertext_bytes(self):
        r = self.seal()
        ct_path, _ = self.paths(r["paper_id"])
        self.assertEqual(sha3_256_hex(ct_path.read_bytes()), r["ciphertext_sha3_256_hex"])


class AccessControl(Base):
    def test_wrong_role_cannot_seal(self):
        self.assertReason("ROLE_NOT_ALLOWED", self.seal, actor=OFFICER)

    def test_wrong_role_cannot_release(self):
        r = self.seal()
        self.assertReason("ROLE_NOT_ALLOWED", self.release, r["paper_id"], actor=AUTHORITY)

    def test_release_before_time_never_touches_private_key(self):
        r = self.seal()

        def loader():
            raise AssertionError("private key must NOT be loaded before release time")

        self.assertReason("RELEASE_TIME_NOT_REACHED", self.release, r["paper_id"],
                          now=BEFORE, loader=loader)

    def test_wrong_recipient_key(self):
        r = self.seal()
        other = KeyStore(self.tmp / "other_keys")
        other.init_keys(PASS)
        self.assertReason("WRONG_RECIPIENT_KEY", self.release, r["paper_id"],
                          loader=lambda: other.recipient_private(PASS))

    def test_wrong_passphrase(self):
        self.assertReason("KEY_PASSPHRASE_INVALID", self.ks.recipient_private, b"wrong-passphrase!!")


class Tampering(Base):
    def test_ciphertext_changed(self):
        r = self.seal()
        ct_path, _ = self.paths(r["paper_id"])
        data = bytearray(ct_path.read_bytes()); data[5] ^= 1
        ct_path.write_bytes(bytes(data))
        self.assertReason("CIPHERTEXT_DIGEST_MISMATCH", self.release, r["paper_id"])

    def test_release_time_moved_earlier(self):
        r = self.seal()
        self.rewrite_manifest(r["paper_id"],
                              lambda m: m.update(release_at_utc="2026-11-01T00:00:00Z"))
        self.assertReason("SIGNATURE_INVALID", self.release, r["paper_id"], now=BEFORE)

    def test_file_swapped_and_digest_updated(self):
        r = self.seal()
        ct_path, _ = self.paths(r["paper_id"])
        ct_path.write_bytes(b"attacker bytes")
        self.rewrite_manifest(r["paper_id"], lambda m: m.update(
            ciphertext_sha3_256_hex=sha3_256_hex(b"attacker bytes")))
        self.assertReason("SIGNATURE_INVALID", self.release, r["paper_id"])

    def test_attacker_resigns_with_own_key(self):
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
        attacker = MLDSA65PrivateKey.generate()
        r = self.seal()
        self.rewrite_manifest(r["paper_id"], lambda m: m.update(
            release_at_utc="2026-11-01T00:00:00Z",
            signer_key_id=key_id(attacker.public_key().public_bytes_raw())), resign_with=attacker)
        self.assertReason("UNTRUSTED_SIGNER", self.release, r["paper_id"], now=BEFORE)

    def test_attacker_resigns_but_keeps_trusted_key_id(self):
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
        attacker = MLDSA65PrivateKey.generate()
        r = self.seal()
        self.rewrite_manifest(r["paper_id"], lambda m: m.update(
            release_at_utc="2026-11-01T00:00:00Z"), resign_with=attacker)
        self.assertReason("SIGNATURE_INVALID", self.release, r["paper_id"], now=BEFORE)

    def test_bad_kem_ciphertext_even_if_validly_signed(self):
        """Defence in depth: even a correctly signed but corrupted manifest
        cannot produce plaintext - AES-GCM rejects the wrong key."""
        r = self.seal()

        def corrupt(m):
            kem_ct = bytearray(b64d(m["kem_ciphertext_b64"])); kem_ct[0] ^= 1
            m["kem_ciphertext_b64"] = b64e(bytes(kem_ct))

        self.rewrite_manifest(r["paper_id"], corrupt, resign_with=self.ks.signer_private(PASS))
        self.assertReason("DECRYPTION_AUTHENTICATION_FAILED", self.release, r["paper_id"])

    def test_signature_bytes_flipped(self):
        r = self.seal()
        _, mpath = self.paths(r["paper_id"])
        env = json.loads(mpath.read_text())
        sig = bytearray(b64d(env["signature_b64"])); sig[10] ^= 1
        env["signature_b64"] = b64e(bytes(sig))
        mpath.write_text(json.dumps(env))
        self.assertReason("SIGNATURE_INVALID", self.release, r["paper_id"])


class MalformedData(Base):
    def test_unsupported_schema_version(self):
        r = self.seal()
        self.rewrite_manifest(r["paper_id"], lambda m: m.update(schema_version="99"))
        self.assertReason("UNSUPPORTED_VERSION", self.release, r["paper_id"])

    def test_unsupported_algorithm_label(self):
        r = self.seal()
        self.rewrite_manifest(r["paper_id"], lambda m: m.update(hash_algorithm="SHA-256"))
        self.assertReason("UNSUPPORTED_VERSION", self.release, r["paper_id"])

    def test_missing_manifest_field(self):
        r = self.seal()
        self.rewrite_manifest(r["paper_id"], lambda m: m.pop("aes_gcm_nonce_b64"))
        self.assertReason("MANIFEST_MALFORMED", self.release, r["paper_id"])

    def test_manifest_not_json(self):
        r = self.seal()
        _, mpath = self.paths(r["paper_id"])
        mpath.write_bytes(b"{not json")
        self.assertReason("MANIFEST_MALFORMED", self.release, r["paper_id"])

    def test_ciphertext_missing(self):
        r = self.seal()
        ct_path, _ = self.paths(r["paper_id"])
        ct_path.unlink()
        self.assertReason("PAPER_NOT_FOUND", self.release, r["paper_id"])

    def test_unknown_paper(self):
        self.assertReason("PAPER_NOT_FOUND", self.release, "pap_doesnotexist")

    def test_path_traversal_id_rejected(self):
        self.assertReason("INVALID_INPUT", self.release, "../../etc")


class UploadValidation(Base):
    def test_not_a_pdf(self):
        self.assertReason("NOT_A_PDF", self.seal, plaintext=b"MZ\x90\x00 an exe")

    def test_empty_file(self):
        self.assertReason("INVALID_INPUT", self.seal, plaintext=b"")

    def test_too_large(self):
        self.assertReason("FILE_TOO_LARGE", self.seal, plaintext=b"%PDF-" + b"0" * (20 * 1024 * 1024))

    def test_bad_exam_id(self):
        self.assertReason("INVALID_INPUT", self.seal, exam_id="CS301|release_at_utc=now")

    def test_release_time_in_past(self):
        self.assertReason("INVALID_INPUT", self.seal, now=AFTER)

    def test_bad_time_format(self):
        self.assertReason("INVALID_INPUT", self.seal, release_at_utc="1 Dec 2026 9am")

    def test_new_version_of_unknown_paper(self):
        self.assertReason("PAPER_NOT_FOUND", self.seal, paper_id="pap_unknown")


class KeysAndStorage(Base):
    def test_init_keys_refuses_overwrite(self):
        self.assertReason("KEY_ALREADY_EXISTS", self.ks.init_keys, PASS)

    def test_short_passphrase_rejected(self):
        self.assertReason("INVALID_INPUT", KeyStore(self.tmp / "k2").init_keys, b"short")

    def test_missing_keys(self):
        self.assertReason("KEY_MISSING", KeyStore(self.tmp / "empty").recipient_public)

    def test_storage_is_write_once(self):
        r = self.seal()
        ct_key, _ = object_keys(r["paper_id"], 1)
        self.assertReason("DUPLICATE_VERSION", self.storage.put, ct_key, b"overwrite attempt")

    def test_passphrase_is_scrypt_stretched(self):
        from cryptography.hazmat.primitives import serialization as ser
        cfg = json.loads((self.tmp / "keys" / "key_protection.json").read_text())
        self.assertEqual((cfg["kdf"], cfg["n"], cfg["r"]), ("scrypt", 2 ** 15, 8))
        self.assertEqual(self.ks.protection, "scrypt-stretched")
        pem = (self.tmp / "keys" / "release_mlkem768_private.pem").read_bytes()
        with self.assertRaises(ValueError):                    # the raw passphrase alone no longer opens the PEM
            ser.load_pem_private_key(pem, password=PASS)
        self.ks.recipient_private(PASS)                        # but the KeyStore (scrypt first) does

    def test_legacy_key_folder_still_loads(self):
        from cryptography.hazmat.primitives import serialization as ser
        from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
        legacy = self.tmp / "legacy"
        legacy.mkdir()
        k = MLKEM768PrivateKey.generate()
        (legacy / "release_mlkem768_private.pem").write_bytes(
            k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.BestAvailableEncryption(PASS)))
        ks = KeyStore(legacy)
        self.assertEqual(ks.protection, "legacy (PBKDF2 2048 only)")
        self.assertEqual(ks.recipient_private(PASS).public_key().public_bytes_raw(),
                         k.public_key().public_bytes_raw())

    def test_private_keys_are_encrypted_on_disk(self):
        for name in ("release_mlkem768_private.pem", "authority_mldsa65_private.pem"):
            text = (self.tmp / "keys" / name).read_text()
            self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", text)


class CanonicalForm(unittest.TestCase):
    def test_key_order_does_not_change_signed_bytes(self):
        from examcrypto.encoding import canonical_json
        self.assertEqual(canonical_json({"b": 2, "a": "x"}), canonical_json({"a": "x", "b": 2}))
        self.assertEqual(canonical_json({"b": 2, "a": "x"}), b'{"a":"x","b":2}')

    def test_non_ascii_and_float_rejected(self):
        from examcrypto.encoding import canonical_json
        for bad in ({"a": "café"}, {"a": 1.5}, {"a": None}, {"a": True}):
            with self.assertRaises(ExamCryptoError):
                canonical_json(bad)


if __name__ == "__main__":
    unittest.main()
