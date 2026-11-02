r"""Milestone 4 - extra attack and failure tests.

These simulate an INSIDER who can re-sign manifests with the real authority key
(the strongest attacker short of stealing the release key). Even then, the
layers underneath must refuse to produce plaintext.

Run from the project root:
    python -m unittest discover -s tests -v
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from examcrypto import pipeline
from examcrypto.encoding import b64d, b64e
from examcrypto.hashing import sha3_256_hex
from examcrypto.keystore import KeyStore
from examcrypto.storage import object_keys

from tests.test_pipeline import AFTER, BEFORE, PASS, PDF, Base, OFFICER

ROOT = Path(__file__).resolve().parent.parent


def flip_b64(value: str, index: int = 0) -> str:
    raw = bytearray(b64d(value))
    raw[index] ^= 1
    return b64e(bytes(raw))


class InsiderAttacks(Base):
    """Attacker has the authority signing key, but NOT the release private key."""

    def resign(self, paper_id, change):
        self.rewrite_manifest(paper_id, change, resign_with=self.ks.signer_private(PASS))

    def test_ciphertext_tag_changed_and_digest_resigned(self):
        r = self.seal()
        ct_path, _ = self.paths(r["paper_id"])
        data = bytearray(ct_path.read_bytes()); data[-1] ^= 1          # last byte = GCM tag
        ct_path.write_bytes(bytes(data))
        self.resign(r["paper_id"], lambda m: m.update(
            ciphertext_sha3_256_hex=sha3_256_hex(bytes(data))))
        self.assertReason("DECRYPTION_AUTHENTICATION_FAILED", self.release, r["paper_id"])

    def test_nonce_changed_and_resigned(self):
        r = self.seal()
        self.resign(r["paper_id"], lambda m: m.update(
            aes_gcm_nonce_b64=flip_b64(m["aes_gcm_nonce_b64"])))
        self.assertReason("DECRYPTION_AUTHENTICATION_FAILED", self.release, r["paper_id"])

    def test_salt_changed_and_resigned(self):
        r = self.seal()
        self.resign(r["paper_id"], lambda m: m.update(hkdf_salt_b64=flip_b64(m["hkdf_salt_b64"])))
        self.assertReason("DECRYPTION_AUTHENTICATION_FAILED", self.release, r["paper_id"])

    def test_release_time_moved_earlier_and_resigned(self):
        """Signature is valid, but AES-GCM AAD still contains the ORIGINAL time."""
        r = self.seal()
        early = "2026-11-01T00:00:00Z"

        def change(m):
            m["release_at_utc"] = early
            m["aad"] = m["aad"].replace("2026-12-01T09:00:00Z", early)

        self.resign(r["paper_id"], change)
        self.assertReason("DECRYPTION_AUTHENTICATION_FAILED", self.release, r["paper_id"])

    def test_aad_text_inconsistent_with_fields(self):
        r = self.seal()
        self.resign(r["paper_id"], lambda m: m.update(aad=m["aad"] + "|extra=1"))
        self.assertReason("MANIFEST_MALFORMED", self.release, r["paper_id"])

    def test_ciphertext_moved_from_another_paper(self):
        """Paper B's object slot gets paper A's ciphertext + A's KEM data, re-signed.
        AAD and HKDF info contain B's paper_id, so decryption must fail."""
        a, b = self.seal(), self.seal()
        a_ct, a_mf = self.paths(a["paper_id"])
        b_ct, _ = self.paths(b["paper_id"])
        a_manifest = json.loads(a_mf.read_text())["manifest"]
        b_ct.write_bytes(a_ct.read_bytes())

        def change(m):
            for field in ("kem_ciphertext_b64", "hkdf_salt_b64", "aes_gcm_nonce_b64",
                          "ciphertext_sha3_256_hex"):
                m[field] = a_manifest[field]

        self.resign(b["paper_id"], change)
        self.assertReason("DECRYPTION_AUTHENTICATION_FAILED", self.release, b["paper_id"])

    def test_manifest_copied_to_another_version_slot(self):
        r1 = self.seal()
        self.seal(paper_id=r1["paper_id"])                      # creates v2
        _, mf1 = self.paths(r1["paper_id"], 1)
        _, mf2 = self.paths(r1["paper_id"], 2)
        mf2.write_bytes(mf1.read_bytes())                       # v1 manifest in v2 slot
        self.assertReason("INVALID_INPUT", self.release, r1["paper_id"], version=2)


class TrustAndKeys(Base):
    def test_verifier_trusts_a_different_authority(self):
        r = self.seal()
        other = KeyStore(self.tmp / "other_authority")
        other.init_keys(PASS)
        with self.assertRaises(Exception) as cm:
            pipeline.release_paper(storage=self.storage, paper_id=r["paper_id"],
                                   trusted_signer_public=other.signer_public(),
                                   load_recipient_private=lambda: self.ks.recipient_private(PASS),
                                   actor=OFFICER, now=AFTER)
        self.assertEqual(cm.exception.reason_code, "UNTRUSTED_SIGNER")

    def test_kem_and_signing_keys_are_different_key_types(self):
        self.assertNotEqual(type(self.ks.recipient_public()), type(self.ks.signer_public()))

    def test_lost_passphrase_means_no_release(self):
        r = self.seal()
        self.assertReason("KEY_PASSPHRASE_INVALID", self.release, r["paper_id"],
                          loader=lambda: self.ks.recipient_private(b"forgotten-passphrase"))


class Randomness(Base):
    def test_nonce_salt_and_kem_ciphertext_never_repeat(self):
        nonces, salts, kems = set(), set(), set()
        for _ in range(30):
            r = self.seal()
            _, mpath = self.paths(r["paper_id"])
            m = json.loads(mpath.read_text())["manifest"]
            nonces.add(m["aes_gcm_nonce_b64"]); salts.add(m["hkdf_salt_b64"])
            kems.add(m["kem_ciphertext_b64"])
        self.assertEqual((len(nonces), len(salts), len(kems)), (30, 30, 30))


class CommandLine(unittest.TestCase):
    """Runs the real CLI in a temporary folder (like a user would)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = dict(os.environ, EXAM_KEY_PASSPHRASE="cli-test-passphrase",
                        PYTHONPATH=str(ROOT))
        self.env.pop("EXAM_DEMO_MODE", None)

    def cli(self, *args, demo=False):
        env = dict(self.env, EXAM_DEMO_MODE="1") if demo else self.env
        p = subprocess.run([sys.executable, "-m", "examcrypto", *args], cwd=self.tmp,
                           env=env, capture_output=True, text=True, timeout=60)
        start = p.stdout.index("{")
        obj, _ = json.JSONDecoder().raw_decode(p.stdout[start:])   # ignore trailing notes
        return p.returncode, obj

    def test_cli_full_story(self):
        self.assertEqual(self.cli("init-keys")[0], 0)
        self.assertEqual(self.cli("init-keys")[1]["reason_code"], "KEY_ALREADY_EXISTS")
        self.cli("make-sample")
        code, sealed = self.cli("seal", "output/sample_paper.pdf", "--exam-id", "CS301",
                                "--release-at", "2099-01-01T00:00:00Z")
        self.assertEqual((code, sealed["status"]), (0, "SEALED"))
        pid = sealed["paper_id"]

        code, res = self.cli("release", pid)
        self.assertEqual((code, res["reason_code"]), (2, "RELEASE_TIME_NOT_REACHED"))

        code, res = self.cli("release", pid, "--simulate-now", "2099-01-01T00:00:00Z")
        self.assertEqual(res["reason_code"], "ROLE_NOT_ALLOWED")   # demo mode off

        code, res = self.cli("release", pid, "--simulate-now", "2099-01-01T00:00:00Z", demo=True)
        self.assertEqual(res["reason_code"], "CHAIN_NOT_RELEASED")   # custodians not yet

        code, res = self.cli("mock-approve", pid, "--simulate-now", "2099-01-01T00:00:00Z", demo=True)
        self.assertEqual(res["chain"]["status"], "RELEASED")

        code, res = self.cli("release", pid, "--simulate-now", "2099-01-01T00:00:00Z", demo=True)
        self.assertEqual((code, res["status"]), (0, "RELEASED"))
        released = Path(self.tmp, res["written_to"]).read_bytes()
        self.assertEqual(released, Path(self.tmp, "output/sample_paper.pdf").read_bytes())

        code, res = self.cli("release", pid, "--simulate-now", "2099-01-01T00:00:00Z", demo=True)
        self.assertEqual(res["reason_code"], "OUTPUT_EXISTS")      # never overwrites

        code, res = self.cli("verify-events")
        self.assertEqual(res["status"], "EVENTS_OK")

    def test_cli_missing_input_file(self):
        self.cli("init-keys")
        code, res = self.cli("seal", "nope.pdf", "--exam-id", "X", "--release-at",
                             "2099-01-01T00:00:00Z")
        self.assertEqual((code, res["reason_code"]), (2, "INVALID_INPUT"))


if __name__ == "__main__":
    unittest.main()
