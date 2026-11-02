# ExamVault capstone project | Aditya Renushe | MIT World Peace University, Pune
# Module: secure upload, post-quantum encryption and cloud storage
# SPDX-License-Identifier: MIT
r"""Tests for the integration adapters: signed audit chain, S3Storage, GatewayBlockchain.

No AWS account and no blockchain are needed: S3 is replaced by an in-memory fake
client and the chain gateway by a tiny local HTTP server.
"""

import io
import json
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from examcrypto.blockchain import GatewayBlockchain
from examcrypto.errors import ExamCryptoError
from examcrypto.events import JsonlEventSink, build_event, verify_chain
from examcrypto.storage import S3Storage


# ------------------------------------------------------------------ audit chain
class AuditChain(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.key = MLDSA65PrivateKey.generate()
        self.sink = JsonlEventSink(self.tmp / "e.jsonl", signer=self.key)
        for i in range(5):
            self.sink.emit(build_event("UPLOAD", actor={"actor_id": f"u{i}", "role": "exam_authority"}))
        self.events = self.sink.read(limit=0)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_valid_chain(self):
        r = verify_chain(self.events, self.key.public_key())
        self.assertEqual((r["ok"], r["checked"]), (True, 5))
        self.assertEqual([e["seq"] for e in self.events], [1, 2, 3, 4, 5])

    def test_edit_detected(self):
        ev = [dict(e) for e in self.events]; ev[2]["actor_id"] = "someone-else"
        self.assertEqual(verify_chain(ev, self.key.public_key())["bad_seq"], 3)

    def test_delete_detected(self):
        ev = self.events[:2] + self.events[3:]
        self.assertFalse(verify_chain(ev, self.key.public_key())["ok"])

    def test_reorder_detected(self):
        ev = [self.events[0], self.events[2], self.events[1]] + self.events[3:]
        self.assertFalse(verify_chain(ev, self.key.public_key())["ok"])

    def test_recomputed_hash_still_needs_signature(self):
        """Attacker edits an event AND recomputes its hash: the ML-DSA signature fails."""
        from examcrypto.events import _hash_body
        ev = [dict(e) for e in self.events]
        ev[-1]["actor_id"] = "forged"
        body = {k: v for k, v in ev[-1].items() if k not in ("event_hash", "signature_b64")}
        ev[-1]["event_hash"] = _hash_body(body)
        self.assertEqual(verify_chain(ev, self.key.public_key())["reason"], "bad signature")
        self.assertTrue(verify_chain(ev)["ok"])   # without key, only linkage is checked

    def test_wrong_key(self):
        other = MLDSA65PrivateKey.generate().public_key()
        self.assertEqual(verify_chain(self.events, other)["reason"], "bad signature")

    def test_chain_continues_after_restart(self):
        again = JsonlEventSink(self.tmp / "e.jsonl", signer=self.key)
        again.emit(build_event("AUTH", actor=None, reason_code="AUTH_REQUIRED"))
        all_events = again.read(limit=0)
        self.assertEqual(all_events[-1]["seq"], 6)
        self.assertTrue(verify_chain(all_events, self.key.public_key())["ok"])

    def test_no_none_values_written(self):
        for e in self.events:
            self.assertNotIn(None, e.values())


# ------------------------------------------------------------------------- S3
class FakeClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    """Implements just the calls S3Storage makes, with S3's conditional-write rule."""

    def __init__(self):
        self.objects, self.calls, self.down = {}, [], False

    def _maybe_down(self):
        if self.down:
            raise FakeClientError("ServiceUnavailable")

    def put_object(self, **kw):
        self._maybe_down()
        self.calls.append(kw)
        if kw.get("IfNoneMatch") == "*" and kw["Key"] in self.objects:
            raise FakeClientError("PreconditionFailed")
        self.objects[kw["Key"]] = kw["Body"]

    def get_object(self, Bucket, Key):
        self._maybe_down()
        if Key not in self.objects:
            raise FakeClientError("NoSuchKey")
        return {"Body": io.BytesIO(self.objects[Key])}

    def head_object(self, Bucket, Key):
        self._maybe_down()
        if Key not in self.objects:
            raise FakeClientError("404")
        return {}

    def list_objects_v2(self, Bucket, Prefix, Delimiter, ContinuationToken=None):
        self._maybe_down()
        subs = sorted({Prefix + k[len(Prefix):].split("/")[0] + "/"
                       for k in self.objects if k.startswith(Prefix) and "/" in k[len(Prefix):]})
        return {"CommonPrefixes": [{"Prefix": p} for p in subs], "IsTruncated": False}


class S3Adapter(unittest.TestCase):
    def setUp(self):
        self.fake = FakeS3()
        self.s3 = S3Storage("exam-bucket", prefix="dev", client=self.fake, kms_key_id="alias/exam")

    def test_put_get_versions(self):
        self.s3.put("papers/pap_x/v1/ciphertext.bin", b"ct1")
        self.s3.put("papers/pap_x/v2/ciphertext.bin", b"ct2")
        self.assertEqual(self.s3.get("papers/pap_x/v1/ciphertext.bin"), b"ct1")
        self.assertEqual(self.s3.versions("pap_x"), [1, 2])
        self.assertTrue(self.s3.exists("papers/pap_x/v2/ciphertext.bin"))
        self.assertFalse(self.s3.exists("papers/pap_x/v3/ciphertext.bin"))
        self.assertIn("dev/papers/pap_x/v1/ciphertext.bin", self.fake.objects)

    def test_write_once_and_sse_kms_headers(self):
        self.s3.put("papers/pap_x/v1/manifest.json", b"{}")
        with self.assertRaises(ExamCryptoError) as cm:
            self.s3.put("papers/pap_x/v1/manifest.json", b"overwrite")
        self.assertEqual(cm.exception.reason_code, "DUPLICATE_VERSION")
        call = self.fake.calls[0]
        self.assertEqual((call["IfNoneMatch"], call["ServerSideEncryption"], call["SSEKMSKeyId"]),
                         ("*", "aws:kms", "alias/exam"))

    def test_sse_s3_when_no_kms_key(self):
        s3 = S3Storage("b", client=self.fake)
        s3.put("papers/pap_y/v1/ciphertext.bin", b"x")
        self.assertEqual(self.fake.calls[-1]["ServerSideEncryption"], "AES256")

    def test_missing_and_outage(self):
        with self.assertRaises(ExamCryptoError) as cm:
            self.s3.get("papers/pap_x/v9/ciphertext.bin")
        self.assertEqual(cm.exception.reason_code, "PAPER_NOT_FOUND")
        self.fake.down = True
        with self.assertRaises(ExamCryptoError) as cm:
            self.s3.put("papers/pap_x/v1/ciphertext.bin", b"x")
        self.assertEqual(cm.exception.reason_code, "STORAGE_UNAVAILABLE")

    def test_illegal_keys_rejected(self):
        with self.assertRaises(ValueError):
            self.s3.put("../../etc/passwd", b"x")

    def test_full_pipeline_on_fake_s3(self):
        from datetime import datetime, timezone
        from examcrypto import pipeline
        from examcrypto.keystore import KeyStore
        tmp = Path(tempfile.mkdtemp())
        try:
            ks = KeyStore(tmp / "k"); ks.init_keys(b"s3-test-passphrase")
            r = pipeline.seal_paper(storage=self.s3, recipient_public=ks.recipient_public(),
                                    signer_private=ks.signer_private(b"s3-test-passphrase"),
                                    plaintext=b"%PDF-1.4 s3 test", exam_id="S3-TEST",
                                    release_at_utc="2026-12-01T09:00:00Z",
                                    actor={"role": "exam_authority"},
                                    now=datetime(2026, 11, 1, tzinfo=timezone.utc))
            _, pt = pipeline.release_paper(storage=self.s3, paper_id=r["paper_id"],
                                           trusted_signer_public=ks.signer_public(),
                                           load_recipient_private=lambda: ks.recipient_private(b"s3-test-passphrase"),
                                           actor={"role": "release_officer"},
                                           now=datetime(2026, 12, 1, 9, tzinfo=timezone.utc))
            self.assertEqual(pt, b"%PDF-1.4 s3 test")
            for body in self.fake.objects.values():
                self.assertNotIn(b"s3 test", body)            # only ciphertext reaches "AWS"
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# -------------------------------------------------------------------- gateway
class FakeGateway(BaseHTTPRequestHandler):
    papers = {}

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/papers/seal":
            key = f"{body['paper_id']}/{body['paper_version']}"
            if key in self.papers:
                return self._send(409, {"error": "PaperExists"})
            self.papers[key] = {"found": True, "status": "SEALED", "master_hash": body["ciphertext_digest_bytes32"],
                                "release_at_unix": body["release_at_unix"], "approvals": 0, "threshold": 3}
            return self._send(200, {"tx_id": "0xabc", "chain_paper_id": "0x" + "11" * 32})
        if self.path == "/audit/anchor":
            return self._send(200, {"tx_id": "0xdef", "batch_index": 0, "root": "0x" + "22" * 32})
        self._send(404, {"error": "no route"})

    def do_GET(self):
        if self.path == "/audit/last-seq":
            return self._send(200, {"last_seq": 0})
        key = self.path.removeprefix("/papers/")
        if key in self.papers:
            return self._send(200, self.papers[key])
        self._send(404, {"found": False})


class GatewayClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FakeGateway)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.chain = GatewayBlockchain(f"http://127.0.0.1:{cls.server.server_port}", timeout=5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_seal_status_anchor_round_trip(self):
        rec = {"paper_id": "pap_gw", "paper_version": 1, "hash_algorithm": "SHA3-256",
               "ciphertext_digest_bytes32": "0x" + "aa" * 32, "manifest_digest_bytes32": "0x" + "bb" * 32,
               "release_at_unix": 1796115600, "signer_key_id": "00" * 16}
        a = self.chain.anchor_paper(rec)
        self.assertEqual((a["status"], a["tx_id"]), ("ANCHORED", "0xabc"))
        self.assertEqual(self.chain.anchor_paper(rec)["status"], "FAILED")      # duplicate
        st = self.chain.get_status("pap_gw", 1)
        self.assertEqual((st["found"], st["status"], st["mode"]), (True, "SEALED", "gateway"))
        self.assertFalse(self.chain.get_status("pap_unknown", 1)["found"])
        self.assertEqual(self.chain.anchor_events(1, 1, ["0x" + "cc" * 32])["status"], "ANCHORED")
        self.assertEqual(self.chain.anchored_seq(), 0)

    def test_gateway_down(self):
        down = GatewayBlockchain("http://127.0.0.1:9", timeout=2)
        self.assertEqual(down.anchor_paper({"paper_id": "x"})["status"], "FAILED")
        with self.assertRaises(ExamCryptoError) as cm:
            down.get_status("pap_x", 1)
        self.assertEqual(cm.exception.reason_code, "CHAIN_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
