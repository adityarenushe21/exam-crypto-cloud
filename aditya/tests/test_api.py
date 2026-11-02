# ExamVault capstone project | Aditya Renushe | MIT World Peace University, Pune
# Module: secure upload, post-quantum encryption and cloud storage
# SPDX-License-Identifier: MIT
r"""Milestone 5 - HTTP API, events and blockchain mock tests (Flask test client).

Run from the project root:
    python -m unittest discover -s tests -v
"""

import io
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from examcrypto.api import create_app
from examcrypto.blockchain import MockBlockchain
from examcrypto.events import ALLOWED_FIELDS, JsonlEventSink
from examcrypto.keystore import KeyStore
from examcrypto.service import PaperService
from examcrypto.storage import LocalStorage, object_keys

PASS = b"api-test-passphrase"
MARKER = b"TOP-SECRET-QUESTION-42"
PDF = b"%PDF-1.4\n" + MARKER + b"\n%%EOF\n"
RELEASE_AT = "2026-12-01T09:00:00Z"
TOKENS = {
    "tok-authority": {"actor_id": "u-auth", "role": "exam_authority"},
    "tok-officer": {"actor_id": "u-off", "role": "release_officer"},
    "tok-admin": {"actor_id": "u-admin", "role": "admin"},
    "tok-student": {"actor_id": "u-stu", "role": "student"},
}


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


class ApiBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        ks = KeyStore(self.tmp / "keys"); ks.init_keys(PASS)
        self.ks = ks
        self.clock = Clock()
        self.events = JsonlEventSink(self.tmp / "events.jsonl", signer=ks.audit_private(PASS))
        self.chain = MockBlockchain(self.tmp / "chain.json", clock=self.clock)
        self.storage = LocalStorage(self.tmp / "storage")
        self.service = PaperService(storage=self.storage, keystore=ks, passphrase=PASS,
                                    events=self.events, blockchain=self.chain, clock=self.clock)
        self.app = create_app(self.service, TOKENS, audit_public=ks.audit_public())
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def auth(token):
        return {"Authorization": f"Bearer {token}"}

    def upload(self, token="tok-authority", data=PDF, release_at=RELEASE_AT, url="/api/v1/papers"):
        return self.client.post(url, headers=self.auth(token), content_type="multipart/form-data",
                                data={"file": (io.BytesIO(data), "paper.pdf"),
                                      "exam_id": "CS301-ENDSEM", "release_at_utc": release_at})

    def exam_time_and_approve(self, pid, version=1):
        self.clock.now = datetime(2026, 12, 1, 9, 0, tzinfo=timezone.utc)
        for c in range(3):
            self.chain.approve_release(pid, version, c)

    def sealed_id(self):
        r = self.upload()
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()["paper_id"]


class Routes(ApiBase):
    def test_health_needs_no_token(self):
        r = self.client.get("/api/v1/health")
        self.assertEqual((r.status_code, r.get_json()["status"]), (200, "OK"))

    def test_no_token_401(self):
        r = self.client.post("/api/v1/papers")
        self.assertEqual((r.status_code, r.get_json()["reason_code"]), (401, "AUTH_REQUIRED"))

    def test_bad_token_401(self):
        r = self.upload(token="made-up")
        self.assertEqual(r.status_code, 401)

    def test_upload_201_and_response_shape(self):
        r = self.upload()
        body = r.get_json()
        self.assertEqual(r.status_code, 201)
        for key in ("paper_id", "paper_version", "status", "ciphertext_sha3_256_hex",
                    "manifest_sha3_256_hex", "release_at_utc", "blockchain_status", "request_id"):
            self.assertIn(key, body)
        self.assertEqual(body["status"], "SEALED")
        self.assertEqual(body["blockchain_status"], "MOCK_ANCHORED")
        self.assertEqual(r.headers["X-Request-Id"], body["request_id"])

    def test_student_cannot_upload_403(self):
        self.assertEqual(self.upload(token="tok-student").status_code, 403)

    def test_not_pdf_415(self):
        self.assertEqual(self.upload(data=b"just text").status_code, 415)

    def test_missing_file_400(self):
        r = self.client.post("/api/v1/papers", headers=self.auth("tok-authority"),
                             data={"exam_id": "X", "release_at_utc": RELEASE_AT})
        self.assertEqual((r.status_code, r.get_json()["reason_code"]), (400, "INVALID_INPUT"))

    def test_too_large_413(self):
        r = self.upload(data=b"%PDF-" + b"0" * (21 * 1024 * 1024))
        self.assertEqual((r.status_code, r.get_json()["reason_code"]), (413, "FILE_TOO_LARGE"))

    def test_unknown_paper_404(self):
        r = self.client.get("/api/v1/papers/pap_nope", headers=self.auth("tok-admin"))
        self.assertEqual(r.status_code, 404)

    def test_unknown_route_404_json(self):
        r = self.client.get("/api/v1/nothing")
        self.assertEqual((r.status_code, r.get_json()["reason_code"]), (404, "NOT_FOUND"))

    def test_status_before_and_after_release_time(self):
        pid = self.sealed_id()
        r = self.client.get(f"/api/v1/papers/{pid}", headers=self.auth("tok-admin")).get_json()
        self.assertEqual((r["signature_status"], r["integrity_status"], r["release_status"]),
                         ("valid", "valid", "NOT_YET_RELEASABLE"))
        self.assertEqual(r["blockchain"]["status"], "SEALED")
        self.clock.now = datetime(2026, 12, 1, 9, 0, tzinfo=timezone.utc)
        r = self.client.get(f"/api/v1/papers/{pid}", headers=self.auth("tok-admin")).get_json()
        self.assertEqual((r["release_status"], r["chain_reason_code"]),
                         ("AWAITING_CUSTODIANS", "CHAIN_NOT_RELEASED"))
        self.exam_time_and_approve(pid)
        r = self.client.get(f"/api/v1/papers/{pid}", headers=self.auth("tok-admin")).get_json()
        self.assertEqual((r["release_status"], r["blockchain"]["status"]), ("RELEASABLE", "RELEASED"))

    def test_release_early_423_then_200(self):
        pid = self.sealed_id()
        r = self.client.post(f"/api/v1/papers/{pid}/release", headers=self.auth("tok-officer"))
        self.assertEqual((r.status_code, r.get_json()["reason_code"]),
                         (423, "RELEASE_TIME_NOT_REACHED"))
        self.clock.now = datetime(2026, 12, 1, 9, 0, tzinfo=timezone.utc)
        r = self.client.post(f"/api/v1/papers/{pid}/release", headers=self.auth("tok-officer"))
        self.assertEqual((r.status_code, r.get_json()["reason_code"]), (423, "CHAIN_NOT_RELEASED"))
        self.exam_time_and_approve(pid)
        r = self.client.post(f"/api/v1/papers/{pid}/release", headers=self.auth("tok-officer"))
        self.assertEqual((r.status_code, r.mimetype), (200, "application/pdf"))
        self.assertEqual(r.data, PDF)
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_admin_cannot_release_403(self):
        pid = self.sealed_id()
        self.clock.now = datetime(2026, 12, 1, 9, 0, tzinfo=timezone.utc)
        r = self.client.post(f"/api/v1/papers/{pid}/release", headers=self.auth("tok-admin"))
        self.assertEqual(r.status_code, 403)

    def test_tampered_ciphertext_shows_in_status_and_blocks_release(self):
        pid = self.sealed_id()
        ct = self.storage.root / object_keys(pid, 1)[0]
        data = bytearray(ct.read_bytes()); data[0] ^= 1; ct.write_bytes(bytes(data))
        r = self.client.get(f"/api/v1/papers/{pid}", headers=self.auth("tok-admin")).get_json()
        self.assertEqual((r["integrity_status"], r["release_status"]), ("mismatch", "BLOCKED"))
        self.clock.now = datetime(2026, 12, 1, 9, 0, tzinfo=timezone.utc)
        r = self.client.post(f"/api/v1/papers/{pid}/release", headers=self.auth("tok-officer"))
        self.assertEqual((r.status_code, r.get_json()["reason_code"]),
                         (422, "CIPHERTEXT_DIGEST_MISMATCH"))

    def test_tampered_manifest_shows_signature_invalid(self):
        pid = self.sealed_id()
        mpath = self.storage.root / object_keys(pid, 1)[1]
        env = json.loads(mpath.read_text())
        env["manifest"]["release_at_utc"] = "2026-11-21T00:00:00Z"
        mpath.write_text(json.dumps(env))
        r = self.client.get(f"/api/v1/papers/{pid}", headers=self.auth("tok-admin")).get_json()
        self.assertEqual((r["signature_status"], r["release_status"]), ("invalid", "BLOCKED"))

    def test_new_version_route(self):
        pid = self.sealed_id()
        r = self.upload(url=f"/api/v1/papers/{pid}/versions")
        self.assertEqual((r.status_code, r.get_json()["paper_version"]), (201, 2))
        r = self.client.get(f"/api/v1/papers/{pid}?version=1", headers=self.auth("tok-admin"))
        self.assertEqual(r.get_json()["paper_version"], 1)

    def test_bad_version_param_400(self):
        pid = self.sealed_id()
        r = self.client.get(f"/api/v1/papers/{pid}?version=abc", headers=self.auth("tok-admin"))
        self.assertEqual(r.status_code, 400)

    def test_manifest_route_has_no_secrets(self):
        pid = self.sealed_id()
        r = self.client.get(f"/api/v1/papers/{pid}/manifest", headers=self.auth("tok-admin"))
        body = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertIn("signature_b64", body)
        self.assertNotIn(MARKER.decode(), json.dumps(body))

    def test_events_route_role_restricted(self):
        self.sealed_id()
        self.assertEqual(self.client.get("/api/v1/events", headers=self.auth("tok-student"))
                         .status_code, 403)
        r = self.client.get("/api/v1/events", headers=self.auth("tok-admin"))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(any(e["event_type"] == "UPLOAD" for e in r.get_json()["events"]))


class EventsAndChain(ApiBase):
    def test_every_request_emits_one_event_with_safe_fields_only(self):
        pid = self.sealed_id()
        self.client.post(f"/api/v1/papers/{pid}/release", headers=self.auth("tok-officer"))  # early
        self.upload(token="tok-student")                                                    # denied
        self.client.get("/api/v1/papers", headers={})                                       # 405
        self.client.post("/api/v1/papers")                                                  # 401
        events = self.events.read(1000)
        kinds = [(e["event_type"], e["result"], e.get("reason_code")) for e in events]
        self.assertIn(("UPLOAD", "SUCCESS", None), kinds)
        self.assertIn(("RELEASE_REQUEST", "DENIED", "RELEASE_TIME_NOT_REACHED"), kinds)
        self.assertIn(("UPLOAD", "DENIED", "ROLE_NOT_ALLOWED"), kinds)
        self.assertIn(("AUTH", "DENIED", "AUTH_REQUIRED"), kinds)
        for e in events:
            self.assertLessEqual(set(e), set(ALLOWED_FIELDS))
        raw = self.events.path.read_bytes()
        self.assertNotIn(MARKER, raw)
        for secret_word in (b"kem_ciphertext", b"hkdf_salt", b"nonce", b"tok-", b"passphrase"):
            self.assertNotIn(secret_word, raw)
        from examcrypto.events import verify_chain
        self.assertTrue(verify_chain(events, self.ks.audit_public())["ok"])

    def test_anchor_record_matches_stored_ciphertext(self):
        from examcrypto.hashing import sha3_256_hex
        pid = self.sealed_id()
        st = self.chain.get_status(pid, 1)
        ct = (self.storage.root / object_keys(pid, 1)[0]).read_bytes()
        self.assertEqual(st["master_hash"], "0x" + sha3_256_hex(ct))
        self.assertEqual(st["release_at_unix"], 1796115600)   # 2026-12-01T09:00:00Z
        self.assertTrue(st["tx_id"].startswith("MOCK-"))

    def test_chain_unavailable_upload_still_sealed_then_retry_anchor(self):
        self.chain.fail = True
        r = self.upload().get_json()
        self.assertEqual((r["status"], r["blockchain_status"]), ("SEALED", "FAILED"))
        self.chain.fail = False
        r2 = self.client.post(f"/api/v1/papers/{r['paper_id']}/anchor",
                              headers=self.auth("tok-authority"))
        self.assertEqual((r2.status_code, r2.get_json()["status"]), (200, "MOCK_ANCHORED"))

    def test_error_bodies_never_contain_internal_details(self):
        r = self.client.post("/api/v1/papers", headers=self.auth("tok-authority"),
                             data=b"\x00garbage", content_type="multipart/form-data; boundary=x")
        body = r.get_json()
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("Traceback", json.dumps(body))


class ChainAuthorization(ApiBase):
    """Harsh's ExamVault decides; Aditya's release service obeys - and fails closed."""

    def release(self, pid):
        return self.client.post(f"/api/v1/papers/{pid}/release", headers=self.auth("tok-officer"))

    def guard_key(self):
        calls = []
        real = self.ks.recipient_private
        self.ks.recipient_private = lambda p: calls.append(1) or real(p)
        return calls

    def test_frozen_paper_cannot_be_released_and_key_untouched(self):
        pid = self.sealed_id()
        self.exam_time_and_approve(pid)
        self.chain.set_status(pid, 1, "FROZEN")
        calls = self.guard_key()
        r = self.release(pid)
        self.assertEqual((r.status_code, r.get_json()["reason_code"]), (423, "CHAIN_PAPER_BLOCKED"))
        self.assertEqual(calls, [])
        st = self.client.get(f"/api/v1/papers/{pid}", headers=self.auth("tok-admin")).get_json()
        self.assertEqual(st["release_status"], "BLOCKED")

    def test_revoked_and_compromised_block_release(self):
        for status in ("REVOKED", "COMPROMISED"):
            pid = self.sealed_id()
            self.chain.set_status(pid, 1, status)
            self.clock.now = datetime(2026, 12, 1, 9, 0, tzinfo=timezone.utc)
            self.assertEqual(self.release(pid).get_json()["reason_code"], "CHAIN_PAPER_BLOCKED")
            self.clock.now = datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc)

    def test_two_approvals_are_not_enough(self):
        pid = self.sealed_id()
        self.clock.now = datetime(2026, 12, 1, 9, 0, tzinfo=timezone.utc)
        self.chain.approve_release(pid, 1, 0); self.chain.approve_release(pid, 1, 1)
        self.assertEqual(self.release(pid).get_json()["reason_code"], "CHAIN_NOT_RELEASED")

    def test_custodians_cannot_approve_early(self):
        pid = self.sealed_id()
        with self.assertRaises(ValueError):
            self.chain.approve_release(pid, 1, 0)

    def test_reschedule_later_on_chain_is_respected(self):
        pid = self.sealed_id()
        self.chain.reschedule(pid, 1, 1796115600 + 3600)        # one hour later
        self.clock.now = datetime(2026, 12, 1, 9, 30, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):                     # TooEarly for custodians
            self.chain.approve_release(pid, 1, 0)
        self.assertEqual(self.release(pid).get_json()["reason_code"], "CHAIN_NOT_RELEASED")

    def test_chain_record_mismatch(self):
        pid = self.sealed_id()
        state = json.loads(self.chain.path.read_text())
        state["papers"][f"{pid}:v1"]["master_hash"] = "0x" + "ab" * 32
        self.chain.path.write_text(json.dumps(state))
        self.exam_time_and_approve(pid)
        r = self.release(pid)
        self.assertEqual((r.status_code, r.get_json()["reason_code"]), (422, "CHAIN_RECORD_MISMATCH"))

    def test_chain_down_at_release_fails_closed(self):
        pid = self.sealed_id()
        self.exam_time_and_approve(pid)
        self.chain.fail = True
        calls = self.guard_key()
        r = self.release(pid)
        self.assertEqual((r.status_code, r.get_json()["reason_code"]), (503, "CHAIN_UNAVAILABLE"))
        self.assertEqual(calls, [])

    def test_unregistered_paper_cannot_be_released(self):
        self.chain.fail = True
        pid = self.upload().get_json()["paper_id"]               # sealed, but not on chain
        self.chain.fail = False
        self.clock.now = datetime(2026, 12, 1, 9, 0, tzinfo=timezone.utc)
        self.assertEqual(self.release(pid).get_json()["reason_code"], "CHAIN_UNKNOWN_PAPER")

    def test_demo_route_absent_without_demo_mode(self):
        pid = self.sealed_id()
        r = self.client.post(f"/api/v1/_demo/mock-chain/{pid}/approve")
        self.assertEqual(r.status_code, 404)


class AuditAnchoring(ApiBase):
    def test_anchor_events_contiguous_batches(self):
        self.sealed_id()
        r = self.client.post("/api/v1/events/anchor", headers=self.auth("tok-admin")).get_json()
        first = r["anchored_batches"][0]
        self.assertEqual((first["first_seq"], first["status"]), (1, "MOCK_ANCHORED"))
        self.sealed_id()
        r2 = self.client.post("/api/v1/events/anchor", headers=self.auth("tok-admin")).get_json()
        self.assertEqual(r2["anchored_batches"][0]["first_seq"], first["last_seq"] + 1)

    def test_only_admin_can_anchor(self):
        r = self.client.post("/api/v1/events/anchor", headers=self.auth("tok-officer"))
        self.assertEqual(r.status_code, 403)

    def test_verify_events_detects_tampering(self):
        self.sealed_id()
        ok = self.client.get("/api/v1/events/verify", headers=self.auth("tok-admin")).get_json()
        self.assertEqual((ok["ok"], ok["signatures_checked"]), (True, True))
        lines = self.events.path.read_text().splitlines()
        e = json.loads(lines[0]); e["actor_role"] = "admin"; lines[0] = json.dumps(e)
        self.events.path.write_text("\n".join(lines) + "\n")
        bad = self.client.get("/api/v1/events/verify", headers=self.auth("tok-admin")).get_json()
        self.assertEqual((bad["ok"], bad["bad_seq"]), (False, 1))


if __name__ == "__main__":
    unittest.main()
