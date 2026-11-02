r"""Tests for Nayan's module (controlcenter): access control, alert review, dashboard API, UI serving.

Run from the nayan folder:   python -m unittest discover -s tests -v
Needs the sibling folders ..\aditya (examcrypto) and ..\ansh (threatdetect).
"""

import io
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from controlcenter import bootstrap  # noqa: F401  (adds aditya/ and ansh/ to sys.path)
from controlcenter import passwords, totp
from controlcenter.restrictions import RestrictionStore
from controlcenter.server import CSP, build
from controlcenter.sessions import SessionManager
from controlcenter.users import UserError, UserStore

from examcrypto.blockchain import MockBlockchain
from examcrypto.events import JsonlEventSink, verify_chain
from examcrypto.keystore import KeyStore
from examcrypto.service import PaperService
from examcrypto.storage import LocalStorage

PASS = b"controlcenter-test-pass"
PDF = b"%PDF-1.4\nCONTROL CENTER TEST PAPER\n%%EOF\n"
PW = {"admin1": "Admin-pass-111", "admin2": "Admin-pass-222", "aud1": "Auditor-pass-1",
      "auth1": "Authority-pass-1", "off1": "Officer-pass-11"}
ROLE = {"admin1": "admin", "admin2": "admin", "aud1": "auditor", "auth1": "exam_authority", "off1": "release_officer"}


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 20, 6, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, **kw):
        self.now += timedelta(**kw)


# ----------------------------------------------------------------- building blocks
class Passwords(unittest.TestCase):
    def test_hash_verify_and_salt(self):
        h1, h2 = passwords.hash_password("Correct-horse-9"), passwords.hash_password("Correct-horse-9")
        self.assertNotEqual(h1, h2)                                   # random salt
        self.assertTrue(h1.startswith("scrypt$16384$8$1$"))
        self.assertTrue(passwords.verify_password("Correct-horse-9", h1))
        self.assertFalse(passwords.verify_password("Correct-horse-8", h1))
        self.assertFalse(passwords.verify_password("x", "garbage"))

    def test_policy(self):
        self.assertTrue(passwords.policy_problems("short1"))
        self.assertTrue(passwords.policy_problems("alllowercaseletters"))
        self.assertTrue(passwords.policy_problems("password12"))                          # common
        self.assertTrue(passwords.policy_problems("Admin1-aditya-pw", "aditya"))
        self.assertEqual(passwords.policy_problems("Exam-vault-2026"), [])


class Totp(unittest.TestCase):
    RFC_KEY = b"12345678901234567890"                                 # RFC 6238 appendix B (SHA-1)

    def test_rfc6238_vectors(self):
        for t, expected in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                            (1234567890, "89005924"), (2000000000, "69279037")]:
            self.assertEqual(totp.hotp(self.RFC_KEY, t // 30, digits=8), expected)

    def test_rfc4226_vectors(self):
        for c, expected in enumerate(["755224", "287082", "359152", "969429", "338314"]):
            self.assertEqual(totp.hotp(self.RFC_KEY, c), expected)

    def test_verify_window_and_replay(self):
        s = totp.generate_secret()
        now = 1_800_000_000
        step = totp.verify(s, totp.code_at(s, now - 30), now)            # one step of clock drift is OK
        self.assertEqual(step, now // 30 - 1)
        self.assertIsNone(totp.verify(s, totp.code_at(s, now - 90), now))
        self.assertIsNone(totp.verify(s, totp.code_at(s, now), now, last_step=now // 30))   # replay
        self.assertIsNone(totp.verify(s, "12ab56", now))
        self.assertTrue(totp.provisioning_uri(s, "admin1").startswith("otpauth://totp/ExamCryptoCloud%3Aadmin1?secret="))


class Stores(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.now = datetime(2026, 11, 20, tzinfo=timezone.utc)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_users_persist_and_validate(self):
        us = UserStore(self.tmp / "users.json")
        us.create("Alice.k", "auditor", "Auditor-pass-1", self.now)
        self.assertEqual(UserStore(self.tmp / "users.json").public("alice.k")["role"], "auditor")
        raw = (self.tmp / "users.json").read_text()
        self.assertNotIn("Auditor-pass-1", raw)                        # never plaintext
        for bad in [("1abc", "auditor", "Auditor-pass-1"), ("bob", "superuser", "Auditor-pass-1"),
                    ("bob", "auditor", "weak"), ("alice.k", "auditor", "Auditor-pass-1")]:
            with self.assertRaises(UserError):
                us.create(*bad, self.now)

    def test_lockout_after_five_failures_then_expires(self):
        us = UserStore(self.tmp / "users.json")
        us.create("bob", "auditor", "Auditor-pass-1", self.now)
        for i in range(4):
            self.assertIsNone(us.record_failure("bob", self.now + timedelta(seconds=i)))
        locked = us.record_failure("bob", self.now + timedelta(seconds=5))
        self.assertEqual(locked, self.now + timedelta(seconds=5, minutes=15))
        self.assertIsNotNone(us.locked_until("bob", self.now + timedelta(minutes=10)))
        self.assertIsNone(us.locked_until("bob", self.now + timedelta(minutes=16)))

    def test_sessions_idle_absolute_revoke_and_hashed(self):
        sm = SessionManager()
        tok, _ = sm.create("bob", "auditor", self.now)
        self.assertNotIn(tok, json.dumps(list(sm._s)))                  # only hashes kept
        self.assertEqual(sm.resolve(tok, self.now + timedelta(minutes=29))["username"], "bob")
        self.assertIsNone(sm.resolve(tok, self.now + timedelta(minutes=29 + 31)))   # idle
        tok2, _ = sm.create("bob", "auditor", self.now)
        t = self.now
        for _ in range(17):                                           # keep active 8.5 h
            t += timedelta(minutes=30)
            r = sm.resolve(tok2, t)
        self.assertIsNone(r)                                          # absolute lifetime
        tok3, _ = sm.create("bob", "auditor", self.now)
        self.assertEqual(sm.revoke_user("bob"), 1)
        self.assertIsNone(sm.resolve(tok3, self.now))

    def test_restrictions_expire_and_lift(self):
        rs = RestrictionStore(self.tmp / "r.jsonl")
        rs.restrict("bob", "admin1", "alert", self.now, hours=2)
        self.assertTrue(rs.is_restricted("bob", self.now + timedelta(hours=1)))
        self.assertFalse(rs.is_restricted("bob", self.now + timedelta(hours=3)))
        rs.restrict("bob", "admin1", "again", self.now)                 # indefinite
        self.assertTrue(rs.is_restricted("bob", self.now + timedelta(days=99)))
        rs.lift("bob", "admin1", "cleared", self.now)
        self.assertFalse(rs.is_restricted("bob", self.now))
        self.assertEqual([r["record"] for r in rs.history()], ["restrict", "restrict", "lift"])


# ------------------------------------------------------------------ whole server
class Server(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.clock = Clock()
        self.ks = KeyStore(self.tmp / "keys"); self.ks.init_keys(PASS)
        self.events = JsonlEventSink(self.tmp / "local_storage" / "events" / "events.jsonl",
                                     signer=self.ks.audit_private(PASS))
        self.chain = MockBlockchain(self.tmp / "local_storage" / "chain.json", clock=self.clock)
        self.service = PaperService(storage=LocalStorage(self.tmp / "local_storage"), keystore=self.ks,
                                    passphrase=PASS, events=self.events, blockchain=self.chain, clock=self.clock)
        self.app, self.ctx = build(service=self.service, keystore=self.ks, data_dir=self.tmp,
                                   watcher=True, interval=0.1)
        self.c = self.app.test_client()
        for u, pw in PW.items():
            self.ctx.auth.users.create(u, ROLE[u], pw, self.clock())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # helpers
    def login(self, user, pw=None, code=None):
        return self.c.post("/api/v1/auth/login", json={"username": user, "password": pw or PW[user], "totp": code})

    def token(self, user):
        r = self.login(user)
        self.assertEqual(r.status_code, 200, r.get_json())
        return {"Authorization": "Bearer " + r.get_json()["token"]}

    def upload(self, hdr, release="2026-12-01T09:00:00Z"):
        return self.c.post("/api/v1/papers", headers=hdr, content_type="multipart/form-data",
                           data={"file": (io.BytesIO(PDF), "p.pdf"), "exam_id": "CS301", "release_at_utc": release})

    def events_where(self, **kw):
        return [e for e in self.events.read(limit=0) if all(e.get(k) == v for k, v in kw.items())]

    # -------------------------------------------------------------- login
    def test_login_success_and_me(self):
        r = self.login("aud1").get_json()
        self.assertEqual((r["username"], r["role"]), ("aud1", "auditor"))
        me = self.c.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + r["token"]}).get_json()
        self.assertEqual(me["role"], "auditor")
        self.assertEqual(len(self.events_where(action="LOGIN", result="SUCCESS")), 1)

    def test_wrong_password_and_unknown_user_look_identical(self):
        a, b = self.login("aud1", "Wrong-pass-123"), self.login("nobody", "Wrong-pass-123")
        self.assertEqual((a.status_code, b.status_code), (401, 401))
        self.assertEqual(a.get_json()["message"], b.get_json()["message"])
        self.assertEqual(self.c.post("/api/v1/auth/login", json={"username": "<script>", "password": "x"}).status_code, 401)
        self.assertEqual(len(self.events_where(reason_code="LOGIN_FAILED")), 3)
        self.assertTrue(all(e["actor_id"] in ("aud1", "nobody", "invalid") for e in self.events_where(reason_code="LOGIN_FAILED")))

    def test_lockout(self):
        for _ in range(5):
            self.assertEqual(self.login("aud1", "Wrong-pass-123").status_code, 401)
        r = self.login("aud1")                                          # correct password, still locked
        self.assertEqual((r.status_code, r.get_json()["reason_code"]), (429, "ACCOUNT_LOCKED"))
        self.clock.advance(minutes=16)
        self.assertEqual(self.login("aud1").status_code, 200)

    def test_mfa_flow_and_replay(self):
        secret = self.ctx.auth.users.enable_totp("admin1")
        r = self.login("admin1")
        self.assertEqual((r.status_code, r.get_json()["reason_code"]), (401, "MFA_REQUIRED"))
        code = totp.code_at(secret, self.clock().timestamp())
        self.assertEqual(self.login("admin1", code="000000" if code != "000000" else "111111").status_code, 401)
        self.assertEqual(self.login("admin1", code=code).status_code, 200)
        self.assertEqual(self.login("admin1", code=code).status_code, 401)            # replay refused

    def test_logout_and_bad_tokens(self):
        hdr = self.token("aud1")
        self.assertEqual(self.c.post("/api/v1/auth/logout", headers=hdr).status_code, 200)
        self.assertEqual(self.c.get("/api/v1/auth/me", headers=hdr).status_code, 401)
        self.assertEqual(self.c.get("/api/v1/dashboard/overview", headers={"Authorization": "Bearer forged"}).status_code, 401)
        self.assertEqual(self.c.get("/api/v1/dashboard/overview").status_code, 401)

    def test_session_expires_after_idle(self):
        hdr = self.token("aud1")
        self.clock.advance(minutes=31)
        self.assertEqual(self.c.get("/api/v1/auth/me", headers=hdr).status_code, 401)

    # ---------------------------------------------------- examcrypto behind login
    def test_paper_flow_with_real_accounts(self):
        r = self.upload(self.token("auth1"))
        self.assertEqual(r.status_code, 201, r.get_json())
        pid = r.get_json()["paper_id"]
        self.assertEqual(self.events_where(event_type="UPLOAD", result="SUCCESS")[0]["actor_id"], "auth1")
        self.assertEqual(self.upload(self.token("off1")).status_code, 403)              # wrong role
        off = self.token("off1")
        self.clock.now = datetime(2026, 12, 1, 9, 0, tzinfo=timezone.utc)
        off = self.token("off1")                                                        # fresh session at exam time
        self.assertEqual(self.c.post(f"/api/v1/papers/{pid}/release", headers=off).get_json()["reason_code"], "CHAIN_NOT_RELEASED")
        for c in range(3):
            self.chain.approve_release(pid, 1, c)
        rel = self.c.post(f"/api/v1/papers/{pid}/release", headers=off)
        self.assertEqual((rel.status_code, rel.data), (200, PDF))
        papers = self.c.get("/api/v1/dashboard/papers", headers=self.token("aud1")).get_json()["papers"]
        self.assertEqual([(p["paper_id"], p["release_status"]) for p in papers], [(pid, "RELEASABLE")])

    def test_dev_tokens_are_not_accepted(self):
        self.assertEqual(self.c.post("/api/v1/papers", headers={"Authorization": "Bearer tok-authority"}).status_code, 401)

    # -------------------------------------------------------------- restrictions
    def test_restrict_blocks_everything_then_lift(self):
        auth_hdr, admin = self.token("auth1"), self.token("admin1")
        r = self.c.post("/api/v1/access/users/auth1/restrict", headers=admin, json={"reason": "suspicious uploads", "hours": 2})
        self.assertEqual((r.status_code, r.get_json()["restriction"]["sessions_revoked"]), (200, 1))
        self.assertEqual(self.upload(auth_hdr).status_code, 401)                       # session killed
        login = self.login("auth1")
        self.assertEqual((login.status_code, login.get_json()["reason_code"]), (403, "ACCOUNT_RESTRICTED"))
        lift = self.c.post("/api/v1/access/users/auth1/unrestrict", headers=admin, json={"reason": "false alarm"})
        self.assertEqual(lift.status_code, 200)
        self.assertEqual(self.upload(self.token("auth1")).status_code, 201)
        acts = [e["action"] for e in self.events_where(event_type="ADMIN_ACTION")]
        self.assertEqual(acts, ["RESTRICT_ACCOUNT", "LIFT_RESTRICTION"])
        self.assertEqual(self.events_where(action="RESTRICT_ACCOUNT")[0]["target_actor_id"], "auth1")

    def test_restriction_recorded_elsewhere_still_blocks_open_session(self):
        """Defence in depth: a restriction written by another process/CLI (sessions NOT revoked
        here) must still stop the very next request of an already-logged-in user."""
        hdr = self.token("auth1")
        self.ctx.auth.restrictions.restrict("auth1", "admin1", "set from another console", self.clock())
        r = self.upload(hdr)
        self.assertEqual((r.status_code, r.get_json()["reason_code"]), (403, "ACCOUNT_RESTRICTED"))
        self.assertEqual(self.c.get("/api/v1/auth/me", headers=hdr).status_code, 401)   # session now killed

    def test_restriction_expires(self):
        admin = self.token("admin1")
        self.c.post("/api/v1/access/users/aud1/restrict", headers=admin, json={"reason": "x", "hours": 1})
        self.assertEqual(self.login("aud1").status_code, 403)
        self.clock.advance(hours=1, minutes=1)
        self.assertEqual(self.login("aud1").status_code, 200)

    def test_restriction_guards(self):
        admin = self.token("admin1")
        self.assertEqual(self.c.post("/api/v1/access/users/admin1/restrict", headers=admin, json={"reason": "x"}).status_code, 409)
        self.assertEqual(self.c.post("/api/v1/access/users/aud1/restrict", headers=admin, json={"reason": ""}).status_code, 400)
        self.assertEqual(self.c.post("/api/v1/access/users/ghost/restrict", headers=admin, json={"reason": "x"}).status_code, 400)
        self.assertEqual(self.c.post("/api/v1/access/users/aud1/restrict", headers=admin, json={"reason": "x", "hours": 9999}).status_code, 400)
        self.assertEqual(self.c.post("/api/v1/access/users/admin2/restrict", headers=admin, json={"reason": "x"}).status_code, 200)
        from examcrypto.errors import ExamCryptoError
        with self.assertRaises(ExamCryptoError) as cm:                                  # admin1 is now the last admin
            self.ctx.auth.restrict({"actor_id": "system", "role": "admin"}, "admin1", "x")
        self.assertIn("last active administrator", str(cm.exception))

    def test_auditor_is_read_only(self):
        aud = self.token("aud1")
        for path in ("/api/v1/dashboard/overview", "/api/v1/alerts", "/api/v1/access/users",
                     "/api/v1/access/restrictions", "/api/v1/system/health", "/api/v1/events"):
            self.assertEqual(self.c.get(path, headers=aud).status_code, 200, path)
        self.assertEqual(self.c.post("/api/v1/access/users/auth1/restrict", headers=aud, json={"reason": "x"}).status_code, 403)
        self.assertEqual(self.c.post("/api/v1/access/users", headers=aud, json={"username": "eve", "role": "admin", "password": "Admin-pass-999"}).status_code, 403)
        self.assertEqual(self.c.post("/api/v1/events/anchor", headers=aud).status_code, 403)
        denied = self.events_where(event_type="ADMIN_ACTION", reason_code="ROLE_NOT_ALLOWED")
        self.assertEqual(len(denied), 2)

    def test_paper_roles_cannot_use_admin_pages(self):
        for u in ("auth1", "off1"):
            self.assertEqual(self.c.get("/api/v1/dashboard/overview", headers=self.token(u)).status_code, 403)

    def test_admin_creates_user(self):
        admin = self.token("admin1")
        r = self.c.post("/api/v1/access/users", headers=admin, json={"username": "newofficer", "role": "release_officer", "password": "Officer-pass-22"})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.login("newofficer", "Officer-pass-22").status_code, 200)
        weak = self.c.post("/api/v1/access/users", headers=admin, json={"username": "weakling", "role": "auditor", "password": "abc"})
        self.assertEqual(weak.status_code, 400)

    # ------------------------------------------------- AI alerts -> human review
    def make_alert_via_watcher(self, actor="auth1", code="SIGNATURE_INVALID"):
        """Real path: examcrypto events -> Ansh's watcher -> AlertStore."""
        from examcrypto.events import build_event
        for _ in range(3):
            self.events.emit(build_event("RELEASE_REQUEST", actor={"actor_id": actor, "role": ROLE.get(actor, "unknown")},
                                         reason_code=code, paper_id="pap_0123456789abcdef"))
        self.ctx.watcher.poll_once()
        return self.ctx.alerts.list()

    def test_watcher_alert_reviewed_and_actor_restricted(self):
        alerts = self.make_alert_via_watcher()
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual((a["severity"], a["recommended_action"]), ("HIGH", "TEMPORARY_RESTRICT"))
        admin = self.token("admin1")
        listed = self.c.get("/api/v1/alerts?severity=HIGH", headers=admin).get_json()["alerts"]
        self.assertEqual(listed[0]["alert_id"], a["alert_id"])
        self.assertEqual(self.c.post(f"/api/v1/alerts/{a['alert_id']}/review", headers=admin, json={"status": "CLOSED"}).status_code, 400)
        ack = self.c.post(f"/api/v1/alerts/{a['alert_id']}/review", headers=admin, json={"status": "ACKNOWLEDGED", "note": "looking"})
        self.assertEqual(ack.get_json()["alert"]["status"], "ACKNOWLEDGED")
        r = self.c.post(f"/api/v1/alerts/{a['alert_id']}/restrict", headers=admin, json={"hours": 24})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["alert"]["access_action"]["action"], "RESTRICTED")
        self.assertEqual(self.login("auth1").get_json()["reason_code"], "ACCOUNT_RESTRICTED")
        closed = self.c.post(f"/api/v1/alerts/{a['alert_id']}/review", headers=admin, json={"status": "CLOSED", "note": "confirmed tampering attempt"})
        hist = closed.get_json()["alert"]["history"]
        self.assertEqual([h_.get("status") for h_ in hist if h_.get("status")], ["ACKNOWLEDGED", "CLOSED"])
        self.assertEqual(self.events_where(action="ALERT_CLOSED")[0]["alert_id"], a["alert_id"])

    def test_anonymous_actor_cannot_be_restricted(self):
        a = self.make_alert_via_watcher(actor="unknown", code="CIPHERTEXT_DIGEST_MISMATCH")[0]
        r = self.c.post(f"/api/v1/alerts/{a['alert_id']}/restrict", headers=self.token("admin1"), json={})
        self.assertEqual(r.status_code, 409)

    def test_failed_logins_become_an_alert(self):
        for _ in range(9):
            self.login("nobody", "Wrong-pass-123")
        self.ctx.watcher.poll_once()
        reasons = [c for a in self.ctx.alerts.list() for c in a["reason_codes"]]
        self.assertIn("AUTH_FAILURE_BURST", reasons)

    def test_only_admin_reviews(self):
        a = self.make_alert_via_watcher()[0]
        self.assertEqual(self.c.post(f"/api/v1/alerts/{a['alert_id']}/review", headers=self.token("aud1"),
                                     json={"status": "ACKNOWLEDGED"}).status_code, 403)
        self.assertEqual(self.c.post("/api/v1/alerts/nope/review", headers=self.token("admin1"),
                                     json={"status": "ACKNOWLEDGED"}).status_code, 404)

    # ----------------------------------------------------- overview / health / UI
    def test_overview_and_health(self):
        self.upload(self.token("auth1"))
        self.make_alert_via_watcher()
        o = self.c.get("/api/v1/dashboard/overview", headers=self.token("admin1")).get_json()
        self.assertEqual(o["papers"]["total"], 1)
        self.assertEqual(o["alerts"]["open_by_severity"], {"HIGH": 1})
        self.assertEqual(o["access"]["users"], 5)
        self.assertEqual((o["chain"]["mode"], o["chain"]["reachable"]), ("mock", True))
        h = self.c.get("/api/v1/system/health", headers=self.token("aud1")).get_json()
        self.assertEqual((h["api"], h["audit_log"]["ok"], h["release_requires_chain"]), ("OK", True, True))
        self.assertIsNotNone(h["watcher"]["last_poll_utc"])

    def test_every_action_is_in_the_signed_audit_chain(self):
        admin = self.token("admin1")
        self.c.post("/api/v1/access/users/aud1/restrict", headers=admin, json={"reason": "x"})
        self.login("aud1")
        self.assertTrue(verify_chain(self.events.read(limit=0), self.ks.audit_public())["ok"])

    def test_dashboard_served_with_security_headers(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        r.close()
        self.assertIn('<script src="/ui/app.js" defer></script>', html)
        self.assertNotIn("<script>", html)                                              # no inline scripts
        self.assertEqual(r.headers["Content-Security-Policy"], CSP)
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        js = self.c.get("/ui/app.js")
        self.assertEqual(js.status_code, 200)
        js.close()
        self.assertEqual(self.c.get("/ui/../server.py").status_code, 404)
        self.assertEqual(self.c.get("/ui/server.py").status_code, 404)

    def test_watcher_thread_runs_in_background(self):
        import time
        self.ctx.watcher.start()
        try:
            deadline = time.time() + 5
            while self.ctx.watcher.status["last_poll_utc"] is None and time.time() < deadline:
                time.sleep(0.05)
            self.assertTrue(self.ctx.watcher.status["running"])
            self.assertIsNotNone(self.ctx.watcher.status["last_poll_utc"])
        finally:
            self.ctx.watcher.stop()


if __name__ == "__main__":
    unittest.main()
