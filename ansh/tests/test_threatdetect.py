r"""Tests for Ansh's threat-detection module (stdlib unittest).

Run from the ansh folder:   python -m unittest discover -s tests -v
The cross-module tests use Aditya's examcrypto package from ..\aditya if present.
"""

import json
import shutil
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import numpy as np

from threatdetect import rules
from threatdetect.alerts import AlertStore
from threatdetect.chainflag import GatewayFlagger, flag_payload, load_or_create_salt, subject_hash
from threatdetect.features import FEATURES, FeatureExtractor, extract
from threatdetect.model import ThreatModel
from threatdetect.schema import TamperedLogError, check_chain, fmt_ts
from threatdetect.scoring import Scorer
from threatdetect.synthetic import ATTACKS, generate
from threatdetect.watcher import Watcher

ADITYA = Path(__file__).resolve().parents[2] / "aditya"
IDX = {n: i for i, n in enumerate(FEATURES)}
T0 = datetime(2026, 11, 2, 6, 0, tzinfo=timezone.utc)          # 11:30 IST, Monday


def ev(seq, minutes, etype="STATUS_CHECK", actor="u1", role="auditor", result="SUCCESS",
       reason=None, paper=None):
    e = {"seq": seq, "event_type": etype, "timestamp_utc": fmt_ts(T0 + timedelta(minutes=minutes)),
         "actor_id": actor, "actor_role": role, "result": result}
    if reason:
        e["reason_code"] = reason
    if paper:
        e["paper_id"] = paper
    return e


_MODEL = None


def small_model():
    global _MODEL
    if _MODEL is None:
        events, y, _ = generate(days=25, seed=11, attacks_per_kind=4)
        _MODEL = ThreatModel.train(extract(events), y, seed=3)
    return _MODEL


# ------------------------------------------------------------------ data + features
class SyntheticData(unittest.TestCase):
    def test_deterministic_and_labelled(self):
        a = generate(days=10, seed=5, attacks_per_kind=2)
        b = generate(days=10, seed=5, attacks_per_kind=2)
        self.assertEqual(json.dumps(a[0]), json.dumps(b[0]))
        events, labels, scen = a
        self.assertEqual(len(events), len(labels))
        self.assertEqual({s.split("#")[0] for s, l in zip(scen, labels) if l}, set(ATTACKS))
        self.assertEqual(len({s for s, l in zip(scen, labels) if l}), 2 * len(ATTACKS))   # episode ids
        ts = [e["timestamp_utc"] for e in events]
        self.assertEqual(ts, sorted(ts))


class Features(unittest.TestCase):
    def test_no_look_ahead(self):
        events = [ev(i, i) for i in range(1, 6)]
        first = extract(events[:3])
        full = extract(events)
        self.assertEqual(first, full[:3])

    def test_windows_and_counts(self):
        fx = FeatureExtractor()
        for i in range(4):
            x = fx.update(ev(i + 1, i, "RELEASE_REQUEST", "off", "release_officer", "DENIED",
                             "RELEASE_TIME_NOT_REACHED", "pap_a"))
        self.assertEqual((x[IDX["events_10m"]], x[IDX["early_release_1h"]], x[IDX["denied_10m"]]), (4, 4, 4))
        x = fx.update(ev(5, 30, "RELEASE_REQUEST", "off", "release_officer", paper="pap_b"))
        self.assertEqual(x[IDX["events_10m"]], 1)                # earlier ones left the 10-min window
        self.assertEqual(x[IDX["early_release_1h"]], 4)          # but are still in the 1-hour window
        self.assertEqual(x[IDX["distinct_papers_1h"]], 2)
        x = fx.update(ev(6, 120, "RELEASE_REQUEST", "off", "release_officer"))
        self.assertEqual(x[IDX["early_release_1h"]], 0)

    def test_login_failures_count_as_auth_failures(self):
        fx = FeatureExtractor()
        for i, code in enumerate(["LOGIN_FAILED", "MFA_REQUIRED", "ACCOUNT_LOCKED", "AUTH_REQUIRED"]):
            x = fx.update(ev(i + 1, i, "AUTH", "mallory", "unknown", "DENIED", code))
        self.assertEqual(x[IDX["auth_fail_10m"]], 4)
        x = fx.update(ev(5, 5, "UPLOAD", "mallory", "unknown", "DENIED", "ACCOUNT_RESTRICTED"))
        self.assertEqual(x[IDX["blocked_paper_1h"]], 1)

    def test_actors_are_separate_and_ist_hours(self):
        fx = FeatureExtractor()
        fx.update(ev(1, 0, actor="a"))
        x = fx.update(ev(2, 1, actor="b"))
        self.assertEqual(x[IDX["events_10m"]], 1)
        self.assertEqual(x[IDX["hour_local"]], 11)               # 06:01 UTC = 11:31 IST
        late = fx.update(ev(3, 16 * 60, actor="c"))              # 22:00 UTC = 03:30 IST
        self.assertEqual((late[IDX["hour_local"]], late[IDX["off_hours"]]), (3, 1))


# --------------------------------------------------------------------------- rules
class Rules(unittest.TestCase):
    def fx(self, **kw):
        x = [0.0] * len(FEATURES)
        x[IDX["hour_local"]] = 12
        for k, v in kw.items():
            x[IDX[k]] = float(v)
        return x

    def test_benign_scores_zero(self):
        self.assertEqual(rules.evaluate(self.fx(events_10m=3)), (0, []))

    def test_each_rule_fires(self):
        cases = {"INTEGRITY_FAILURE": dict(integrity_fail_1h=1), "AUTH_FAILURE_BURST": dict(auth_fail_10m=8),
                 "EARLY_RELEASE_PROBING": dict(early_release_1h=4), "BLOCKED_PAPER_ACCESS": dict(blocked_paper_1h=2),
                 "ROLE_PROBING": dict(role_denied_1h=3), "OFF_HOURS_BULK_ACCESS": dict(off_hours=1, distinct_papers_1h=5),
                 "HIGH_REQUEST_RATE": dict(events_10m=15), "REPEATED_DENIALS": dict(denied_10m=3)}
        for code, kw in cases.items():
            score, reasons = rules.evaluate(self.fx(**kw))
            self.assertIn(code, reasons, code)
            self.assertGreaterEqual(score, 40, code)

    def test_score_combines_and_caps(self):
        score, reasons = rules.evaluate(self.fx(integrity_fail_1h=1, early_release_1h=9, denied_10m=9, events_10m=40))
        self.assertEqual(reasons[0], "INTEGRITY_FAILURE")
        self.assertEqual(score, min(100, 80 + 5 * (len(reasons) - 1)))


# --------------------------------------------------------------------------- model
class Model(unittest.TestCase):
    def test_explanation_adds_up_exactly(self):
        m = small_model()
        events, _, _ = generate(days=5, seed=77, attacks_per_kind=1)
        for x in extract(events)[:40]:
            bias, contrib = m.contributions(x)
            self.assertAlmostEqual(bias + contrib.sum(), m.attack_proba([x])[0], places=9)

    def test_anomaly_range_and_attack_ranking(self):
        m = small_model()
        events, y, _ = generate(days=10, seed=78, attacks_per_kind=2)
        X = extract(events)
        an, p = m.anomaly(X), m.attack_proba(X)
        self.assertTrue(((an >= 0) & (an <= 1)).all())
        y = np.array(y)
        self.assertGreater(p[y == 1].mean(), p[y == 0].mean() + 0.5)

    def test_save_load_roundtrip_and_feature_guard(self):
        m = small_model()
        tmp = Path(tempfile.mkdtemp())
        try:
            m.save(tmp)
            m2 = ThreatModel.load(tmp)
            X = extract(generate(days=3, seed=79, attacks_per_kind=1)[0])
            np.testing.assert_allclose(m.attack_proba(X), m2.attack_proba(X))
            meta = json.loads((tmp / "model_meta.json").read_text())
            self.assertIn("SYNTHETIC", meta["training_data"])
            meta["features"] = meta["features"][:-1]
            (tmp / "model_meta.json").write_text(json.dumps(meta))
            with self.assertRaises(ValueError):
                ThreatModel.load(tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------------- scoring
class FakeModel:
    def __init__(self, rf=0.0, an=0.0):
        self.rf, self.an = rf, an

    def attack_proba(self, X):
        return np.full(len(X), self.rf)

    def anomaly(self, X):
        return np.full(len(X), self.an)

    def top_features(self, x, k=3):
        return []


class Scoring(unittest.TestCase):
    def test_isolation_forest_alone_never_restricts(self):
        a = Scorer(FakeModel(rf=0.0, an=1.0)).process(ev(1, 0))
        self.assertEqual((a["severity"], a["recommended_action"], a["risk_score"]), ("MEDIUM", "REVIEW", 65))
        self.assertIn("UNUSUAL_BEHAVIOUR", a["reason_codes"])

    def test_rf_can_raise_high(self):
        a = Scorer(FakeModel(rf=0.9)).process(ev(1, 0))
        self.assertEqual((a["severity"], a["recommended_action"], a["reason_codes"]),
                         ("HIGH", "TEMPORARY_RESTRICT", ["LEARNED_ATTACK_PATTERN"]))

    def test_every_alert_explains_itself(self):
        events, _, _ = generate(days=10, seed=99, attacks_per_kind=1)
        alerts = Scorer(small_model()).process_all(events)
        self.assertTrue(alerts)
        for a in alerts:
            self.assertTrue(a["reason_codes"], a)
        mid = Scorer(FakeModel(rf=0.42)).process(ev(1, 0))     # RF below 0.5 but still MEDIUM
        self.assertEqual((mid["severity"], mid["reason_codes"]), ("MEDIUM", ["LEARNED_ATTACK_PATTERN"]))

    def test_benign_event_no_alert(self):
        self.assertIsNone(Scorer(FakeModel()).process(ev(1, 0)))

    def test_suppression_folds_repeats_and_persists(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            store = AlertStore(tmp / "alerts.jsonl")
            s, ref = Scorer(None, store=store), Scorer(None)
            events = [ev(i + 1, i * 0.5, "AUTH", "unknown", "unknown", "DENIED", "AUTH_REQUIRED") for i in range(10)]
            alerting = sum(ref.score_event(e)["severity"] != "LOW" for e in events)   # first 2 are LOW
            out = []
            for e in events:
                a = s.process(e)
                if a:
                    store.add(a)
                    out.append(a)
            stored = store.load()                         # reloaded from disk
            self.assertEqual(alerting, 8)
            self.assertEqual(len(out) + sum(a["suppressed_count"] for a in stored.values()), alerting)
            self.assertLessEqual(len(out), 3)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_alert_has_link_to_audit_event(self):
        e = ev(1, 0, "RELEASE_REQUEST", "o", "release_officer", "FAILED", "SIGNATURE_INVALID", "pap_x")
        e["event_hash"], e["event_id"] = "ab" * 32, "evt-1"
        a = Scorer(None).process(e)
        self.assertEqual((a["event_hash"], a["event_id"], a["paper_id"], a["severity"]),
                         ("ab" * 32, "evt-1", "pap_x", "HIGH"))


# --------------------------------------------------------------------- alert store
class Store(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.s = AlertStore(self.tmp / "a.jsonl")
        self.s.add({"alert_id": "a1", "severity": "HIGH", "status": "NEW", "risk_score": 90})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_updates_merge_with_history(self):
        self.s.update("a1", by="admin1", status="ACKNOWLEDGED", review_note="looking")
        self.s.update("a1", by="admin1", status="CLOSED")
        a = self.s.load()["a1"]
        self.assertEqual((a["status"], a["review_note"], len(a["history"])), ("CLOSED", "looking", 2))
        self.assertEqual(a["history"][0]["by"], "admin1")
        self.assertEqual(len(self.s.list(status="CLOSED")), 1)

    def test_invalid_updates_rejected(self):
        with self.assertRaises(ValueError):
            self.s.update("a1", status="DELETED")
        with self.assertRaises(ValueError):
            self.s.update("a1", risk_score=0)          # scores cannot be edited by reviewers


# ---------------------------------------------------------------- chain flagging
class FakeGW(BaseHTTPRequestHandler):
    received = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeGW.received.append(body)
        data = json.dumps({"tx_id": "0xfeed", "flag_index": len(FakeGW.received)}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class ChainFlag(unittest.TestCase):
    def test_subject_hash_is_salted_pseudonym(self):
        a = subject_hash(b"salt-one", "release_officer", "off-x")
        self.assertEqual(a, subject_hash(b"salt-one", "release_officer", "off-x"))
        self.assertNotEqual(a, subject_hash(b"salt-two", "release_officer", "off-x"))
        self.assertNotIn("off-x", a)
        self.assertRegex(a, r"^0x[0-9a-f]{64}$")

    def test_salt_created_once(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            s1 = load_or_create_salt(tmp / "k" / "salt.bin")
            self.assertEqual(s1, load_or_create_salt(tmp / "k" / "salt.bin"))
            self.assertEqual(len(s1), 32)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_payload_and_gateway_call(self):
        alert = {"actor_role": "release_officer", "actor_id": "off-x", "risk_score": 87,
                 "reason_codes": ["INTEGRITY_FAILURE"], "event_hash": "cd" * 32, "model_version": "0.1.0"}
        p = flag_payload(alert, b"s")
        self.assertEqual((p["score"], p["event_hash"]), (87, "0x" + "cd" * 32))
        srv = HTTPServer(("127.0.0.1", 0), FakeGW)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            r = GatewayFlagger(b"s", f"http://127.0.0.1:{srv.server_port}", timeout=5).flag(alert)
            self.assertEqual((r["status"], r["tx_id"]), ("FLAGGED", "0xfeed"))
            self.assertEqual(FakeGW.received[-1], p)
        finally:
            srv.shutdown(); srv.server_close()
        self.assertEqual(GatewayFlagger(b"s", "http://127.0.0.1:9", timeout=2).flag(alert)["status"], "FAILED")


# ------------------------------------------------------------- live watcher (real log)
@unittest.skipUnless((ADITYA / "examcrypto").is_dir(), "aditya/ folder not next to ansh/")
class WatcherOnRealExamcryptoLog(unittest.TestCase):
    """Uses Aditya's real JsonlEventSink: proves both modules agree on the hash chain."""

    def setUp(self):
        sys.path.insert(0, str(ADITYA))
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
        from examcrypto.events import JsonlEventSink, build_event
        self.build_event = build_event
        self.tmp = Path(tempfile.mkdtemp())
        self.sink = JsonlEventSink(self.tmp / "events.jsonl", signer=MLDSA65PrivateKey.generate())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        sys.path.remove(str(ADITYA))

    def emit_tampering_attempts(self, n=3):
        actor = {"actor_id": "off-y", "role": "release_officer"}
        for _ in range(n):
            self.sink.emit(self.build_event("RELEASE_REQUEST", actor=actor, reason_code="SIGNATURE_INVALID",
                                            paper_id="pap_0123456789abcdef"))

    def test_chain_compatible_and_alerts_flagged(self):
        self.emit_tampering_attempts()
        check_chain([json.loads(l) for l in (self.tmp / "events.jsonl").read_text().splitlines()])

        class Flagger:
            calls = []
            def flag(self, a):
                self.calls.append(a)
                return {"status": "FLAGGED", "tx_id": "0x1"}

        fl = Flagger()
        w = Watcher(self.tmp / "events.jsonl", self.tmp / "alerts.jsonl", model=None, flagger=fl)
        alerts = w.poll()
        self.assertEqual(len(alerts), 1)                              # 3 events -> 1 alert (+2 folded)
        a = w.store.load()[alerts[0]["alert_id"]]
        self.assertEqual((a["severity"], a["reason_codes"][0], a["suppressed_count"]),
                         ("HIGH", "INTEGRITY_FAILURE", 2))
        self.assertEqual(a["chain_flag"]["status"], "FLAGGED")
        self.assertEqual(len(fl.calls), 1)
        self.assertEqual(w.poll(), [])                                # nothing new -> no duplicates
        w2 = Watcher(self.tmp / "events.jsonl", self.tmp / "alerts.jsonl")
        self.assertEqual(w2.poll(), [])                               # restart-safe

    def test_half_written_last_line_is_skipped_not_crashed(self):
        self.emit_tampering_attempts(1)
        with (self.tmp / "events.jsonl").open("a", encoding="utf-8") as f:
            f.write('{"seq": 2, "event_type": "UPL')                  # writer mid-line
        from threatdetect.schema import load_events
        self.assertEqual(len(load_events(self.tmp / "events.jsonl")), 1)

    def test_medium_alerts_are_not_written_on_chain(self):
        actor = {"actor_id": "off-z", "role": "release_officer"}
        for _ in range(3):                                            # 3 early clicks -> MEDIUM only
            self.sink.emit(self.build_event("RELEASE_REQUEST", actor=actor,
                                            reason_code="RELEASE_TIME_NOT_REACHED", paper_id="pap_0123456789abcdef"))
        calls = []

        class Flagger:
            def flag(self, a):
                calls.append(a)
                return {"status": "FLAGGED"}

        alerts = Watcher(self.tmp / "events.jsonl", self.tmp / "alerts.jsonl", flagger=Flagger()).poll()
        self.assertEqual([a["severity"] for a in alerts], ["MEDIUM"])
        self.assertEqual(calls, [])                                   # permanent records only for HIGH

    def test_tampered_log_raises_single_system_alert_and_stops(self):
        self.emit_tampering_attempts(2)
        lines = (self.tmp / "events.jsonl").read_text().splitlines()
        e = json.loads(lines[0]); e["actor_id"] = "someone-else"; lines[0] = json.dumps(e)
        (self.tmp / "events.jsonl").write_text("\n".join(lines) + "\n")
        w = Watcher(self.tmp / "events.jsonl", self.tmp / "alerts.jsonl")
        alerts = w.poll()
        self.assertEqual([a["reason_codes"] for a in alerts], [["AUDIT_LOG_TAMPERED"]])
        self.assertEqual(w.poll(), [])
        self.assertTrue(Watcher(self.tmp / "events.jsonl", self.tmp / "alerts.jsonl").tampered)
        with self.assertRaises(TamperedLogError):
            check_chain([json.loads(l) for l in lines])


# ---------------------------------------------------------------------- evaluation
class Evaluation(unittest.TestCase):
    def test_report_shape_and_complementarity(self):
        from threatdetect import evaluate
        r, _ = evaluate.run(days=25)
        self.assertIn("SYNTHETIC", r["data"])
        comb, rul = r["event_level"]["combined"], r["event_level"]["rules"]
        self.assertGreaterEqual(comb["recall"], rul["recall"])
        self.assertLess(comb["false_positive_rate"], 0.05)
        self.assertEqual(set(r["episode_level"]), set(ATTACKS))
        self.assertIn("held_out_type", r["unseen_attack"])
        md = evaluate.to_markdown(r)
        self.assertIn("NOT a measure of real-world accuracy", md)


if __name__ == "__main__":
    unittest.main()
