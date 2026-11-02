"""LABELLED SYNTHETIC dataset in the examcrypto audit-event format.

There is no real labelled attack data for this project, so behaviour is simulated:
normal daily work by each role, plus six attack scenarios. Every metric computed on
this data must be reported as "on synthetic data". Scenario names are kept so we
can report per-scenario detection and test an UNSEEN attack type.
"""

import random
import uuid
from datetime import datetime, timedelta, timezone

from .schema import fmt_ts

IST = timezone(timedelta(hours=5, minutes=30))

ATTACKS = {
    "early_release_probing": "insider repeatedly asks for a paper before release time",
    "credential_stuffing":   "burst of requests with missing/unknown tokens",
    "role_probing":          "low-privilege account tries upload/release repeatedly",
    "tampering":             "release attempts that fail signature/digest/decryption checks",
    "off_hours_bulk_access": "admin account reads many papers between 01:00 and 04:00",
    "blocked_paper_access":  "repeated attempts to open a frozen/revoked paper",
}


class _Gen:
    def __init__(self, seed: int, start: datetime):
        self.r = random.Random(seed)
        self.start = start
        self.rows = []            # (event, label, scenario)
        self.papers = [f"pap_{self.r.getrandbits(64):016x}" for _ in range(40)]

    def ev(self, ts, etype, actor, role, result="SUCCESS", reason=None, paper=None,
           label=0, scenario="normal"):
        e = {"schema_version": "2", "event_id": str(uuid.UUID(int=self.r.getrandbits(128))),
             "event_type": etype, "timestamp_utc": fmt_ts(ts), "source_component": "crypto_api",
             "actor_id": actor, "actor_role": role, "result": result}
        if reason:
            e["reason_code"] = reason
        if paper:
            e["paper_id"] = paper
        self.rows.append((e, label, scenario))

    def at(self, day: int, hour: float):
        local = (self.start + timedelta(days=day)).astimezone(IST).replace(hour=0, minute=0, second=0)
        return (local + timedelta(hours=hour)).astimezone(timezone.utc)

    # ---------------------------------------------------------------- normal
    def normal_day(self, d: int):
        r = self.r
        weekday = (self.start + timedelta(days=d)).astimezone(IST).weekday() < 5
        if weekday:
            for a in range(3):                                    # exam authorities
                for _ in range(r.randint(0, 3)):
                    t = self.at(d, r.uniform(9.5, 17.5))
                    p = r.choice(self.papers)
                    self.ev(t, "UPLOAD", f"auth-{a}", "exam_authority", paper=p)
                    self.ev(t + timedelta(seconds=r.randint(5, 120)), "STATUS_CHECK",
                            f"auth-{a}", "exam_authority", paper=p)
            for a in range(2):                                    # auditors
                for _ in range(r.randint(2, 8)):
                    self.ev(self.at(d, r.uniform(10, 18)), r.choice(["STATUS_CHECK", "MANIFEST_READ"]),
                            f"aud-{a}", "auditor", paper=r.choice(self.papers))
        for a in range(2):                                        # admins (some evening work)
            for _ in range(r.randint(1, 6)):
                self.ev(self.at(d, r.uniform(9, 21)), r.choice(["STATUS_CHECK", "MANIFEST_READ", "AUTH"]),
                        f"adm-{a}", "admin", paper=r.choice(self.papers))
        if r.random() < 0.5:                                      # exam session: officers release
            exam_h = r.choice([10.0, 14.0])
            for a in range(2):
                p = r.choice(self.papers)
                if r.random() < 0.3:                              # honest slightly-early click
                    self.ev(self.at(d, exam_h - r.uniform(0.01, 0.05)), "RELEASE_REQUEST",
                            f"off-{a}", "release_officer", "DENIED", "RELEASE_TIME_NOT_REACHED", p)
                if r.random() < 0.2:                              # custodians a bit slow
                    self.ev(self.at(d, exam_h + 0.01), "RELEASE_REQUEST", f"off-{a}", "release_officer",
                            "DENIED", "CHAIN_NOT_RELEASED", p)
                self.ev(self.at(d, exam_h + r.uniform(0.02, 0.2)), "RELEASE_REQUEST",
                        f"off-{a}", "release_officer", paper=p)
        if r.random() < 0.15:                                     # occasional honest mistakes
            self.ev(self.at(d, r.uniform(10, 17)), "UPLOAD", f"aud-{r.randint(0, 1)}", "auditor",
                    "DENIED", "ROLE_NOT_ALLOWED")
        if r.random() < 0.2:
            self.ev(self.at(d, r.uniform(9, 19)), "AUTH", "unknown", "unknown", "DENIED", "AUTH_REQUIRED")

    # ---------------------------------------------------------------- attacks
    def attack(self, d: int, kind: str, n: int = 0):
        r, L = self.r, dict(label=1, scenario=f"{kind}#{n}")   # one id per attack episode
        if kind == "early_release_probing":
            t, p = self.at(d, r.uniform(7, 9)), r.choice(self.papers)
            for i in range(r.randint(6, 15)):
                self.ev(t + timedelta(seconds=i * r.randint(20, 180)), "RELEASE_REQUEST", "off-x",
                        "release_officer", "DENIED", "RELEASE_TIME_NOT_REACHED", p, **L)
        elif kind == "credential_stuffing":
            t = self.at(d, r.uniform(0, 24))
            for i in range(r.randint(15, 40)):
                self.ev(t + timedelta(seconds=i * r.uniform(0.5, 8)), "AUTH", "unknown", "unknown",
                        "DENIED", "AUTH_REQUIRED", **L)
        elif kind == "role_probing":
            t = self.at(d, r.uniform(9, 18))
            for i in range(r.randint(5, 12)):
                self.ev(t + timedelta(seconds=i * r.randint(10, 90)), r.choice(["UPLOAD", "RELEASE_REQUEST"]),
                        "stu-x", "student", "DENIED", "ROLE_NOT_ALLOWED", r.choice(self.papers), **L)
        elif kind == "tampering":
            t, p = self.at(d, r.uniform(9, 16)), r.choice(self.papers)
            for i in range(r.randint(2, 6)):
                self.ev(t + timedelta(seconds=i * r.randint(30, 300)), "RELEASE_REQUEST", "off-y",
                        "release_officer", "FAILED",
                        r.choice(["SIGNATURE_INVALID", "CIPHERTEXT_DIGEST_MISMATCH",
                                  "DECRYPTION_AUTHENTICATION_FAILED"]), p, **L)
        elif kind == "off_hours_bulk_access":
            t = self.at(d, r.uniform(1, 3.5))
            for i in range(r.randint(10, 30)):
                self.ev(t + timedelta(seconds=i * r.randint(15, 90)), r.choice(["MANIFEST_READ", "STATUS_CHECK"]),
                        "adm-x", "admin", paper=r.choice(self.papers), **L)
        elif kind == "blocked_paper_access":
            t, p = self.at(d, r.uniform(9, 17)), r.choice(self.papers)
            for i in range(r.randint(3, 8)):
                self.ev(t + timedelta(seconds=i * r.randint(30, 240)), "RELEASE_REQUEST", "off-z",
                        "release_officer", "DENIED", "CHAIN_PAPER_BLOCKED", p, **L)
        else:
            raise ValueError(kind)


def generate(days: int = 60, seed: int = 1, attacks_per_kind: int = 6,
             kinds=tuple(ATTACKS), start: datetime | None = None):
    """Returns (events, labels, scenarios), sorted by time.
    scenarios: "normal" or "<attack kind>#<episode number>"."""
    g = _Gen(seed, start or datetime(2026, 9, 1, tzinfo=timezone.utc))
    for d in range(days):
        g.normal_day(d)
    for kind in kinds:
        for n in range(attacks_per_kind):
            g.attack(g.r.randrange(days), kind, n)
    g.rows.sort(key=lambda row: row[0]["timestamp_utc"])
    events = [e for e, _, _ in g.rows]
    for i, e in enumerate(events, start=1):
        e["seq"] = i
    return events, [lab for _, lab, _ in g.rows], [s for _, _, s in g.rows]
