"""Behavioural features, computed per event from the actor's recent history.

Streaming: FeatureExtractor.update(event) returns the feature vector for that event,
using only events seen so far (no look-ahead), so the same code works offline and live.
"""

from collections import defaultdict, deque
from datetime import timedelta, timezone

from .schema import BLOCKED_CODES, EARLY_RELEASE_CODES, INTEGRITY_CODES, parse_ts

IST = timezone(timedelta(hours=5, minutes=30))
WIN_SHORT = timedelta(minutes=10)
WIN_LONG = timedelta(hours=1)

FEATURES = [
    "hour_local",          # 0-23, Asia/Kolkata
    "off_hours",           # before 08:00 or from 20:00 local
    "weekend",
    "events_10m",          # actor's events in last 10 min (incl. this one)
    "denied_10m",
    "failed_10m",
    "auth_fail_10m",       # AUTH_REQUIRED
    "early_release_1h",    # RELEASE_TIME_NOT_REACHED / CHAIN_NOT_RELEASED
    "integrity_fail_1h",   # signature / digest / decryption failures
    "role_denied_1h",      # ROLE_NOT_ALLOWED
    "blocked_paper_1h",    # CHAIN_PAPER_BLOCKED
    "release_req_1h",
    "distinct_papers_1h",
    "secs_since_prev",     # capped at 3600
    "is_release_request",
    "is_upload",
    "is_denied",
    "is_failed",
]


class FeatureExtractor:
    def __init__(self):
        self.history = defaultdict(deque)      # actor -> deque[(ts, event)]

    @staticmethod
    def actor_key(e: dict) -> str:
        return f"{e.get('actor_role', 'unknown')}:{e.get('actor_id', 'unknown')}"

    def update(self, e: dict) -> list[float]:
        ts = parse_ts(e["timestamp_utc"])
        h = self.history[self.actor_key(e)]
        prev_ts = h[-1][0] if h else None
        h.append((ts, e))
        while h and ts - h[0][0] > WIN_LONG:
            h.popleft()

        short = [x for t, x in h if ts - t <= WIN_SHORT]
        long = [x for _, x in h]
        code = lambda x: x.get("reason_code")
        local = ts.astimezone(IST)
        f = {
            "hour_local": local.hour,
            "off_hours": int(local.hour < 8 or local.hour >= 20),
            "weekend": int(local.weekday() >= 5),
            "events_10m": len(short),
            "denied_10m": sum(x.get("result") == "DENIED" for x in short),
            "failed_10m": sum(x.get("result") == "FAILED" for x in short),
            "auth_fail_10m": sum(code(x) == "AUTH_REQUIRED" for x in short),
            "early_release_1h": sum(code(x) in EARLY_RELEASE_CODES for x in long),
            "integrity_fail_1h": sum(code(x) in INTEGRITY_CODES for x in long),
            "role_denied_1h": sum(code(x) == "ROLE_NOT_ALLOWED" for x in long),
            "blocked_paper_1h": sum(code(x) in BLOCKED_CODES for x in long),
            "release_req_1h": sum(x.get("event_type") == "RELEASE_REQUEST" for x in long),
            "distinct_papers_1h": len({x.get("paper_id") for x in long if x.get("paper_id")}),
            "secs_since_prev": min(3600.0, (ts - prev_ts).total_seconds()) if prev_ts else 3600.0,
            "is_release_request": int(e.get("event_type") == "RELEASE_REQUEST"),
            "is_upload": int(e.get("event_type") == "UPLOAD"),
            "is_denied": int(e.get("result") == "DENIED"),
            "is_failed": int(e.get("result") == "FAILED"),
        }
        return [float(f[n]) for n in FEATURES]


def extract(events: list[dict]) -> list[list[float]]:
    """Events must already be in chronological order (examcrypto logs are, by seq)."""
    fx = FeatureExtractor()
    return [fx.update(e) for e in events]
