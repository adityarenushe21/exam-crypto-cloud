"""Account restrictions (append-only JSONL: every restrict/lift is kept, with who and why).

A restriction is a HUMAN decision (an admin, usually after reviewing an AI alert).
It can be time-limited (until_utc) or indefinite (until_utc = null) and is lifted early
by an admin. Restricted accounts are refused on every API call.
"""
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

FMT = "%Y-%m-%dT%H:%M:%SZ"


def _fmt(dt):
    return dt.astimezone(timezone.utc).strftime(FMT)


class RestrictionStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _append(self, rec: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")

    def history(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def restrict(self, username: str, by: str, reason: str, now: datetime,
                 hours: float | None = None, alert_id: str | None = None) -> dict:
        rec = {"record": "restrict", "username": username, "by": by, "reason": reason[:500],
               "at_utc": _fmt(now), "until_utc": _fmt(now + timedelta(hours=hours)) if hours else None,
               "alert_id": alert_id}
        self._append(rec)
        return rec

    def lift(self, username: str, by: str, reason: str, now: datetime) -> dict:
        rec = {"record": "lift", "username": username, "by": by, "reason": reason[:500], "at_utc": _fmt(now)}
        self._append(rec)
        return rec

    def active(self, now: datetime) -> dict:
        state = {}
        for r in self.history():
            if r["record"] == "restrict":
                state[r["username"]] = r
            elif r["record"] == "lift":
                state.pop(r["username"], None)
        return {u: r for u, r in state.items()
                if r["until_utc"] is None or datetime.strptime(r["until_utc"], FMT).replace(tzinfo=timezone.utc) > now}

    def is_restricted(self, username: str, now: datetime) -> dict | None:
        return self.active(now).get(username)
