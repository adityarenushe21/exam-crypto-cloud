"""Alert store shared by the threat detector (writer) and the dashboard (review).

Append-only JSONL. Line types:
  {"record": "alert",  ...full alert...}
  {"record": "update", "alert_id": ..., "fields": {...}, "at_utc": ..., "by": ...}
load() replays the file and merges updates, so nothing is ever overwritten in place
and every status change keeps its own timestamped line (a simple audit trail).
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

REVIEW_STATUSES = ("NEW", "ACKNOWLEDGED", "REVIEWING", "CLOSED")
UPDATABLE = {"status", "suppressed_count", "last_event_seq", "review_note", "reviewed_by",
             "chain_flag", "access_action"}


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AlertStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _append(self, rec: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")

    def add(self, alert: dict) -> None:
        self._append({"record": "alert", **alert})

    def update(self, alert_id: str, by: str = "system", **fields) -> None:
        bad = set(fields) - UPDATABLE
        if bad:
            raise ValueError(f"fields not updatable: {sorted(bad)}")
        if "status" in fields and fields["status"] not in REVIEW_STATUSES:
            raise ValueError(f"bad status {fields['status']!r}")
        self._append({"record": "update", "alert_id": alert_id, "fields": fields,
                      "at_utc": _now(), "by": by})

    def load(self) -> dict:
        """{alert_id: merged alert}, in creation order."""
        alerts = {}
        if not self.path.exists():
            return alerts
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                r = json.loads(line)
                if r.get("record") == "alert":
                    a = {k: v for k, v in r.items() if k != "record"}
                    a.setdefault("history", [])
                    alerts[a["alert_id"]] = a
                elif r.get("record") == "update" and r.get("alert_id") in alerts:
                    a = alerts[r["alert_id"]]
                    a.update(r["fields"])
                    a["history"].append({"at_utc": r["at_utc"], "by": r["by"], **r["fields"]})
        return alerts

    def list(self, severity=None, status=None, limit: int = 200) -> list[dict]:
        items = list(self.load().values())
        if severity:
            items = [a for a in items if a.get("severity") == severity]
        if status:
            items = [a for a in items if a.get("status") == status]
        return items[-limit:]
