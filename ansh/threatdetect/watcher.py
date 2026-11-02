"""Live mode: follow examcrypto's events.jsonl and write alerts to an AlertStore.

* Verifies the audit hash chain before scoring; if it is broken, writes ONE HIGH
  "AUDIT_LOG_TAMPERED" system alert and stops scoring (never trust a tampered log).
* Restart-safe: a state file remembers the last processed seq; on start, earlier events
  are replayed silently to rebuild the 10-minute / 1-hour windows.
* Optional on-chain flagging of HIGH alerts (Harsh's AuditAnchor.flagRisk via the gateway).
"""

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import MODEL_NAME, __version__
from .alerts import AlertStore
from .schema import ALERT_SCHEMA_VERSION, TamperedLogError, check_chain, fmt_ts, load_events
from .scoring import Scorer


class Watcher:
    def __init__(self, events_path, alerts_path, model=None, state_path=None, flagger=None):
        self.events_path = Path(events_path)
        self.store = AlertStore(alerts_path)
        self.state_path = Path(state_path or Path(alerts_path).with_suffix(".state.json"))
        self.scorer = Scorer(model, store=self.store)
        self.flagger = flagger
        st = json.loads(self.state_path.read_text()) if self.state_path.exists() else {}
        self.last_seq = int(st.get("last_seq", 0))
        self.tampered = bool(st.get("tampered", False))
        self._replayed = False

    def _save_state(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps({"last_seq": self.last_seq, "tampered": self.tampered}))

    def _emit(self, alert):
        self.store.add(alert)
        if self.flagger is not None and alert["severity"] == "HIGH":
            self.store.update(alert["alert_id"], chain_flag=self.flagger.flag(alert))

    def poll(self) -> list[dict]:
        if self.tampered or not self.events_path.exists():
            return []
        events = load_events(self.events_path, verify=False)
        try:
            check_chain(events)
        except TamperedLogError as exc:
            self.tampered = True
            alert = {"schema_version": ALERT_SCHEMA_VERSION, "alert_id": str(uuid.uuid4()),
                     "created_at_utc": fmt_ts(datetime.now(timezone.utc)), "severity": "HIGH",
                     "risk_score": 100, "reason_codes": ["AUDIT_LOG_TAMPERED"], "detail": str(exc),
                     "recommended_action": "TEMPORARY_RESTRICT", "status": "NEW", "actor_id": "system",
                     "actor_role": "system", "suppressed_count": 0, "model_name": MODEL_NAME,
                     "model_version": __version__}
            self._emit(alert)
            self._save_state()
            return [alert]
        if not self._replayed:                       # rebuild windows silently
            for e in events:
                if e["seq"] <= self.last_seq:
                    self.scorer.score_event(e)
            self._replayed = True
        new = [e for e in events if e["seq"] > self.last_seq]
        alerts = self.scorer.process_all(new)
        for a in alerts:
            self._emit(a)
        if new:
            self.last_seq = new[-1]["seq"]
        self._save_state()
        return alerts

    def run_forever(self, interval: float = 2.0, on_alert=print):
        while True:
            for a in self.poll():
                on_alert(a)
            time.sleep(interval)
