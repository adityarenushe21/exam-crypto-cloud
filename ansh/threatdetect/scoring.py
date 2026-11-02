"""Combine rules + Isolation Forest + Random Forest into one risk score and alert.

risk (0-100) = max(rule_score, 100 * rf_attack_probability, 65 * iforest_anomaly)
  * max(), so any one detector can raise the alarm (rules catch known patterns,
    RF learned patterns, Isolation Forest unusual behaviour nobody labelled).
  * Isolation Forest alone can reach at most 65 = MEDIUM -> REVIEW, never an automatic
    restriction: it is unsupervised and the noisiest signal, so a human looks first.
  * Its anomaly scale starts at the 97th percentile of NORMAL training behaviour.
severity: HIGH >= 70, MEDIUM >= 40, else LOW (prototype thresholds, documented).
action:   HIGH -> TEMPORARY_RESTRICT (human review required), MEDIUM -> REVIEW, LOW -> ALLOW.
"""

import uuid
from datetime import datetime, timedelta, timezone

from . import MODEL_NAME, __version__
from . import rules
from .features import FeatureExtractor
from .schema import ACTIONS, ALERT_SCHEMA_VERSION, fmt_ts, parse_ts

HIGH, MEDIUM = 70, 40
IF_WEIGHT = 65
SUPPRESS_WINDOW = timedelta(minutes=10)


def severity(score: int) -> str:
    return "HIGH" if score >= HIGH else "MEDIUM" if score >= MEDIUM else "LOW"


class Scorer:
    """Streaming scorer: feed events in order, get an alert dict for MEDIUM/HIGH ones.
    Repeated alerts for the same actor+severity within 10 minutes are folded into the
    first alert's suppressed_count (alert fatigue control)."""

    def __init__(self, model=None, store=None):
        self.model = model
        self.store = store           # optional AlertStore: suppression updates are persisted
        self.fx = FeatureExtractor()
        self._recent = {}            # (actor, severity) -> (alert, ts)

    def score_event(self, e: dict) -> dict:
        x = self.fx.update(e)
        rule_score, reasons = rules.evaluate(x)
        rf_p = float(self.model.attack_proba([x])[0]) if self.model else 0.0
        an = float(self.model.anomaly([x])[0]) if self.model else 0.0
        risk = int(round(max(rule_score, 100 * rf_p, IF_WEIGHT * an)))
        if an >= 0.75 and "UNUSUAL_BEHAVIOUR" not in reasons:
            reasons = reasons + ["UNUSUAL_BEHAVIOUR"]
        if not reasons and risk >= MEDIUM:          # every alert must say which detector raised it
            reasons = ["LEARNED_ATTACK_PATTERN" if 100 * rf_p >= IF_WEIGHT * an else "UNUSUAL_BEHAVIOUR"]
        return {"x": x, "risk_score": risk, "severity": severity(risk), "reason_codes": reasons,
                "components": {"rules": rule_score, "random_forest": round(rf_p, 4),
                               "isolation_forest": round(an, 4)}}

    def process(self, e: dict) -> dict | None:
        s = self.score_event(e)
        if s["severity"] == "LOW":
            return None
        ts = parse_ts(e["timestamp_utc"])
        key = (FeatureExtractor.actor_key(e), s["severity"])
        prev = self._recent.get(key)
        if prev and ts - prev[1] <= SUPPRESS_WINDOW:
            prev[0]["suppressed_count"] += 1
            prev[0]["last_event_seq"] = e.get("seq")
            self._recent[key] = (prev[0], ts)
            if self.store is not None:
                self.store.update(prev[0]["alert_id"], suppressed_count=prev[0]["suppressed_count"],
                                  last_event_seq=e.get("seq"))
            return None
        alert = {
            "schema_version": ALERT_SCHEMA_VERSION,
            "alert_id": str(uuid.uuid4()),
            "created_at_utc": fmt_ts(datetime.now(timezone.utc)),
            "event_time_utc": e["timestamp_utc"],
            "event_id": e.get("event_id"),
            "event_seq": e.get("seq"),
            "event_hash": e.get("event_hash"),
            "last_event_seq": e.get("seq"),
            "event_type": e.get("event_type"),
            "paper_id": e.get("paper_id"),
            "actor_id": e.get("actor_id"),
            "actor_role": e.get("actor_role"),
            "risk_score": s["risk_score"],
            "severity": s["severity"],
            "reason_codes": s["reason_codes"],
            "top_features": self.model.top_features(s["x"]) if self.model else [],
            "components": s["components"],
            "recommended_action": ACTIONS[s["severity"]],
            "status": "NEW",
            "suppressed_count": 0,
            "model_name": MODEL_NAME,
            "model_version": __version__,
        }
        self._recent[key] = (alert, ts)
        return alert

    def process_all(self, events):
        return [a for a in (self.process(e) for e in events) if a]
