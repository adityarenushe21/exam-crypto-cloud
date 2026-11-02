"""Record HIGH alerts on-chain via Harsh's AuditAnchor.flagRisk (through the chain gateway).

Only pseudonymous, non-reversible data goes on-chain:
  subject_hash = HMAC-SHA3-256(secret salt, "<role>:<actor_id>")   - the salt never leaves
                 this machine, so nobody can dictionary-guess who was flagged;
  reason_hash  = SHA3-256(canonical JSON of score, reasons, top features, model version);
  event_hash   = examcrypto's event_hash of the triggering event (already anchored by
                 AuditAnchor.anchorBatch, so the flag links to a provable log entry).
"""

import hashlib
import hmac
import json
import os
import secrets
import urllib.error
import urllib.request
from pathlib import Path

ZERO32 = "0x" + "00" * 32


def load_or_create_salt(path: str | Path) -> bytes:
    path = Path(path)
    if path.exists():
        return path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_bytes(32)
    with open(path, "xb") as f:
        f.write(salt)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return salt


def subject_hash(salt: bytes, role: str, actor_id: str) -> str:
    return "0x" + hmac.new(salt, f"{role}:{actor_id}".encode("utf-8"), hashlib.sha3_256).hexdigest()


def reason_hash(alert: dict) -> str:
    body = {"risk_score": alert.get("risk_score"), "reason_codes": alert.get("reason_codes", []),
            "top_features": alert.get("top_features", []), "model_version": alert.get("model_version")}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "0x" + hashlib.sha3_256(canon.encode("utf-8")).hexdigest()


def flag_payload(alert: dict, salt: bytes) -> dict:
    ev = alert.get("event_hash")
    return {
        "subject_hash": subject_hash(salt, alert.get("actor_role", "unknown"), alert.get("actor_id", "unknown")),
        "score": int(max(0, min(100, alert["risk_score"]))),
        "reason_hash": reason_hash(alert),
        "event_hash": ("0x" + ev) if ev and len(ev) == 64 else ZERO32,
    }


class GatewayFlagger:
    def __init__(self, salt: bytes, base_url: str = "http://127.0.0.1:8546", timeout: float = 30.0):
        self.salt = salt
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def flag(self, alert: dict) -> dict:
        payload = flag_payload(alert, self.salt)
        req = urllib.request.Request(self.base_url + "/risk/flag", data=json.dumps(payload).encode(),
                                     method="POST", headers={"Content-Type": "application/json"})
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                body = json.loads(r.read() or b"{}")
                return {"status": "FLAGGED", "tx_id": body.get("tx_id"),
                        "flag_index": body.get("flag_index"), "subject_hash": payload["subject_hash"]}
        except urllib.error.HTTPError as e:
            with e:
                return {"status": "FAILED", "http": e.code}
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            return {"status": "FAILED", "error": "gateway not reachable"}
