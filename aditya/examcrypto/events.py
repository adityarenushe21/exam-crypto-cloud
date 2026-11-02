"""Audit/security events (for Ansh's AI module, Nayan's dashboard and Harsh's AuditAnchor).

* Built from a WHITELIST of fields, so plaintext, keys, passphrases, tokens and
  KEM/HKDF/GCM parameters can never end up in an event by accident.
* TAMPER-EVIDENT: every event has seq (1, 2, 3, ...), prev_hash and
      event_hash = SHA3-256(canonical_json(body without event_hash/signature_b64))
  and is signed with a dedicated ML-DSA-65 AUDIT key (separate from the paper
  signing key). Editing, deleting or reordering a line breaks the chain.
* Batches of event_hash values are anchored on-chain by Harsh's AuditAnchor
  contract (contiguous seq ranges), so history cannot be rewritten later.
Format v2 - PROPOSED, awaiting confirmation from Ansh and Nayan.
"""

import json
import threading
import uuid
from pathlib import Path

from .encoding import b64d, b64e, canonical_json, format_utc, utc_now
from .hashing import sha3_256, digests_equal

EVENT_SCHEMA_VERSION = "2"
GENESIS_HASH = "0" * 64
AUDIT_SIGNATURE_CONTEXT = b"exam-crypto-cloud/audit-event/v1"
EVENT_TYPES = {"UPLOAD", "STATUS_CHECK", "MANIFEST_READ", "RELEASE_REQUEST", "AUTH", "ANCHOR"}
RESULTS = {"SUCCESS", "DENIED", "FAILED"}

# reason codes that mean "policy said no" (vs. bad data / system failure)
DENIED_CODES = {"AUTH_REQUIRED", "ROLE_NOT_ALLOWED", "RELEASE_TIME_NOT_REACHED",
                "CHAIN_NOT_RELEASED", "CHAIN_PAPER_BLOCKED"}

CONTENT_FIELDS = (
    "schema_version", "event_id", "event_type", "timestamp_utc", "source_component",
    "request_id", "actor_id", "actor_role", "result", "reason_code",
    "paper_id", "paper_version", "exam_id", "ciphertext_sha3_256_hex", "manifest_sha3_256_hex",
)
CHAIN_FIELDS = ("seq", "prev_hash", "event_hash", "signature_b64")
ALLOWED_FIELDS = CONTENT_FIELDS + CHAIN_FIELDS


def result_for(reason_code: str | None) -> str:
    if reason_code is None:
        return "SUCCESS"
    return "DENIED" if reason_code in DENIED_CODES else "FAILED"


def build_event(event_type: str, *, actor: dict | None, reason_code: str | None = None,
                request_id: str | None = None, **fields) -> dict:
    """Content part of an event. None values are left out (canonical JSON has no nulls)."""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown event_type {event_type}")
    event = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "timestamp_utc": format_utc(utc_now()),
        "source_component": "crypto_api",
        "request_id": request_id,
        "actor_id": str((actor or {}).get("actor_id", "unknown")),
        "actor_role": str((actor or {}).get("role", "unknown")),
        "result": result_for(reason_code),
        "reason_code": reason_code,
    }
    for k, v in fields.items():
        if k in CONTENT_FIELDS:
            event[k] = v
    return {k: event[k] for k in CONTENT_FIELDS if event.get(k) is not None}


def _hash_body(body: dict) -> str:
    return sha3_256(canonical_json(body)).hex()


class JsonlEventSink:
    """Append-only, hash-chained, ML-DSA-signed event log (one JSON object per line).

    signer: an MLDSA65PrivateKey, or None for an UNSIGNED log (unit tests only).
    """

    def __init__(self, path: str | Path, signer=None):
        self.path = Path(path)
        self.signer = signer
        self._lock = threading.Lock()
        self._seq, self._prev = self._load_tail()

    def _load_tail(self):
        if not self.path.exists():
            return 0, GENESIS_HASH
        last = None
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        if last is None:
            return 0, GENESIS_HASH
        e = json.loads(last)
        return int(e["seq"]), e["event_hash"]

    def emit(self, event: dict) -> dict:
        with self._lock:
            body = {k: v for k, v in event.items() if k in CONTENT_FIELDS}
            body["seq"] = self._seq + 1
            body["prev_hash"] = self._prev
            digest_hex = _hash_body(body)
            full = dict(body, event_hash=digest_hex)
            if self.signer is not None:
                sig = self.signer.sign(bytes.fromhex(digest_hex), AUDIT_SIGNATURE_CONTEXT)
                full["signature_b64"] = b64e(sig)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(full, sort_keys=True) + "\n")
            self._seq, self._prev = body["seq"], digest_hex
            return full

    @property
    def last_seq(self) -> int:
        return self._seq

    def read(self, limit: int = 100, since_seq: int = 0) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    e = json.loads(line)
                    if e["seq"] > since_seq:
                        out.append(e)
        return out[-limit:] if limit else out

    def read_range(self, first_seq: int, last_seq: int) -> list[dict]:
        return [e for e in self.read(limit=0) if first_seq <= e["seq"] <= last_seq]


def verify_chain(events: list[dict], public_key=None, expected_prev: str = GENESIS_HASH,
                 first_seq: int = 1) -> dict:
    """Check linkage, hashes and (if public_key given) signatures. Returns {ok, bad_seq?, reason?}."""
    from cryptography.exceptions import InvalidSignature

    prev, seq = expected_prev, first_seq
    for e in events:
        if e.get("seq") != seq:
            return {"ok": False, "bad_seq": e.get("seq"), "reason": "missing or reordered event"}
        if e.get("prev_hash") != prev:
            return {"ok": False, "bad_seq": seq, "reason": "broken chain link"}
        body = {k: v for k, v in e.items() if k not in ("event_hash", "signature_b64")}
        if not digests_equal(_hash_body(body), e.get("event_hash", "")):
            return {"ok": False, "bad_seq": seq, "reason": "hash mismatch (event modified)"}
        if public_key is not None:
            try:
                public_key.verify(b64d(e.get("signature_b64", "")), bytes.fromhex(e["event_hash"]),
                                  AUDIT_SIGNATURE_CONTEXT)
            except (InvalidSignature, Exception):
                return {"ok": False, "bad_seq": seq, "reason": "bad signature"}
        prev, seq = e["event_hash"], seq + 1
    return {"ok": True, "checked": len(events)}
