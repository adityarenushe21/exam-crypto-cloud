"""Event input (examcrypto audit events v2) and alert output (alerts v1)."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS_HASH = "0" * 64

EARLY_RELEASE_CODES = {"RELEASE_TIME_NOT_REACHED", "CHAIN_NOT_RELEASED"}
INTEGRITY_CODES = {"SIGNATURE_INVALID", "UNTRUSTED_SIGNER", "CIPHERTEXT_DIGEST_MISMATCH",
                   "DECRYPTION_AUTHENTICATION_FAILED", "CHAIN_RECORD_MISMATCH",
                   "MANIFEST_MALFORMED", "WRONG_RECIPIENT_KEY"}
BLOCKED_CODES = {"CHAIN_PAPER_BLOCKED"}

SEVERITIES = ("LOW", "MEDIUM", "HIGH")
ACTIONS = {"LOW": "ALLOW", "MEDIUM": "REVIEW", "HIGH": "TEMPORARY_RESTRICT"}
ALERT_SCHEMA_VERSION = "1"


def parse_ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class TamperedLogError(Exception):
    """Raised when the audit log fails the hash-chain check. We refuse to score it."""


def _event_hash(event: dict) -> str:
    body = {k: v for k, v in event.items() if k not in ("event_hash", "signature_b64")}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha3_256(canon.encode("utf-8")).hexdigest()


def check_chain(events: list[dict], start_prev: str = GENESIS_HASH, start_seq: int = 1) -> None:
    """Same linkage rule as examcrypto.events.verify_chain (hash + order; signatures are
    checked by examcrypto / the /events/verify route)."""
    prev, seq = start_prev, start_seq
    for e in events:
        if e.get("seq") != seq or e.get("prev_hash") != prev:
            raise TamperedLogError(f"audit chain broken at seq {e.get('seq')} (expected {seq})")
        if _event_hash(e) != e.get("event_hash"):
            raise TamperedLogError(f"event {seq} was modified (hash mismatch)")
        prev, seq = e["event_hash"], seq + 1


def load_events(path: str | Path, verify: bool = True) -> list[dict]:
    events = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))
    if verify and events and "event_hash" in events[0]:
        check_chain(events)
    return events
