"""Blockchain adapters for Harsh's ExamVault + AuditAnchor contracts.

Two implementations with the SAME methods:

* GatewayBlockchain - talks HTTP to Harsh's chain gateway
  (harsh/examvault/blockchain/gateway/server.js), which signs real transactions
  on a Hardhat node with ethers.js. Python never holds an Ethereum key.
* MockBlockchain    - an in-file emulation of the ExamVault rules that matter for
  release (seal, threshold custodian approvals only after releaseTime, freeze,
  revoke, reschedule-later). Used by tests and when no gateway is running.
  Its anchor status is "MOCK_ANCHORED" so it is never mistaken for a real chain.

Methods
    anchor_paper(record)                 -> {"status", "tx_id", "chain_paper_id"}
    get_status(paper_id, paper_version)  -> {"found", "status", "release_at_unix",
                                             "master_hash", "approvals", "threshold", ...}
    anchor_events(first_seq, last_seq, event_hashes, critical=False)
                                         -> {"status", "tx_id", "batch_index"}

record (all public, no secrets)
    paper_id, paper_version, hash_algorithm="SHA3-256",
    ciphertext_digest_bytes32 = "0x" + SHA3-256(ciphertext.bin)  -> ExamVault.masterHash
    manifest_digest_bytes32, release_at_unix, signer_key_id
"""

import json
import threading
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from .encoding import utc_now
from .errors import ExamCryptoError, CHAIN_UNAVAILABLE

PAPER_STATUSES = ("NONE", "SEALED", "FROZEN", "RELEASED", "REVOKED", "COMPROMISED")
BLOCKING_STATUSES = {"FROZEN", "REVOKED", "COMPROMISED"}


# ============================================================================ MOCK
class MockBlockchain:
    MODE = "mock"
    ANCHOR_STATUS = "MOCK_ANCHORED"

    def __init__(self, path: str | Path, threshold: int = 3, custodians: int = 5,
                 fail: bool = False, clock=utc_now):
        self.path = Path(path)
        self.threshold = threshold
        self.custodians = custodians
        self.fail = fail                      # tests: simulate an unavailable chain
        self.clock = clock
        self._lock = threading.Lock()

    # -- persistence
    def _load(self) -> dict:
        if self.path.exists():
            return json.loads(self.path.read_text(encoding="utf-8"))
        return {"papers": {}, "audit": {"last_seq": 0, "batches": []}}

    def _save(self, state: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")

    @staticmethod
    def _key(paper_id, version):
        return f"{paper_id}:v{version}"

    def _check(self):
        if self.fail:
            raise ExamCryptoError(CHAIN_UNAVAILABLE, "mock chain set to fail")

    # -- interface
    def anchor_paper(self, record: dict) -> dict:
        if self.fail:
            return {"status": "FAILED", "tx_id": None, "chain_paper_id": None}
        with self._lock:
            state = self._load()
            key = self._key(record["paper_id"], record["paper_version"])
            if key in state["papers"]:
                return {"status": "FAILED", "tx_id": None, "chain_paper_id": key,
                        "error": "PaperExists"}
            tx = "MOCK-" + uuid.uuid4().hex
            state["papers"][key] = {
                "status": "SEALED", "round": 0, "approvals": [],
                "release_at_unix": int(record["release_at_unix"]),
                "master_hash": record["ciphertext_digest_bytes32"],
                "manifest_digest": record.get("manifest_digest_bytes32"),
                "tx_id": tx, "superseded_by": None,
            }
            self._save(state)
        return {"status": self.ANCHOR_STATUS, "tx_id": tx, "chain_paper_id": key}

    def get_status(self, paper_id: str, paper_version: int) -> dict:
        self._check()
        p = self._load()["papers"].get(self._key(paper_id, paper_version))
        if p is None:
            return {"found": False, "mode": self.MODE}
        return {"found": True, "mode": self.MODE, "chain_paper_id": self._key(paper_id, paper_version),
                "status": p["status"], "release_at_unix": p["release_at_unix"],
                "master_hash": p["master_hash"], "approvals": len(p["approvals"]),
                "threshold": self.threshold, "tx_id": p["tx_id"],
                "superseded_by": p["superseded_by"]}

    def anchor_events(self, first_seq: int, last_seq: int, event_hashes: list[str],
                      critical: bool = False) -> dict:
        self._check()
        with self._lock:
            state = self._load()
            audit = state["audit"]
            if (first_seq != audit["last_seq"] + 1 or last_seq < first_seq
                    or len(event_hashes) != last_seq - first_seq + 1):
                return {"status": "FAILED", "error": "BadRange", "expected_first_seq": audit["last_seq"] + 1}
            audit["batches"].append({"first_seq": first_seq, "last_seq": last_seq,
                                     "event_hashes": event_hashes, "critical": critical})
            audit["last_seq"] = last_seq
            self._save(state)
            return {"status": self.ANCHOR_STATUS, "tx_id": "MOCK-" + uuid.uuid4().hex,
                    "batch_index": len(audit["batches"]) - 1}

    def anchored_seq(self) -> int:
        return self._load()["audit"]["last_seq"]

    # -- emulated custodian actions (what Harsh's scripts do on the real chain)
    def approve_release(self, paper_id: str, paper_version: int, custodian: int) -> dict:
        """Mirrors ExamVault.approveRelease: only after releaseTime, only custodians, one vote each."""
        with self._lock:
            state = self._load()
            p = state["papers"].get(self._key(paper_id, paper_version))
            if p is None:
                raise ValueError("PaperUnknown")
            if p["status"] != "SEALED":
                raise ValueError("BadState")
            if int(self.clock().timestamp()) < p["release_at_unix"]:
                raise ValueError("TooEarly")
            if not 0 <= custodian < self.custodians:
                raise ValueError("NotCustodian")
            if custodian in p["approvals"]:
                raise ValueError("AlreadyVoted")
            p["approvals"].append(custodian)
            if len(p["approvals"]) >= self.threshold:
                p["status"] = "RELEASED"
            self._save(state)
            return {"approvals": len(p["approvals"]), "status": p["status"]}

    def set_status(self, paper_id: str, paper_version: int, status: str,
                   superseded_by: str | None = None) -> None:
        """Emulates an executed custodian proposal (Freeze / Unfreeze / Revoke / MarkCompromised)."""
        if status not in PAPER_STATUSES:
            raise ValueError(status)
        with self._lock:
            state = self._load()
            p = state["papers"][self._key(paper_id, paper_version)]
            p["status"], p["round"], p["approvals"] = status, p["round"] + 1, []
            p["superseded_by"] = superseded_by
            self._save(state)

    def reschedule(self, paper_id: str, paper_version: int, new_release_unix: int) -> None:
        with self._lock:
            state = self._load()
            p = state["papers"][self._key(paper_id, paper_version)]
            if new_release_unix <= p["release_at_unix"]:
                raise ValueError("BadParam: later only")
            p["release_at_unix"], p["round"], p["approvals"] = new_release_unix, p["round"] + 1, []
            self._save(state)


# ========================================================================= GATEWAY
class GatewayBlockchain:
    MODE = "gateway"

    def __init__(self, base_url: str = "http://127.0.0.1:8546", timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _call(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            with e:                                   # close the error response (no ResourceWarning)
                try:
                    return e.code, json.loads(e.read() or b"{}")
                except json.JSONDecodeError:
                    return e.code, {}
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as exc:
            raise ExamCryptoError(CHAIN_UNAVAILABLE, "chain gateway not reachable") from exc

    def anchor_paper(self, record: dict) -> dict:
        try:
            code, body = self._call("POST", "/papers/seal", record)
        except ExamCryptoError:
            return {"status": "FAILED", "tx_id": None, "chain_paper_id": None}
        if code != 200:
            return {"status": "FAILED", "tx_id": None, "chain_paper_id": body.get("chain_paper_id"),
                    "error": body.get("error")}
        return {"status": "ANCHORED", "tx_id": body.get("tx_id"),
                "chain_paper_id": body.get("chain_paper_id")}

    def get_status(self, paper_id: str, paper_version: int) -> dict:
        code, body = self._call("GET", f"/papers/{paper_id}/{int(paper_version)}")
        if code == 404:
            return {"found": False, "mode": self.MODE}
        if code != 200:
            raise ExamCryptoError(CHAIN_UNAVAILABLE, f"gateway returned HTTP {code}")
        return {"mode": self.MODE, **body}

    def anchor_events(self, first_seq: int, last_seq: int, event_hashes: list[str],
                      critical: bool = False) -> dict:
        code, body = self._call("POST", "/audit/anchor", {
            "first_seq": first_seq, "last_seq": last_seq,
            "event_hashes": event_hashes, "critical": critical})
        if code != 200:
            return {"status": "FAILED", **body}
        return {"status": "ANCHORED", **body}

    def anchored_seq(self) -> int:
        code, body = self._call("GET", "/audit/last-seq")
        if code != 200:
            raise ExamCryptoError(CHAIN_UNAVAILABLE, f"gateway returned HTTP {code}")
        return int(body["last_seq"])
