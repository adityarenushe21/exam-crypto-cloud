"""PaperService = pipeline + signed audit events + blockchain adapter.

The API (and CLI server) talk only to this class. Every call emits exactly one
audit event, success or failure, and failures are re-raised unchanged.
"""

from . import authz, pipeline
from . import manifest as mf
from .encoding import parse_utc, utc_now
from .errors import (ExamCryptoError, CIPHERTEXT_DIGEST_MISMATCH, SIGNATURE_INVALID,
                     UNTRUSTED_SIGNER)
from .events import build_event, verify_chain
from .hashing import sha3_256_hex
from .storage import object_keys


class PaperService:
    def __init__(self, *, storage, keystore, passphrase: bytes, events, blockchain,
                 clock=utc_now, require_chain_release: bool = True):
        self.storage = storage
        self.keystore = keystore
        self._passphrase = passphrase           # held in memory only, never logged
        self.events = events
        self.blockchain = blockchain
        self.clock = clock
        self.require_chain_release = require_chain_release

    # ------------------------------------------------------------------ helpers
    def _emit(self, event_type, actor, request_id, reason_code=None, **fields):
        self.events.emit(build_event(event_type, actor=actor, reason_code=reason_code,
                                     request_id=request_id, **fields))

    def _run(self, event_type, actor, request_id, fn, **fields):
        try:
            return fn()
        except ExamCryptoError as exc:
            self._emit(event_type, actor, request_id, exc.reason_code, **fields)
            raise

    def _verified(self, paper_id, version, actor):
        return pipeline.verify_paper(storage=self.storage, paper_id=paper_id, version=version,
                                     trusted_signer_public=self.keystore.signer_public(), actor=actor)

    @staticmethod
    def _anchor_record(manifest: dict) -> dict:
        return {
            "paper_id": manifest["paper_id"],
            "paper_version": manifest["paper_version"],
            "hash_algorithm": "SHA3-256",
            "ciphertext_digest_bytes32": "0x" + manifest["ciphertext_sha3_256_hex"],
            "manifest_digest_bytes32": "0x" + sha3_256_hex(mf.signed_bytes(manifest)),
            "release_at_unix": int(parse_utc(manifest["release_at_utc"]).timestamp()),
            "signer_key_id": manifest["signer_key_id"],
        }

    # --------------------------------------------------------------------- seal
    def seal(self, *, plaintext, exam_id, release_at_utc, actor, request_id=None, paper_id=None):
        result = self._run("UPLOAD", actor, request_id, lambda: pipeline.seal_paper(
            storage=self.storage, recipient_public=self.keystore.recipient_public(),
            signer_private=self.keystore.signer_private(self._passphrase),
            plaintext=plaintext, exam_id=exam_id, release_at_utc=release_at_utc,
            actor=actor, paper_id=paper_id, now=self.clock()), paper_id=paper_id)

        manifest, _ = self._verified(result["paper_id"], result["paper_version"],
                                     {"role": "exam_authority"})
        anchor = self.blockchain.anchor_paper(self._anchor_record(manifest))
        result["blockchain_status"] = anchor["status"]
        result["blockchain_tx_id"] = anchor.get("tx_id")
        result["chain_paper_id"] = anchor.get("chain_paper_id")
        self._emit("UPLOAD", actor, request_id, paper_id=result["paper_id"],
                   paper_version=result["paper_version"], exam_id=exam_id,
                   ciphertext_sha3_256_hex=result["ciphertext_sha3_256_hex"],
                   manifest_sha3_256_hex=result["manifest_sha3_256_hex"])
        return result

    def retry_anchor(self, *, paper_id, actor, version=None, request_id=None):
        """Re-send the on-chain registration if the chain was down during upload."""
        def work():
            authz.require(actor, "seal")
            manifest, _ = self._verified(paper_id, version, actor)
            return manifest, self.blockchain.anchor_paper(self._anchor_record(manifest))

        manifest, anchor = self._run("ANCHOR", actor, request_id, work, paper_id=paper_id)
        reason = None if anchor["status"] in ("ANCHORED", "MOCK_ANCHORED") else "CHAIN_UNAVAILABLE"
        self._emit("ANCHOR", actor, request_id, reason, paper_id=paper_id,
                   paper_version=manifest["paper_version"])
        return {"paper_id": paper_id, "paper_version": manifest["paper_version"], **anchor}

    # ------------------------------------------------------------------- status
    def _chain_view(self, paper_id, version):
        try:
            return self.blockchain.get_status(paper_id, version)
        except ExamCryptoError as exc:
            return {"found": False, "status": "UNAVAILABLE", "reason_code": exc.reason_code}

    def status(self, *, paper_id, actor, version=None, request_id=None, _emit_event=True):
        def work():
            authz.require(actor, "verify")
            versions = self.storage.versions(paper_id) if pipeline._ID_RE.match(paper_id) else []
            out = {"paper_id": paper_id, "versions": versions, "signature_status": "valid",
                   "integrity_status": "valid", "reason_code": None}
            try:
                manifest, _ = self._verified(paper_id, version, actor)
            except ExamCryptoError as exc:
                if exc.reason_code in (SIGNATURE_INVALID, UNTRUSTED_SIGNER):
                    out.update(signature_status="invalid", integrity_status="not_checked",
                               release_status="BLOCKED", reason_code=exc.reason_code)
                    return out
                if exc.reason_code == CIPHERTEXT_DIGEST_MISMATCH:
                    out.update(integrity_status="mismatch", release_status="BLOCKED",
                               reason_code=exc.reason_code)
                    return out
                raise
            chain = self._chain_view(paper_id, manifest["paper_version"])
            time_ok = self.clock() >= parse_utc(manifest["release_at_utc"])
            try:
                if self.require_chain_release:
                    pipeline.check_chain_authorization(manifest, chain)
                chain_ok, chain_reason = True, None
            except ExamCryptoError as exc:
                chain_ok, chain_reason = False, exc.reason_code
            if chain_reason in ("CHAIN_PAPER_BLOCKED", "CHAIN_RECORD_MISMATCH"):
                release_status = "BLOCKED"
            elif time_ok and chain_ok:
                release_status = "RELEASABLE"
            elif time_ok:
                release_status = "AWAITING_CUSTODIANS"
            else:
                release_status = "NOT_YET_RELEASABLE"
            out.update(
                paper_version=manifest["paper_version"], exam_id=manifest["exam_id"],
                release_at_utc=manifest["release_at_utc"],
                created_at_utc=manifest["created_at_utc"], release_status=release_status,
                ciphertext_sha3_256_hex=manifest["ciphertext_sha3_256_hex"],
                signer_key_id=manifest["signer_key_id"], blockchain=chain,
                chain_reason_code=chain_reason,
            )
            return out

        if not _emit_event:
            return work()
        out = self._run("STATUS_CHECK", actor, request_id, work, paper_id=paper_id)
        self._emit("STATUS_CHECK", actor, request_id, out["reason_code"], paper_id=paper_id,
                   paper_version=out.get("paper_version"))
        return out

    def list_papers(self, *, actor, request_id=None, limit: int = 200):
        """Latest-version status of every stored paper (dashboard). One STATUS_CHECK event."""
        def work():
            authz.require(actor, "verify")
            out = []
            for pid in self.storage.list_papers()[-limit:]:
                try:
                    st = self.status(paper_id=pid, actor=actor, request_id=request_id, _emit_event=False)
                except ExamCryptoError as exc:
                    st = {"paper_id": pid, "release_status": "ERROR", "reason_code": exc.reason_code}
                out.append(st)
            return out

        out = self._run("STATUS_CHECK", actor, request_id, work)
        self._emit("STATUS_CHECK", actor, request_id, action="LIST_PAPERS")
        return out

    # ----------------------------------------------------------------- manifest
    def signed_manifest(self, *, paper_id, actor, version=None, request_id=None):
        def work():
            manifest, _ = self._verified(paper_id, version, actor)
            _, mf_key = object_keys(paper_id, manifest["paper_version"])
            envelope, signature_b64 = mf.from_envelope_bytes(self.storage.get(mf_key))
            return {"manifest": envelope, "signature_b64": signature_b64,
                    "manifest_sha3_256_hex": sha3_256_hex(mf.signed_bytes(envelope))}

        out = self._run("MANIFEST_READ", actor, request_id, work, paper_id=paper_id)
        self._emit("MANIFEST_READ", actor, request_id, paper_id=paper_id,
                   paper_version=out["manifest"]["paper_version"])
        return out

    # ------------------------------------------------------------------ release
    def release(self, *, paper_id, actor, version=None, request_id=None):
        def chain_authorize(manifest):
            status = self.blockchain.get_status(manifest["paper_id"], manifest["paper_version"])
            pipeline.check_chain_authorization(manifest, status)

        manifest, plaintext = self._run("RELEASE_REQUEST", actor, request_id, lambda:
            pipeline.release_paper(
                storage=self.storage, paper_id=paper_id, version=version,
                trusted_signer_public=self.keystore.signer_public(),
                load_recipient_private=lambda: self.keystore.recipient_private(self._passphrase),
                actor=actor, now=self.clock(),
                chain_authorize=chain_authorize if self.require_chain_release else None),
            paper_id=paper_id, paper_version=version)
        self._emit("RELEASE_REQUEST", actor, request_id, paper_id=paper_id,
                   paper_version=manifest["paper_version"], exam_id=manifest["exam_id"],
                   ciphertext_sha3_256_hex=manifest["ciphertext_sha3_256_hex"])
        return manifest, plaintext

    # ------------------------------------------------------------------- events
    def recent_events(self, *, actor, limit=100, request_id=None):
        self._run("AUTH", actor, request_id, lambda: authz.require(actor, "read_events"))
        return self.events.read(limit=max(1, min(limit, 1000)))

    def verify_events(self, *, actor, audit_public=None, request_id=None):
        self._run("AUTH", actor, request_id, lambda: authz.require(actor, "read_events"))
        return verify_chain(self.events.read(limit=0), audit_public)

    def anchor_events(self, *, actor, request_id=None, max_batch: int = 500):
        """Anchor every event not yet on-chain, as contiguous batches (AuditAnchor rule)."""
        def work():
            authz.require(actor, "anchor_events")
            start = self.blockchain.anchored_seq() + 1
            pending = [e for e in self.events.read(limit=0) if e["seq"] >= start]
            batches = []
            for i in range(0, len(pending), max_batch):
                chunk = pending[i:i + max_batch]
                res = self.blockchain.anchor_events(
                    chunk[0]["seq"], chunk[-1]["seq"], ["0x" + e["event_hash"] for e in chunk],
                    critical=any(e["event_type"] == "RELEASE_REQUEST" for e in chunk))
                batches.append({"first_seq": chunk[0]["seq"], "last_seq": chunk[-1]["seq"], **res})
                if res["status"] == "FAILED":
                    break
            return {"anchored_batches": batches, "pending_before": len(pending)}

        out = self._run("ANCHOR", actor, request_id, work)
        self._emit("ANCHOR", actor, request_id)
        return out
