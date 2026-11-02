// ExamVault capstone project | Harsh Kapile | MIT World Peace University, Pune
// Module: blockchain integrity (smart contracts, chain gateway, ChronoSeal)
// SPDX-License-Identifier: MIT
"use strict";
/**
 * Chain gateway core - connects Aditya's Python crypto service (examcrypto) to the
 * ExamVault and AuditAnchor contracts. Pure logic: the contract objects are injected,
 * so this file is tested with real contracts in test/Gateway.test.js (Hardhat) and
 * with fakes in gateway/test/core.test.js (plain node --test).
 *
 * Mapping from examcrypto's record to ExamVault.sealPaper(SealParams):
 *   paperId          = keccak256(utf8("<paper_id>:v<version>"))     (ethers.id style)
 *   masterHash       = SHA3-256(ciphertext.bin) from examcrypto      (stored as bytes32)
 *   manifestRoot     = Merkle root over ONE variant leaf:
 *                        variantLeaf(sha256("CENTRAL"), masterHash) (single centre for now)
 *   shareCommitRoot  = 0x00..00 (Option A wraps the key with ML-KEM, no Shamir shares)
 *   releaseTime      = release_at_unix (the same time that is signed inside the manifest)
 *   custodians / threshold / freezeThreshold / orgId = gateway config (deployments file)
 * The contract does not recompute any hash; it stores what examcrypto computed.
 */
const http = require("http");
const ev = require("../../packages/crypto/src");

const ZERO32 = "0x" + "00".repeat(32);
const STATUS = ["NONE", "SEALED", "FROZEN", "RELEASED", "REVOKED", "COMPROMISED"];
const HEX32 = /^0x[0-9a-f]{64}$/;
const PAPER_ID = /^[A-Za-z0-9_-]{1,64}$/;
const CENTRAL = "CENTRAL";
const MAX_BATCH = 2000;

class HttpError extends Error {
  constructor(code, error, extra = {}) {
    super(error);
    this.code = code;
    this.body = { error, ...extra };
  }
}

const chainPaperId = (paperId, version) => ev.keccakHex(ev.utf8(`${paperId}:v${version}`));
const orgIdFor = (name) => ev.keccakHex(ev.utf8(name));
const centreIdHash = (centreId = CENTRAL) => ev.sha256Hex(ev.utf8(centreId));
const manifestRootFor = (masterHash) =>
  new ev.MerkleTree([ev.variantLeaf(centreIdHash(), masterHash)]).rootHex;

function revertName(err) {
  if (err && err.revert && err.revert.name) return err.revert.name;
  const msg = String((err && (err.shortMessage || err.message)) || "");
  const m = msg.match(/custom error '([A-Za-z]+)\(/) || msg.match(/\b(PaperUnknown|PaperExists|NotController|BadParam|NotAnchorer|BadRange|TooEarly|BadState|NotCustodian|AlreadyVoted)\b/);
  return m ? m[1] : null;
}

function validateSealRecord(r) {
  if (!r || typeof r !== "object") throw new HttpError(400, "body must be a JSON object");
  if (!PAPER_ID.test(String(r.paper_id))) throw new HttpError(400, "bad paper_id");
  if (!Number.isInteger(r.paper_version) || r.paper_version < 1) throw new HttpError(400, "bad paper_version");
  if (r.hash_algorithm !== "SHA3-256") throw new HttpError(400, "hash_algorithm must be SHA3-256");
  if (!HEX32.test(String(r.ciphertext_digest_bytes32))) throw new HttpError(400, "ciphertext_digest_bytes32 must be 0x + 64 lowercase hex");
  if (!Number.isInteger(r.release_at_unix) || r.release_at_unix <= 0) throw new HttpError(400, "bad release_at_unix");
}

function buildSealParams(r, cfg) {
  validateSealRecord(r);
  return {
    orgId: cfg.orgId,
    paperId: chainPaperId(r.paper_id, r.paper_version),
    manifestRoot: manifestRootFor(r.ciphertext_digest_bytes32),
    shareCommitRoot: ZERO32,
    masterHash: r.ciphertext_digest_bytes32,
    releaseTime: BigInt(r.release_at_unix),
    threshold: cfg.threshold,
    freezeThreshold: cfg.freezeThreshold,
    custodians: cfg.custodians,
  };
}

function paperView(p, approvals) {
  return {
    found: true,
    status: STATUS[Number(p.status)] || "UNKNOWN",
    release_at_unix: Number(p.releaseTime),
    sealed_at_unix: Number(p.sealedAt),
    released_at_unix: Number(p.releasedAt),
    master_hash: String(p.masterHash).toLowerCase(),
    manifest_root: String(p.manifestRoot).toLowerCase(),
    round: Number(p.round),
    approvals: Number(approvals),
    threshold: Number(p.threshold),
    freeze_threshold: Number(p.freezeThreshold),
    custodians: Array.from(p.custodians || []),
  };
}

async function txHash(tx) {
  const rc = tx && typeof tx.wait === "function" ? await tx.wait() : null;
  return (rc && rc.hash) || (tx && tx.hash) || null;
}

/** Returns async handle(method, path, body) -> {code, body}. */
function createHandler({ vault, anchor, cfg }) {
  async function route(method, path, body) {
    if (method === "GET" && path === "/health") {
      return { code: 200, body: { status: "OK", service: "chain-gateway", org_id: cfg.orgId,
        threshold: cfg.threshold, custodians: cfg.custodians.length } };
    }

    if (method === "POST" && path === "/papers/seal") {
      const params = buildSealParams(body, cfg);
      try {
        const hash = await txHash(await vault.sealPaper(params));
        return { code: 200, body: { tx_id: hash, chain_paper_id: params.paperId, manifest_root: params.manifestRoot } };
      } catch (err) {
        const name = revertName(err);
        const code = { PaperExists: 409, BadParam: 400, NotController: 403 }[name] || 502;
        throw new HttpError(code, name || "chain call failed", { chain_paper_id: params.paperId });
      }
    }

    let m = path.match(/^\/papers\/([A-Za-z0-9_-]{1,64})\/([0-9]{1,6})$/);
    if (method === "GET" && m) {
      const id = chainPaperId(m[1], Number(m[2]));
      let p;
      try {
        p = await vault.getPaper(id);
      } catch (err) {
        if (revertName(err) === "PaperUnknown") return { code: 404, body: { found: false, chain_paper_id: id } };
        throw new HttpError(502, revertName(err) || "chain call failed");
      }
      const approvals = await vault.releaseApprovals(id, p.round);
      return { code: 200, body: { chain_paper_id: id, ...paperView(p, approvals) } };
    }

    if (method === "GET" && path === "/audit/last-seq") {
      return { code: 200, body: { last_seq: Number(await anchor.lastSeq(cfg.orgId)) } };
    }

    if (method === "POST" && path === "/risk/flag") {
      // Ansh's threat detector: record a HIGH alert on-chain (AuditAnchor.flagRisk).
      // Only pseudonymous hashes + a 0-100 score; never names, IPs or paper content.
      const { subject_hash, score, reason_hash, event_hash } = body || {};
      for (const [k, v] of Object.entries({ subject_hash, reason_hash, event_hash }))
        if (!HEX32.test(String(v))) throw new HttpError(400, `${k} must be 0x + 64 lowercase hex`);
      if (!Number.isInteger(score) || score < 0 || score > 100) throw new HttpError(400, "score must be an integer 0-100");
      try {
        const hash = await txHash(await anchor.flagRisk(cfg.orgId, subject_hash, score, reason_hash, event_hash));
        const idx = Number(await anchor.flagCount(cfg.orgId));
        return { code: 200, body: { tx_id: hash, flag_index: idx } };
      } catch (err) {
        const name = revertName(err);
        throw new HttpError(name === "NotAnchorer" ? 403 : 502, name || "chain call failed");
      }
    }

    if (method === "POST" && path === "/audit/anchor") {
      const { first_seq, last_seq, event_hashes, critical = false } = body || {};
      if (!Number.isInteger(first_seq) || !Number.isInteger(last_seq) || first_seq < 1 || last_seq < first_seq)
        throw new HttpError(400, "bad seq range");
      if (!Array.isArray(event_hashes) || event_hashes.length !== last_seq - first_seq + 1 || event_hashes.length > MAX_BATCH)
        throw new HttpError(400, "event_hashes length must equal last_seq - first_seq + 1 (max " + MAX_BATCH + ")");
      if (!event_hashes.every((h) => HEX32.test(String(h)))) throw new HttpError(400, "event hashes must be 0x + 64 lowercase hex");
      const tree = new ev.MerkleTree(event_hashes.map(ev.auditLeaf));
      try {
        const hash = await txHash(await anchor.anchorBatch(cfg.orgId, tree.rootHex, first_seq, last_seq, Boolean(critical)));
        const index = Number(await anchor.batchCount(cfg.orgId)) - 1;
        return { code: 200, body: { tx_id: hash, batch_index: index, root: tree.rootHex } };
      } catch (err) {
        const name = revertName(err);
        if (name === "BadRange") {
          const expected = Number(await anchor.lastSeq(cfg.orgId)) + 1;
          throw new HttpError(409, "BadRange", { expected_first_seq: expected });
        }
        throw new HttpError(name === "NotAnchorer" ? 403 : 502, name || "chain call failed");
      }
    }

    throw new HttpError(404, "no such route");
  }

  return async function handle(method, path, body) {
    try {
      return await route(method, path, body);
    } catch (err) {
      if (err instanceof HttpError) return { code: err.code, body: err.body };
      return { code: 500, body: { error: "internal gateway error" } };
    }
  };
}

/** Wraps handle() in a localhost-only JSON HTTP server. */
function createServer(handle, { maxBody = 1024 * 1024 } = {}) {
  return http.createServer((req, res) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > maxBody) req.destroy();
      else chunks.push(c);
    });
    req.on("end", async () => {
      let body = null;
      if (chunks.length) {
        try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
        catch { body = undefined; }
      }
      const out = body === undefined
        ? { code: 400, body: { error: "invalid JSON" } }
        : await handle(req.method, new URL(req.url, "http://localhost").pathname, body);
      const data = JSON.stringify(out.body);
      res.writeHead(out.code, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) });
      res.end(data);
    });
  });
}

module.exports = {
  createHandler, createServer, buildSealParams, validateSealRecord, paperView, revertName,
  chainPaperId, orgIdFor, centreIdHash, manifestRootFor, STATUS, ZERO32, CENTRAL,
};
