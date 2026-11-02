// ExamVault capstone project | Harsh Kapile | MIT World Peace University, Pune
// Module: blockchain integrity (smart contracts, chain gateway, ChronoSeal)
// SPDX-License-Identifier: MIT
"use strict";
const { utf8, toHex, fromHex } = require("./bytes");
const { sha256 } = require("./hash");
const { sign, verify } = require("./ciphers");
const { MerkleTree, auditLeaf } = require("./merkle");

/** Deterministic JSON (sorted keys) so every party hashes identical bytes. */
function canonicalJson(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") + "}";
}

const GENESIS = "0x" + "00".repeat(32);

/**
 * Tamper-evident audit log:
 *   hash_n = SHA-256(canonical(entry_n without hash/sig, including prevHash = hash_{n-1}))
 *   sig_n  = ECDSA-P256(signerKey, hash_n)
 * Editing, deleting or reordering any entry breaks the chain; forging needs the signing key. Batches of
 * entries are rolled into a Merkle root that is anchored on-chain (AuditAnchor), so even the log operator
 * cannot rewrite history after anchoring.
 */
class AuditChain {
  constructor({ orgId, signingPrivateKey, startSeq = 1, prevHash = GENESIS }) {
    this.orgId = orgId;
    this.key = signingPrivateKey;
    this.nextSeq = startSeq;
    this.prevHash = prevHash;
  }

  async append(type, actor, data = {}, ts = Date.now()) {
    const body = { seq: this.nextSeq, orgId: this.orgId, type, actor, data, ts, prevHash: this.prevHash };
    const hash = sha256(utf8(canonicalJson(body)));
    const sig = await sign(this.key, hash);
    const entry = { ...body, hash: "0x" + toHex(hash), sig: toHex(sig) };
    this.nextSeq += 1;
    this.prevHash = entry.hash;
    return entry;
  }

  /** Verify linkage, hashes and signatures of a contiguous run of entries. Returns {ok, badSeq?, reason?}. */
  static async verify(entries, publicKey, expectedPrevHash = GENESIS) {
    let prev = expectedPrevHash;
    for (const e of entries) {
      const { hash, sig, ...body } = e;
      if (body.prevHash !== prev) return { ok: false, badSeq: e.seq, reason: "broken chain link" };
      const h = sha256(utf8(canonicalJson(body)));
      if ("0x" + toHex(h) !== hash) return { ok: false, badSeq: e.seq, reason: "hash mismatch (entry modified)" };
      if (!(await verify(publicKey, fromHex(sig), h))) return { ok: false, badSeq: e.seq, reason: "bad signature" };
      prev = hash;
    }
    return { ok: true };
  }

  /** Build the Merkle batch for entries to be anchored on-chain. */
  static batch(entries) {
    const tree = new MerkleTree(entries.map((e) => auditLeaf(e.hash)));
    return {
      firstSeq: entries[0].seq,
      lastSeq: entries[entries.length - 1].seq,
      root: tree.rootHex,
      proofFor: (i) => tree.proof(i),
      tree,
    };
  }
}

module.exports = { AuditChain, canonicalJson, GENESIS };
