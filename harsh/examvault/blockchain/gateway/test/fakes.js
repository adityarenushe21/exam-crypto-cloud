"use strict";
// In-memory stand-ins for ExamVault / AuditAnchor (subset), shaped like ethers v6 contract
// objects: async methods, bigint fields, reverts carry err.revert.name. Used ONLY by
// gateway/test/core.test.js - the real contracts are tested in test/Gateway.test.js.
const ev = require("../../../packages/crypto/src");

const revert = (name) => Object.assign(new Error(`reverted with custom error '${name}()'`), { revert: { name } });
const tx = () => { const hash = "0x" + Buffer.from(ev.randomBytes(32)).toString("hex"); return { hash, wait: async () => ({ hash }) }; };

class FakeVault {
  constructor(now = () => Math.floor(Date.now() / 1000)) { this.now = now; this.papers = new Map(); this.approvals = new Map(); }
  async sealPaper(s) {
    if (this.papers.has(s.paperId)) throw revert("PaperExists");
    if (BigInt(s.releaseTime) <= BigInt(this.now()) || s.manifestRoot === "0x" + "00".repeat(32) ||
        s.threshold < 2 || s.threshold > s.custodians.length) throw revert("BadParam");
    this.papers.set(s.paperId, { orgId: s.orgId, manifestRoot: s.manifestRoot, shareCommitRoot: s.shareCommitRoot,
      masterHash: s.masterHash, sealedAt: BigInt(this.now()), releaseTime: BigInt(s.releaseTime), releasedAt: 0n,
      round: 0n, threshold: BigInt(s.threshold), freezeThreshold: BigInt(s.freezeThreshold), status: 1n,
      custodians: [...s.custodians], voted: new Set() });
    return tx();
  }
  async getPaper(id) { const p = this.papers.get(id); if (!p) throw revert("PaperUnknown"); return p; }
  async releaseApprovals(id, round) { return BigInt(this.approvals.get(`${id}:${round}`) || 0); }
  approve(id, custodian) {                       // mirrors approveRelease(msg.sender = custodian)
    const p = this.papers.get(id);
    if (!p) throw revert("PaperUnknown");
    if (p.status !== 1n) throw revert("BadState");
    if (BigInt(this.now()) < p.releaseTime) throw revert("TooEarly");
    if (!p.custodians.includes(custodian)) throw revert("NotCustodian");
    const k = `${id}:${p.round}`;
    if (p.voted.has(k + custodian)) throw revert("AlreadyVoted");
    p.voted.add(k + custodian);
    const n = (this.approvals.get(k) || 0) + 1; this.approvals.set(k, n);
    if (n >= Number(p.threshold)) { p.status = 3n; p.releasedAt = BigInt(this.now()); }
  }
  setStatus(id, status) { const p = this.papers.get(id); p.status = BigInt(status); p.round += 1n; }
}

class FakeAnchor {
  constructor() { this.batches = []; this.last = 0n; this.flags = []; }
  async flagRisk(orgId, subjectHash, score, reasonHash, eventHash) {
    if (score > 255) throw revert("BadParam");
    this.flags.push({ subjectHash, score, reasonHash, eventHash }); return tx();
  }
  async flagCount() { return BigInt(this.flags.length); }
  async anchorBatch(orgId, root, firstSeq, lastSeq, critical) {
    if (BigInt(firstSeq) !== this.last + 1n || BigInt(lastSeq) < BigInt(firstSeq) || root === "0x" + "00".repeat(32)) throw revert("BadRange");
    this.batches.push({ root, firstSeq, lastSeq, critical }); this.last = BigInt(lastSeq); return tx();
  }
  async batchCount() { return BigInt(this.batches.length); }
  async lastSeq() { return this.last; }
  async verifyInclusion(orgId, index, eventHash, proof) {
    return ev.verifyProof(proof, this.batches[index].root, ev.auditLeaf(eventHash));
  }
}

module.exports = { FakeVault, FakeAnchor, revert };
