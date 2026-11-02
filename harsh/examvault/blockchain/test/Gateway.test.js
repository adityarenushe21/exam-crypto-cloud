// ExamVault capstone project | Harsh Kapile | MIT World Peace University, Pune
// Module: blockchain integrity (smart contracts, chain gateway, ChronoSeal)
// SPDX-License-Identifier: MIT
// Integration: chain gateway core + the REAL ExamVault / AuditAnchor contracts (Hardhat network).
// Runs together with the existing tests:  npx hardhat test
const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");
const ev = require("../../packages/crypto/src");
const core = require("../gateway/core");

const Role = { Controller: 1, Analyst: 2, Anchorer: 3 };

async function setup() {
  const s = await ethers.getSigners();
  const [owner, orgAdmin, controller, analyst, anchorer] = s;
  const custodians = s.slice(5, 10);
  const registry = await (await ethers.getContractFactory("OrgRegistry")).deploy(owner.address);
  const vault = await (await ethers.getContractFactory("ExamVault")).deploy(await registry.getAddress(), 86400);
  const anchor = await (await ethers.getContractFactory("AuditAnchor")).deploy(await registry.getAddress());
  const orgId = ethers.id("ORG-GATEWAY-TEST");
  await registry.registerOrg(orgId, orgAdmin.address);
  await registry.connect(orgAdmin).grantRole(orgId, Role.Controller, controller.address);
  await registry.connect(orgAdmin).grantRole(orgId, Role.Analyst, analyst.address);
  await registry.connect(orgAdmin).grantRole(orgId, Role.Anchorer, anchorer.address);
  const cfg = { orgId, custodians: custodians.map((c) => c.address), threshold: 3, freezeThreshold: 2 };
  const handle = core.createHandler({ vault: vault.connect(controller), anchor: anchor.connect(anchorer), cfg });
  const digest = ev.sha256Hex(ev.utf8("stand-in for SHA3-256(ciphertext.bin)")); // any 32-byte value
  const record = async (over = {}) => ({
    paper_id: "pap_gwtest", paper_version: 1, hash_algorithm: "SHA3-256",
    ciphertext_digest_bytes32: digest, manifest_digest_bytes32: digest,
    release_at_unix: (await time.latest()) + 3600, signer_key_id: "00".repeat(16), ...over,
  });
  return { vault, anchor, registry, handle, cfg, custodians, orgId, digest, record };
}

describe("Chain gateway <-> real contracts", () => {
  it("orgIdFor() equals ethers.id()", async () => {
    expect(core.orgIdFor("ORG-GATEWAY-TEST")).to.equal(ethers.id("ORG-GATEWAY-TEST"));
    expect(core.chainPaperId("pap_x", 1)).to.equal(ethers.id("pap_x:v1"));
  });

  it("seal stores examcrypto's digest as masterHash; manifestRoot verifies on-chain", async () => {
    const f = await setup();
    const rec = await f.record();
    const out = await f.handle("POST", "/papers/seal", rec);
    expect(out.code).to.equal(200);
    const p = await f.vault.getPaper(out.body.chain_paper_id);
    expect(p.masterHash).to.equal(f.digest);
    expect(p.releaseTime).to.equal(BigInt(rec.release_at_unix));
    expect(await f.vault.verifyVariant(out.body.chain_paper_id, core.centreIdHash(), f.digest, [])).to.equal(true);
    expect(await f.vault.verifyVariant(out.body.chain_paper_id, core.centreIdHash(), ethers.ZeroHash, [])).to.equal(false);
    const st = await f.handle("GET", "/papers/pap_gwtest/1");
    expect(st.body.status).to.equal("SEALED");
    expect(st.body.master_hash).to.equal(f.digest);
  });

  it("duplicate -> 409, unknown -> 404, past time -> 400", async () => {
    const f = await setup();
    const rec = await f.record();
    await f.handle("POST", "/papers/seal", rec);
    expect((await f.handle("POST", "/papers/seal", rec)).code).to.equal(409);
    expect((await f.handle("GET", "/papers/pap_nothing/1")).code).to.equal(404);
    const past = await f.record({ paper_version: 2, release_at_unix: (await time.latest()) - 5 });
    expect((await f.handle("POST", "/papers/seal", past)).code).to.equal(400);
  });

  it("status goes SEALED -> RELEASED only after releaseTime and 3 custodian approvals", async () => {
    const f = await setup();
    const rec = await f.record();
    const { body } = await f.handle("POST", "/papers/seal", rec);
    await expect(f.vault.connect(f.custodians[0]).approveRelease(body.chain_paper_id))
      .to.be.revertedWithCustomError(f.vault, "TooEarly");
    await time.increaseTo(rec.release_at_unix);
    await f.vault.connect(f.custodians[0]).approveRelease(body.chain_paper_id);
    await f.vault.connect(f.custodians[1]).approveRelease(body.chain_paper_id);
    let st = (await f.handle("GET", "/papers/pap_gwtest/1")).body;
    expect([st.status, st.approvals]).to.deep.equal(["SEALED", 2]);
    await f.vault.connect(f.custodians[2]).approveRelease(body.chain_paper_id);
    st = (await f.handle("GET", "/papers/pap_gwtest/1")).body;
    expect([st.status, st.approvals]).to.deep.equal(["RELEASED", 3]);
  });

  it("freeze by 2 custodians is reported as FROZEN", async () => {
    const f = await setup();
    const { body } = await f.handle("POST", "/papers/seal", await f.record());
    await f.vault.connect(f.custodians[0]).propose(body.chain_paper_id, 0, 0, ethers.ZeroAddress, ethers.ZeroAddress, ethers.ZeroHash);
    await f.vault.connect(f.custodians[1]).voteProposal(1);
    expect((await f.handle("GET", "/papers/pap_gwtest/1")).body.status).to.equal("FROZEN");
  });

  it("audit batches anchor contiguously and events verify by inclusion proof", async () => {
    const f = await setup();
    const hashes = [1, 2, 3].map((i) => ev.sha256Hex(ev.utf8("event-" + i)));
    const a = await f.handle("POST", "/audit/anchor", { first_seq: 1, last_seq: 3, event_hashes: hashes });
    expect(a.code).to.equal(200);
    const tree = new ev.MerkleTree(hashes.map(ev.auditLeaf));
    expect(a.body.root).to.equal(tree.rootHex);
    expect(await f.anchor.verifyInclusion(f.orgId, 0, hashes[2], tree.proof(2))).to.equal(true);
    const gap = await f.handle("POST", "/audit/anchor", { first_seq: 9, last_seq: 9, event_hashes: [hashes[0]] });
    expect([gap.code, gap.body.expected_first_seq]).to.deep.equal([409, 4]);
    expect((await f.handle("GET", "/audit/last-seq")).body.last_seq).to.equal(3);
  });

  it("risk flags from the AI module are recorded on-chain (pseudonymous)", async () => {
    const f = await setup();
    const h = (c) => "0x" + c.repeat(64);
    const out = await f.handle("POST", "/risk/flag", { subject_hash: h("a"), score: 87, reason_hash: h("b"), event_hash: h("c") });
    expect([out.code, out.body.flag_index]).to.deep.equal([200, 1]);
    expect(await f.anchor.flagCount(f.orgId)).to.equal(1n);
    expect((await f.handle("POST", "/risk/flag", { subject_hash: h("a"), score: 300, reason_hash: h("b"), event_hash: h("c") })).code).to.equal(400);
  });

  it("an account without the Controller role cannot seal through the gateway", async () => {
    const f = await setup();
    const [, , , , , , , , , , outsider] = await ethers.getSigners();
    const bad = core.createHandler({ vault: f.vault.connect(outsider), anchor: f.anchor, cfg: f.cfg });
    const out = await bad("POST", "/papers/seal", await f.record());
    expect([out.code, out.body.error]).to.deep.equal([403, "NotController"]);
  });
});
