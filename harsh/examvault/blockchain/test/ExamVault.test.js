// ExamVault capstone project | Harsh Kapile | MIT World Peace University, Pune
// Module: blockchain integrity (smart contracts, chain gateway, ChronoSeal)
// SPDX-License-Identifier: MIT
const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");
const ev = require("../../packages/crypto/src");

const Action = { Freeze: 0, Unfreeze: 1, Reschedule: 2, Revoke: 3, RotateCustodian: 4, MarkCompromised: 5 };
const Status = { None: 0, Sealed: 1, Frozen: 2, Released: 3, Revoked: 4, Compromised: 5 };
const Role = { Controller: 1, Analyst: 2, Anchorer: 3 };
const id = (s) => ethers.keccak256(ethers.toUtf8Bytes(s));
const H = (s) => ev.sha256Hex(ev.utf8(s));

async function fixture() {
  const [owner, orgAdmin, controller, analyst, anchorer, c1, c2, c3, c4, c5, c6, outsider, orgBAdmin, orgBController] =
    await ethers.getSigners();
  const registry = await (await ethers.getContractFactory("OrgRegistry")).deploy(owner.address);
  const vault = await (await ethers.getContractFactory("ExamVault")).deploy(await registry.getAddress(), 86400);
  const anchor = await (await ethers.getContractFactory("AuditAnchor")).deploy(await registry.getAddress());

  const orgA = id("ORG-NATIONAL-BOARD");
  const orgB = id("ORG-UNIVERSITY");
  await registry.registerOrg(orgA, orgAdmin.address);
  await registry.registerOrg(orgB, orgBAdmin.address);
  await registry.connect(orgAdmin).grantRole(orgA, Role.Controller, controller.address);
  await registry.connect(orgAdmin).grantRole(orgA, Role.Analyst, analyst.address);
  await registry.connect(orgAdmin).grantRole(orgA, Role.Anchorer, anchorer.address);
  await registry.connect(orgBAdmin).grantRole(orgB, Role.Controller, orgBController.address);

  const custodians = [c1, c2, c3, c4, c5];

  // Build real commitments with the same crypto library the app will use.
  const centres = ["CENTRE-001", "CENTRE-002", "CENTRE-003"];
  const variants = centres.map((c) => ({ centreIdHash: H(c), variantHash: H("cipher-" + c) }));
  const manifest = new ev.MerkleTree(variants.map((v) => ev.variantLeaf(v.centreIdHash, v.variantHash)));
  const shareHashes = custodians.map((c, i) => H("share-" + i));
  const shareTree = new ev.MerkleTree(custodians.map((c, i) => ev.shareLeaf(c.address, shareHashes[i])));

  const sealArgs = async (paperName, overrides = {}) => {
    const now = await time.latest();
    return {
      orgId: orgA, paperId: id(paperName), manifestRoot: manifest.rootHex, shareCommitRoot: shareTree.rootHex,
      masterHash: H("master-" + paperName), releaseTime: now + 3600, threshold: 3, freezeThreshold: 2,
      custodians: custodians.map((c) => c.address), ...overrides,
    };
  };
  const seal = async (name, overrides) => {
    const a = await sealArgs(name, overrides);
    await vault.connect(controller).sealPaper(a);
    return a;
  };

  return { owner, orgAdmin, controller, analyst, anchorer, custodians, c6, outsider, orgBController, registry, vault, anchor,
    orgA, orgB, manifest, shareTree, variants, shareHashes, sealArgs, seal };
}
const load = fixture; // fresh deployment per test (simple and isolated)

describe("OrgRegistry (multi-tenant)", () => {
  it("only platform owner registers orgs; only org admin grants roles; roles are org-scoped", async () => {
    const f = await load();
    await expect(f.registry.connect(f.outsider).registerOrg(id("X"), f.outsider.address)).to.be.reverted;
    await expect(f.registry.connect(f.outsider).grantRole(f.orgA, Role.Controller, f.outsider.address))
      .to.be.revertedWithCustomError(f.registry, "NotOrgAdmin");
    expect(await f.registry.hasRole(f.orgA, Role.Controller, f.controller.address)).to.equal(true);
    expect(await f.registry.hasRole(f.orgB, Role.Controller, f.controller.address)).to.equal(false);
  });
  it("deactivating an org suspends all its roles", async () => {
    const f = await load();
    await f.registry.setOrgActive(f.orgA, false);
    expect(await f.registry.hasRole(f.orgA, Role.Controller, f.controller.address)).to.equal(false);
  });
});

describe("ExamVault: sealing", () => {
  it("controller seals; state and event are correct", async () => {
    const f = await load();
    const a = await f.sealArgs("P1");
    await expect(f.vault.connect(f.controller).sealPaper(a)).to.emit(f.vault, "PaperSealed");
    const p = await f.vault.getPaper(a.paperId);
    expect(p.status).to.equal(Status.Sealed);
    expect(p.manifestRoot).to.equal(a.manifestRoot);
    expect(p.releaseTime).to.equal(a.releaseTime);
    expect((await f.vault.custodiansOf(a.paperId)).length).to.equal(5);
  });
  it("rejects non-controller, other tenant's controller, duplicates and bad params", async () => {
    const f = await load();
    const a = await f.sealArgs("P1");
    await expect(f.vault.connect(f.outsider).sealPaper(a)).to.be.revertedWithCustomError(f.vault, "NotController");
    await expect(f.vault.connect(f.orgBController).sealPaper(a)).to.be.revertedWithCustomError(f.vault, "NotController");
    await f.vault.connect(f.controller).sealPaper(a);
    await expect(f.vault.connect(f.controller).sealPaper(a)).to.be.revertedWithCustomError(f.vault, "PaperExists");

    const dup = await f.sealArgs("P2", { custodians: [f.custodians[0].address, f.custodians[0].address, f.custodians[1].address] });
    await expect(f.vault.connect(f.controller).sealPaper(dup)).to.be.revertedWithCustomError(f.vault, "BadParam");
    const big = await f.sealArgs("P3", { threshold: 6 });
    await expect(f.vault.connect(f.controller).sealPaper(big)).to.be.revertedWithCustomError(f.vault, "BadParam");
    const past = await f.sealArgs("P4", { releaseTime: (await time.latest()) - 10 });
    await expect(f.vault.connect(f.controller).sealPaper(past)).to.be.revertedWithCustomError(f.vault, "BadParam");
  });
});

describe("ExamVault: time-locked threshold release", () => {
  it("cannot approve before releaseTime, even as a valid custodian", async () => {
    const f = await load();
    const a = await f.seal("P1");
    await expect(f.vault.connect(f.custodians[0]).approveRelease(a.paperId)).to.be.revertedWithCustomError(f.vault, "TooEarly");
    expect(await f.vault.canApproveRelease(a.paperId)).to.equal(false);
  });
  it("releases exactly at 3-of-5 after the time; blocks outsiders and double votes", async () => {
    const f = await load();
    const a = await f.seal("P1");
    await time.increaseTo(a.releaseTime);
    await expect(f.vault.connect(f.outsider).approveRelease(a.paperId)).to.be.revertedWithCustomError(f.vault, "NotCustodian");
    await f.vault.connect(f.custodians[0]).approveRelease(a.paperId);
    await expect(f.vault.connect(f.custodians[0]).approveRelease(a.paperId)).to.be.revertedWithCustomError(f.vault, "AlreadyVoted");
    await f.vault.connect(f.custodians[1]).approveRelease(a.paperId);
    expect((await f.vault.getPaper(a.paperId)).status).to.equal(Status.Sealed);
    await expect(f.vault.connect(f.custodians[4]).approveRelease(a.paperId)).to.emit(f.vault, "ReleaseAuthorized");
    expect((await f.vault.getPaper(a.paperId)).status).to.equal(Status.Released);
  });
  it("two custodians offline does not block release (3-of-5)", async () => {
    const f = await load();
    const a = await f.seal("P1");
    await time.increaseTo(a.releaseTime);
    for (const i of [1, 2, 3]) await f.vault.connect(f.custodians[i]).approveRelease(a.paperId);
    expect((await f.vault.getPaper(a.paperId)).status).to.equal(Status.Released);
  });
});

describe("ExamVault: Merkle verification matches the off-chain library", () => {
  it("verifyVariant / verifyShareCommitment accept genuine proofs and reject forged ones", async () => {
    const f = await load();
    const a = await f.seal("P1");
    for (let i = 0; i < f.variants.length; i++) {
      const proof = f.manifest.proof(i);
      expect(await f.vault.verifyVariant(a.paperId, f.variants[i].centreIdHash, f.variants[i].variantHash, proof)).to.equal(true);
      expect(await f.vault.verifyVariant(a.paperId, f.variants[i].centreIdHash, H("tampered"), proof)).to.equal(false);
    }
    for (let i = 0; i < 5; i++) {
      expect(await f.vault.verifyShareCommitment(a.paperId, f.custodians[i].address, f.shareHashes[i], f.shareTree.proof(i))).to.equal(true);
    }
    expect(await f.vault.verifyShareCommitment(a.paperId, f.outsider.address, f.shareHashes[0], f.shareTree.proof(0))).to.equal(false);
  });
});

describe("ExamVault: emergency flows", () => {
  it("freeze needs only 2-of-5, blocks release, unfreeze needs 3-of-5 and resets stale approvals", async () => {
    const f = await load();
    const a = await f.seal("P1");
    await time.increaseTo(a.releaseTime);
    await f.vault.connect(f.custodians[0]).approveRelease(a.paperId); // partial approval (1/3)

    // custodian 3 proposes freeze (auto-votes 1), custodian 4 votes -> executes at 2
    await f.vault.connect(f.custodians[3]).propose(a.paperId, Action.Freeze, 0, ethers.ZeroAddress, ethers.ZeroAddress, ethers.ZeroHash);
    expect((await f.vault.getPaper(a.paperId)).status).to.equal(Status.Sealed);
    await expect(f.vault.connect(f.custodians[4]).voteProposal(1)).to.emit(f.vault, "PaperFrozen");
    expect((await f.vault.getPaper(a.paperId)).status).to.equal(Status.Frozen);
    await expect(f.vault.connect(f.custodians[1]).approveRelease(a.paperId)).to.be.revertedWithCustomError(f.vault, "BadState");

    // unfreeze: 2 votes are not enough
    await f.vault.connect(f.custodians[0]).propose(a.paperId, Action.Unfreeze, 0, ethers.ZeroAddress, ethers.ZeroAddress, ethers.ZeroHash);
    await f.vault.connect(f.custodians[1]).voteProposal(2);
    expect((await f.vault.getPaper(a.paperId)).status).to.equal(Status.Frozen);
    await f.vault.connect(f.custodians[2]).voteProposal(2);
    expect((await f.vault.getPaper(a.paperId)).status).to.equal(Status.Sealed);

    // the earlier partial approval from before the freeze no longer counts: 3 fresh approvals needed
    await f.vault.connect(f.custodians[1]).approveRelease(a.paperId);
    await f.vault.connect(f.custodians[2]).approveRelease(a.paperId);
    expect((await f.vault.getPaper(a.paperId)).status).to.equal(Status.Sealed);
    await f.vault.connect(f.custodians[0]).approveRelease(a.paperId); // custodian 0 may vote again in the new round
    expect((await f.vault.getPaper(a.paperId)).status).to.equal(Status.Released);
  });

  it("controller may propose but cannot vote; outsiders cannot propose", async () => {
    const f = await load();
    const a = await f.seal("P1");
    await f.vault.connect(f.controller).propose(a.paperId, Action.Freeze, 0, ethers.ZeroAddress, ethers.ZeroAddress, ethers.ZeroHash);
    await expect(f.vault.connect(f.controller).voteProposal(1)).to.be.revertedWithCustomError(f.vault, "NotCustodian");
    await expect(f.vault.connect(f.outsider).propose(a.paperId, Action.Freeze, 0, ethers.ZeroAddress, ethers.ZeroAddress, ethers.ZeroHash))
      .to.be.revertedWithCustomError(f.vault, "NotAuthorizedToPropose");
  });

  it("reschedule: later only, 3-of-5, release time moves", async () => {
    const f = await load();
    const a = await f.seal("P1");
    const earlier = a.releaseTime - 100;
    await expect(f.vault.connect(f.custodians[0]).propose(a.paperId, Action.Reschedule, earlier, ethers.ZeroAddress, ethers.ZeroAddress, ethers.ZeroHash))
      .to.be.revertedWithCustomError(f.vault, "BadParam");
    const later = a.releaseTime + 7200;
    await f.vault.connect(f.custodians[0]).propose(a.paperId, Action.Reschedule, later, ethers.ZeroAddress, ethers.ZeroAddress, ethers.ZeroHash);
    await f.vault.connect(f.custodians[1]).voteProposal(1);
    await expect(f.vault.connect(f.custodians[2]).voteProposal(1)).to.emit(f.vault, "PaperRescheduled").withArgs(a.paperId, a.releaseTime, later);
    await time.increaseTo(a.releaseTime + 10); // old time has passed, but release is still locked
    await expect(f.vault.connect(f.custodians[0]).approveRelease(a.paperId)).to.be.revertedWithCustomError(f.vault, "TooEarly");
  });

  it("revoke + activate backup set: original revoked, backup sealed under the same org", async () => {
    const f = await load();
    const a = await f.seal("SET-A");
    const b = await f.seal("SET-B");
    const other = await (async () => { // a paper from another tenant cannot be used as backup
      const now = await time.latest();
      const args = { ...(await f.sealArgs("OTHER")), orgId: f.orgB, releaseTime: now + 3600 };
      await f.vault.connect(f.orgBController).sealPaper(args);
      return args;
    })();
    await expect(f.vault.connect(f.custodians[0]).propose(a.paperId, Action.Revoke, 0, ethers.ZeroAddress, ethers.ZeroAddress, other.paperId))
      .to.be.revertedWithCustomError(f.vault, "BadParam");

    await f.vault.connect(f.custodians[0]).propose(a.paperId, Action.Revoke, 0, ethers.ZeroAddress, ethers.ZeroAddress, b.paperId);
    await f.vault.connect(f.custodians[1]).voteProposal(1);
    await expect(f.vault.connect(f.custodians[2]).voteProposal(1)).to.emit(f.vault, "PaperRevoked").withArgs(a.paperId, b.paperId);
    expect((await f.vault.getPaper(a.paperId)).status).to.equal(Status.Revoked);
    expect(await f.vault.supersededBy(a.paperId)).to.equal(b.paperId);
    expect((await f.vault.getPaper(b.paperId)).status).to.equal(Status.Sealed);

    await time.increaseTo(a.releaseTime);
    await expect(f.vault.connect(f.custodians[0]).approveRelease(a.paperId)).to.be.revertedWithCustomError(f.vault, "BadState");
  });

  it("custodian rotation replaces an unavailable custodian and invalidates the old one", async () => {
    const f = await load();
    const a = await f.seal("P1");
    const newRoot = H("refreshed-share-commitments");
    await f.vault.connect(f.custodians[0]).propose(a.paperId, Action.RotateCustodian, 0, f.custodians[4].address, f.c6.address, newRoot);
    await f.vault.connect(f.custodians[1]).voteProposal(1);
    await expect(f.vault.connect(f.custodians[2]).voteProposal(1)).to.emit(f.vault, "CustodianRotated");
    const list = await f.vault.custodiansOf(a.paperId);
    expect(list).to.include(f.c6.address);
    expect(list).to.not.include(f.custodians[4].address);
    expect((await f.vault.getPaper(a.paperId)).shareCommitRoot).to.equal(newRoot);

    await time.increaseTo(a.releaseTime);
    await expect(f.vault.connect(f.custodians[4]).approveRelease(a.paperId)).to.be.revertedWithCustomError(f.vault, "NotCustodian");
    await f.vault.connect(f.c6).approveRelease(a.paperId);
  });

  it("executing one action invalidates other pending proposals (stale round)", async () => {
    const f = await load();
    const a = await f.seal("P1");
    await f.vault.connect(f.custodians[0]).propose(a.paperId, Action.Reschedule, a.releaseTime + 999, ethers.ZeroAddress, ethers.ZeroAddress, ethers.ZeroHash); // id 1
    await f.vault.connect(f.custodians[1]).propose(a.paperId, Action.Freeze, 0, ethers.ZeroAddress, ethers.ZeroAddress, ethers.ZeroHash); // id 2
    await f.vault.connect(f.custodians[2]).voteProposal(2); // freeze executes
    await expect(f.vault.connect(f.custodians[3]).voteProposal(1)).to.be.revertedWithCustomError(f.vault, "Stale");
  });

  it("proposals expire", async () => {
    const f = await load();
    const a = await f.seal("P1");
    await f.vault.connect(f.custodians[0]).propose(a.paperId, Action.Freeze, 0, ethers.ZeroAddress, ethers.ZeroAddress, ethers.ZeroHash);
    await time.increase(86400 + 5);
    await expect(f.vault.connect(f.custodians[1]).voteProposal(1)).to.be.revertedWithCustomError(f.vault, "Expired");
  });

  it("post-release leak: analyst proposes, 3 custodians confirm, paper marked COMPROMISED", async () => {
    const f = await load();
    const a = await f.seal("P1");
    // cannot be raised before release
    await expect(f.vault.connect(f.analyst).propose(a.paperId, Action.MarkCompromised, 0, ethers.ZeroAddress, ethers.ZeroAddress, ethers.ZeroHash))
      .to.be.revertedWithCustomError(f.vault, "BadState");
    await time.increaseTo(a.releaseTime);
    for (const i of [0, 1, 2]) await f.vault.connect(f.custodians[i]).approveRelease(a.paperId);

    await expect(f.vault.connect(f.custodians[0]).propose(a.paperId, Action.MarkCompromised, 0, ethers.ZeroAddress, ethers.ZeroAddress, ethers.ZeroHash))
      .to.be.revertedWithCustomError(f.vault, "NotAnalyst");
    await f.vault.connect(f.analyst).propose(a.paperId, Action.MarkCompromised, 0, ethers.ZeroAddress, ethers.ZeroAddress, ethers.ZeroHash);
    for (const i of [0, 1]) await f.vault.connect(f.custodians[i]).voteProposal(1);
    await expect(f.vault.connect(f.custodians[2]).voteProposal(1)).to.emit(f.vault, "PaperCompromised");
    expect((await f.vault.getPaper(a.paperId)).status).to.equal(Status.Compromised);
  });
});

describe("AuditAnchor", () => {
  it("anchors contiguous batches, chains roots, rejects gaps/outsiders", async () => {
    const f = await load();
    const kp = await ev.generateSigningKeyPair();
    const chain = new ev.AuditChain({ orgId: "orgA", signingPrivateKey: kp.privateKey });
    const entries = [];
    for (let i = 0; i < 10; i++) entries.push(await chain.append("ACCESS", "u" + i, { i }));
    const b1 = ev.AuditChain.batch(entries.slice(0, 6));
    const b2 = ev.AuditChain.batch(entries.slice(6));

    await expect(f.anchor.connect(f.outsider).anchorBatch(f.orgA, b1.root, 1, 6, false)).to.be.revertedWithCustomError(f.anchor, "NotAnchorer");
    await expect(f.anchor.connect(f.anchorer).anchorBatch(f.orgA, b2.root, 7, 10, false)).to.be.revertedWithCustomError(f.anchor, "BadRange"); // gap
    await f.anchor.connect(f.anchorer).anchorBatch(f.orgA, b1.root, 1, 6, false);
    await f.anchor.connect(f.anchorer).anchorBatch(f.orgA, b2.root, 7, 10, true);

    expect((await f.anchor.getBatch(f.orgA, 1)).prevRoot).to.equal(b1.root);
    expect(await f.anchor.lastSeq(f.orgA)).to.equal(10);
    expect(await f.anchor.batchCount(f.orgA)).to.equal(2);

    // JS-built inclusion proofs verify in the EVM; a modified entry does not
    expect(await f.anchor.verifyInclusion(f.orgA, 0, entries[3].hash, b1.proofFor(3))).to.equal(true);
    expect(await f.anchor.verifyInclusion(f.orgA, 1, entries[9].hash, b2.proofFor(3))).to.equal(true);
    expect(await f.anchor.verifyInclusion(f.orgA, 0, entries[7].hash, b1.proofFor(3))).to.equal(false);
  });

  it("records AI risk flags on-chain (pseudonymous, no personal data)", async () => {
    const f = await load();
    await expect(f.anchor.connect(f.anchorer).flagRisk(f.orgA, H("user-pseudonym"), 87, H("shap-explanation"), H("event")))
      .to.emit(f.anchor, "RiskFlagged").withArgs(f.orgA, H("user-pseudonym"), 87, H("shap-explanation"), H("event"), 1);
    expect(await f.anchor.flagCount(f.orgA)).to.equal(1);
  });

  it("orgs are isolated: org A's anchorer cannot write to org B", async () => {
    const f = await load();
    await expect(f.anchor.connect(f.anchorer).anchorBatch(f.orgB, H("r"), 1, 1, false)).to.be.revertedWithCustomError(f.anchor, "NotAnchorer");
  });
});
