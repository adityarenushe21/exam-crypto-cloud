// ExamVault capstone project | Harsh Kapile | MIT World Peace University, Pune
// Module: blockchain integrity (smart contracts, chain gateway, ChronoSeal)
// SPDX-License-Identifier: MIT
"use strict";
// Gateway logic tests (no chain needed):  node --test gateway/test/
const test = require("node:test");
const assert = require("node:assert/strict");
const ev = require("../../../packages/crypto/src");
const core = require("../core");
const { FakeVault, FakeAnchor } = require("./fakes");

const CUSTODIANS = [1, 2, 3, 4, 5].map((i) => "0x" + String(i).padStart(40, "0"));
const cfg = { orgId: core.orgIdFor("ORG-TEST"), custodians: CUSTODIANS, threshold: 3, freezeThreshold: 2 };
const digest = "0x" + "ab".repeat(32);

function setup() {
  let now = 1_800_000_000;
  const vault = new FakeVault(() => now);
  const anchor = new FakeAnchor();
  const handle = core.createHandler({ vault, anchor, cfg });
  const record = { paper_id: "pap_test01", paper_version: 1, hash_algorithm: "SHA3-256",
    ciphertext_digest_bytes32: digest, manifest_digest_bytes32: "0x" + "cd".repeat(32),
    release_at_unix: now + 3600, signer_key_id: "00".repeat(16) };
  return { vault, anchor, handle, record, setNow: (t) => { now = t; }, getNow: () => now };
}

test("ids match ethers.id() / keccak256(utf8) convention", () => {
  assert.equal(core.orgIdFor(""), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  assert.equal(core.chainPaperId("pap_x", 1), ev.keccakHex(ev.utf8("pap_x:v1")));
  assert.notEqual(core.chainPaperId("pap_x", 1), core.chainPaperId("pap_x", 2));
});

test("single-variant manifest root equals the variant leaf and verifies with an empty proof", () => {
  const root = core.manifestRootFor(digest);
  const leaf = ev.variantLeaf(ev.sha256(ev.utf8("CENTRAL")), digest);
  assert.equal(root, ev.hex(leaf));
  assert.ok(ev.verifyProof([], root, leaf));
  assert.ok(!ev.verifyProof([], root, ev.variantLeaf(ev.sha256(ev.utf8("CENTRAL")), "0x" + "00".repeat(32))));
});

test("seal maps the record onto SealParams exactly", async () => {
  const { vault, handle, record } = setup();
  const out = await handle("POST", "/papers/seal", record);
  assert.equal(out.code, 200);
  const p = await vault.getPaper(out.body.chain_paper_id);
  assert.equal(p.masterHash, digest);
  assert.equal(p.releaseTime, BigInt(record.release_at_unix));
  assert.equal(p.shareCommitRoot, core.ZERO32);
  assert.deepEqual(p.custodians, CUSTODIANS);
  assert.equal(out.body.manifest_root, core.manifestRootFor(digest));
});

test("seal input validation", async () => {
  const { handle, record } = setup();
  for (const bad of [
    { ...record, hash_algorithm: "SHA-256" },
    { ...record, ciphertext_digest_bytes32: "0x1234" },
    { ...record, ciphertext_digest_bytes32: digest.toUpperCase().replace("0X", "0x") },
    { ...record, paper_id: "../x" },
    { ...record, paper_version: 0 },
    { ...record, release_at_unix: "soon" },
  ]) {
    assert.equal((await handle("POST", "/papers/seal", bad)).code, 400, JSON.stringify(bad));
  }
  assert.equal((await handle("POST", "/papers/seal", null)).code, 400);
});

test("duplicate seal -> 409 PaperExists; past release time -> 400 BadParam", async () => {
  const { handle, record, getNow } = setup();
  await handle("POST", "/papers/seal", record);
  const dup = await handle("POST", "/papers/seal", record);
  assert.deepEqual([dup.code, dup.body.error], [409, "PaperExists"]);
  const past = await handle("POST", "/papers/seal", { ...record, paper_version: 2, release_at_unix: getNow() - 1 });
  assert.deepEqual([past.code, past.body.error], [400, "BadParam"]);
});

test("status: unknown 404, SEALED -> RELEASED only after time and 3 custodians", async () => {
  const { vault, handle, record, setNow } = setup();
  assert.equal((await handle("GET", "/papers/pap_test01/1")).code, 404);
  const { body } = await handle("POST", "/papers/seal", record);
  let st = (await handle("GET", "/papers/pap_test01/1")).body;
  assert.deepEqual([st.status, st.approvals, st.threshold, st.master_hash], ["SEALED", 0, 3, digest]);
  assert.throws(() => vault.approve(body.chain_paper_id, CUSTODIANS[0]), /TooEarly/);
  setNow(record.release_at_unix);
  vault.approve(body.chain_paper_id, CUSTODIANS[0]);
  vault.approve(body.chain_paper_id, CUSTODIANS[1]);
  st = (await handle("GET", "/papers/pap_test01/1")).body;
  assert.deepEqual([st.status, st.approvals], ["SEALED", 2]);
  vault.approve(body.chain_paper_id, CUSTODIANS[4]);
  st = (await handle("GET", "/papers/pap_test01/1")).body;
  assert.deepEqual([st.status, st.approvals], ["RELEASED", 3]);
  assert.equal(typeof st.release_at_unix, "number");
});

test("frozen status is reported", async () => {
  const { vault, handle, record } = setup();
  const { body } = await handle("POST", "/papers/seal", record);
  vault.setStatus(body.chain_paper_id, 2);
  assert.equal((await handle("GET", "/papers/pap_test01/1")).body.status, "FROZEN");
});

test("audit anchoring: contiguous batches, inclusion proofs, gap rejected", async () => {
  const { anchor, handle } = setup();
  const hashes = [1, 2, 3, 4].map((i) => ev.sha256Hex(ev.utf8("event" + i)));
  const a = await handle("POST", "/audit/anchor", { first_seq: 1, last_seq: 3, event_hashes: hashes.slice(0, 3) });
  assert.equal(a.code, 200);
  const tree = new ev.MerkleTree(hashes.slice(0, 3).map(ev.auditLeaf));
  assert.equal(a.body.root, tree.rootHex);
  assert.ok(await anchor.verifyInclusion(cfg.orgId, 0, hashes[1], tree.proof(1)));
  assert.equal((await handle("GET", "/audit/last-seq")).body.last_seq, 3);
  const gap = await handle("POST", "/audit/anchor", { first_seq: 5, last_seq: 5, event_hashes: [hashes[3]] });
  assert.deepEqual([gap.code, gap.body.expected_first_seq], [409, 4]);
  const badLen = await handle("POST", "/audit/anchor", { first_seq: 4, last_seq: 5, event_hashes: [hashes[3]] });
  assert.equal(badLen.code, 400);
  const ok = await handle("POST", "/audit/anchor", { first_seq: 4, last_seq: 4, event_hashes: [hashes[3]], critical: true });
  assert.equal(ok.body.batch_index, 1);
});

test("risk flag: validated, recorded, indexed", async () => {
  const { anchor, handle } = setup();
  const h = (c) => "0x" + c.repeat(64);
  const ok = await handle("POST", "/risk/flag", { subject_hash: h("a"), score: 87, reason_hash: h("b"), event_hash: h("c") });
  assert.deepEqual([ok.code, ok.body.flag_index], [200, 1]);
  assert.deepEqual(anchor.flags[0], { subjectHash: h("a"), score: 87, reasonHash: h("b"), eventHash: h("c") });
  for (const bad of [
    { subject_hash: "alice", score: 87, reason_hash: h("b"), event_hash: h("c") },
    { subject_hash: h("a"), score: 101, reason_hash: h("b"), event_hash: h("c") },
    { subject_hash: h("a"), score: 5.5, reason_hash: h("b"), event_hash: h("c") },
    { subject_hash: h("a"), score: 50, reason_hash: h("b") },
  ]) assert.equal((await handle("POST", "/risk/flag", bad)).code, 400, JSON.stringify(bad));
});

test("unknown route 404, contract failure never leaks internals", async () => {
  const { handle, record } = setup();
  assert.equal((await handle("GET", "/nope")).code, 404);
  const broken = core.createHandler({ vault: { sealPaper: async () => { throw new Error("RPC exploded at 127.0.0.1:8545 with secret stuff"); } }, anchor: {}, cfg });
  const out = await broken("POST", "/papers/seal", record);
  assert.equal(out.code, 502);
  assert.ok(!JSON.stringify(out.body).includes("secret"));
});

test("HTTP layer: JSON in/out, invalid JSON -> 400", async () => {
  const { handle, record } = setup();
  const server = core.createServer(handle).listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const r1 = await fetch(base + "/papers/seal", { method: "POST", body: JSON.stringify(record) });
    assert.equal(r1.status, 200);
    const r2 = await fetch(base + "/papers/pap_test01/1");
    assert.equal((await r2.json()).status, "SEALED");
    const r3 = await fetch(base + "/papers/seal", { method: "POST", body: "{not json" });
    assert.equal(r3.status, 400);
    assert.equal((await (await fetch(base + "/health")).json()).status, "OK");
  } finally {
    server.close();
  }
});
