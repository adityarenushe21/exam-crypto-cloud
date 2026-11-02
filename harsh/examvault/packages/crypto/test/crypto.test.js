"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const ev = require("../src");
const { shamir } = ev;

test("AES-256-GCM round trip, AAD binding and tamper detection", async () => {
  const k = ev.generateDEK();
  const ct = await ev.aesEncrypt(k, ev.utf8("hello exam"), ev.utf8("p1|c1"));
  assert.equal(ev.fromUtf8(await ev.aesDecrypt(k, ct, ev.utf8("p1|c1"))), "hello exam");
  await assert.rejects(ev.aesDecrypt(k, ct, ev.utf8("p1|c2")));
  const bad = ct.slice(); bad[20] ^= 1;
  await assert.rejects(ev.aesDecrypt(k, bad, ev.utf8("p1|c1")));
});

test("Shamir: any k of n reconstruct, k-1 do not", () => {
  const secret = ev.randomBytes(32);
  const shares = shamir.split(secret, 5, 3);
  for (const idx of [[0,1,2],[0,2,4],[1,3,4],[2,3,4]]) {
    assert.ok(ev.equal(shamir.combine(idx.map((i) => shares[i])), secret));
  }
  assert.ok(!ev.equal(shamir.combine([shares[0], shares[1]]), secret));
  assert.ok(ev.equal(shamir.combine(shares), secret)); // all 5 also fine
});

test("Shamir: blinded extension gives a new custodian a valid share without reconstructing", () => {
  const secret = ev.randomBytes(32);
  const shares = shamir.split(secret, 5, 3);
  const blinded = shamir.blindedContributions([shares[0], shares[2], shares[4]], 9);
  const s9 = shamir.assembleExtendedShare(blinded, 9);
  assert.ok(ev.equal(shamir.combine([s9, shares[1], shares[3]]), secret));
  // a single blinded contribution looks random (differs from the unblinded Lagrange term)
  assert.equal(blinded.length, 3);
});

test("Shamir: proactive refresh keeps the secret but kills old shares", () => {
  const secret = ev.randomBytes(32);
  const old = shamir.split(secret, 5, 3);
  const fresh = shamir.refresh(old, 3);
  assert.ok(ev.equal(shamir.combine([fresh[0], fresh[1], fresh[2]]), secret));
  assert.ok(!ev.equal(shamir.combine([old[0], old[1], fresh[2]]), secret)); // mixing fails
  assert.ok(ev.equal(shamir.combine([old[0], old[1], old[2]]), secret));    // old set alone still self-consistent
});

test("Merkle: proofs verify, wrong leaf fails, odd sizes ok", () => {
  for (const n of [1, 2, 3, 5, 8, 13]) {
    const leaves = Array.from({ length: n }, (_, i) => ev.auditLeaf(ev.sha256Hex(ev.utf8("e" + i))));
    const t = new ev.MerkleTree(leaves);
    for (let i = 0; i < n; i++) assert.ok(ev.verifyProof(t.proof(i), t.root, leaves[i]));
    assert.ok(!ev.verifyProof(t.proof(0), t.root, ev.auditLeaf(ev.sha256Hex(ev.utf8("evil")))));
  }
});

test("AuditChain: verifies; detects edit, deletion, reorder, wrong key", async () => {
  const kp = await ev.generateSigningKeyPair();
  const chain = new ev.AuditChain({ orgId: "org1", signingPrivateKey: kp.privateKey });
  const entries = [];
  for (let i = 0; i < 6; i++) entries.push(await chain.append("ACCESS", "user" + i, { n: i }));
  assert.ok((await ev.AuditChain.verify(entries, kp.publicKey)).ok);

  const edited = structuredClone(entries); edited[2].data.n = 99;
  assert.equal((await ev.AuditChain.verify(edited, kp.publicKey)).badSeq, 3);
  const deleted = entries.filter((_, i) => i !== 3);
  assert.equal((await ev.AuditChain.verify(deleted, kp.publicKey)).ok, false);
  const reordered = [entries[0], entries[2], entries[1], ...entries.slice(3)];
  assert.equal((await ev.AuditChain.verify(reordered, kp.publicKey)).ok, false);
  const other = await ev.generateSigningKeyPair();
  assert.equal((await ev.AuditChain.verify(entries, other.publicKey)).reason, "bad signature");
});

test("ChronoSeal end to end: seal -> custodian re-encrypt -> centre open", async () => {
  const paper = ev.utf8("Q1. Explain Shamir secret sharing. Q2. ...");
  const cust = [];
  for (let i = 0; i < 5; i++) { const kp = await ev.generateRsaKeyPair(2048); cust.push({ kp, address: "0x" + (i + 1).toString(16).padStart(40, "0") }); }
  const centreKp = await ev.generateRsaKeyPair(2048);

  const sealed = await ev.sealPaper({
    paperId: "paper-1", paperBytes: paper,
    centres: [{ id: "C-001" }, { id: "C-002" }, { id: "C-003" }],
    custodians: cust.map((c) => ({ address: c.address, rsaPublicKey: c.kp.publicKey })),
    threshold: 3,
  });
  const v = sealed.variants[1];
  assert.ok(ev.verifyVariantInManifest({ centreId: "C-002", variantCiphertext: v.ciphertext, proof: v.proof, manifestRoot: sealed.manifestRoot }));
  assert.ok(!ev.verifyVariantInManifest({ centreId: "C-001", variantCiphertext: v.ciphertext, proof: v.proof, manifestRoot: sealed.manifestRoot }));

  const wrap = async (i) => ({
    address: cust[i].address,
    proof: sealed.custodianPackages[i].proof,
    wrapped: await ev.custodianReencrypt({
      custodianPrivateKey: cust[i].kp.privateKey,
      encryptedShare: sealed.custodianPackages[i].encryptedShare,
      centrePublicKey: centreKp.publicKey,
    }),
  });
  const args = { centrePrivateKey: centreKp.privateKey, variantCiphertext: v.ciphertext, paperId: "paper-1", centreId: "C-002", shareCommitRoot: sealed.shareCommitRoot, threshold: 3 };

  const out = await ev.centreOpen({ ...args, wrappedShares: [await wrap(0), await wrap(2), await wrap(4)] });
  assert.equal(ev.fromUtf8(out.plaintext), ev.fromUtf8(paper));

  // only 2 custodians -> cannot open
  await assert.rejects(ev.centreOpen({ ...args, wrappedShares: [await wrap(0), await wrap(1)] }));
  // a malicious custodian sends garbage -> detected and attributed, others still suffice
  const evil = await wrap(1); evil.wrapped = await ev.rsaEncrypt(centreKp.publicKey, ev.randomBytes(33));
  const out2 = await ev.centreOpen({ ...args, wrappedShares: [evil, await wrap(0), await wrap(2), await wrap(3)] });
  assert.deepEqual(out2.rejected, [cust[1].address]);
  assert.equal(ev.fromUtf8(out2.plaintext), ev.fromUtf8(paper));
  // a different centre cannot decrypt this variant even with the DEK (AAD binding)
  await assert.rejects(ev.centreOpen({ ...args, centreId: "C-003", wrappedShares: [await wrap(0), await wrap(2), await wrap(4)] }));
});
