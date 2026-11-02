// Compares per-event anchoring against Merkle-batched anchoring (gas, tx count, proof size).
// Run: npx hardhat run scripts/benchmark-anchoring.js
const { ethers } = require("hardhat");
const ev = require("../../packages/crypto/src");

async function main() {
  const [owner, admin, anchorer] = await ethers.getSigners();
  const registry = await (await ethers.getContractFactory("OrgRegistry")).deploy(owner.address);
  const anchor = await (await ethers.getContractFactory("AuditAnchor")).deploy(await registry.getAddress());
  const org = ethers.id("BENCH-ORG");
  await registry.registerOrg(org, admin.address);
  await registry.connect(admin).grantRole(org, 3, anchorer.address);

  const kp = await ev.generateSigningKeyPair();
  const chain = new ev.AuditChain({ orgId: "bench", signingPrivateKey: kp.privateKey });
  const sizes = [10, 100, 1000, 10000];
  const maxN = sizes[sizes.length - 1];
  const entries = [];
  for (let i = 0; i < maxN; i++) entries.push(await chain.append("ACCESS", "u" + (i % 50), { i }, 1700000000000 + i));

  // Measure real per-event gas on 20 single-event anchors (cold + warm storage), then scale.
  let seq = 1, perEventGas = 0n;
  const SAMPLE = 20;
  for (let i = 0; i < SAMPLE; i++) {
    const b = ev.AuditChain.batch([entries[i]]);
    const r = await (await anchor.connect(anchorer).anchorBatch(org, b.root, seq, seq, false)).wait();
    perEventGas += r.gasUsed; seq++;
  }
  const avgPerEvent = Number(perEventGas) / SAMPLE;

  console.log("\nN events | per-event: txs, gas        | batched: txs, gas   | gas saved | proof size | build time");
  console.log("---------|----------------------------|---------------------|-----------|------------|-----------");
  for (const n of sizes) {
    const slice = entries.slice(SAMPLE, SAMPLE + Math.min(n, maxN - SAMPLE));
    const t0 = process.hrtime.bigint();
    const b = ev.AuditChain.batch(slice);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    const r = await (await anchor.connect(anchorer).anchorBatch(org, b.root, seq, seq + slice.length - 1, false)).wait();
    seq += slice.length;
    const perTotal = avgPerEvent * slice.length;
    const saved = (100 * (1 - Number(r.gasUsed) / perTotal)).toFixed(2);
    console.log(
      String(slice.length).padEnd(8) + " | " + (slice.length + " txs, " + Math.round(perTotal).toLocaleString() + " gas").padEnd(26) +
      " | " + ("1 tx, " + Number(r.gasUsed).toLocaleString() + " gas").padEnd(19) +
      " | " + (saved + "%").padEnd(9) + " | " + (b.proofFor(0).length * 32 + " bytes").padEnd(10) + " | " + ms.toFixed(1) + " ms"
    );
  }
  console.log("\n(avg gas per single-event anchor measured over " + SAMPLE + " txs: " + Math.round(avgPerEvent).toLocaleString() + ")");
}
main().catch((e) => { console.error(e); process.exit(1); });
