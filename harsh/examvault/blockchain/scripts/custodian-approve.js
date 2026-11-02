// Custodians approve release of a paper sealed through examcrypto.
// PowerShell:
//   $env:PAPER_ID="pap_..."; $env:PAPER_VERSION="1"; $env:COUNT="3"
//   npx hardhat run scripts/custodian-approve.js --network localhost
const fs = require("fs");
const path = require("path");
const { ethers, network } = require("hardhat");
const { chainPaperId, STATUS } = require("../gateway/core");

async function main() {
  const paperId = process.env.PAPER_ID;
  if (!paperId) throw new Error("set PAPER_ID (e.g. $env:PAPER_ID=\"pap_...\")");
  const version = Number(process.env.PAPER_VERSION || 1);
  const count = Number(process.env.COUNT || 3);
  const d = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "deployments", network.name + ".json"), "utf8"));
  const vault = await ethers.getContractAt("ExamVault", d.ExamVault);
  const id = chainPaperId(paperId, version);

  for (const addr of d.gateway.custodians.slice(0, count)) {
    const signer = await ethers.getSigner(addr);
    try {
      await (await vault.connect(signer).approveRelease(id)).wait();
      console.log(`custodian ${addr} approved`);
    } catch (e) {
      console.log(`custodian ${addr} REJECTED by contract: ${(e.revert && e.revert.name) || e.shortMessage || e.message}`);
    }
  }
  const p = await vault.getPaper(id);
  console.log(`status: ${STATUS[Number(p.status)]}  releaseTime: ${new Date(Number(p.releaseTime) * 1000).toISOString()}`);
}
main().catch((e) => { console.error(e.message || e); process.exit(1); });
