// Emergency freeze by custodians (2-of-5): custodian 1 proposes, custodian 2 votes.
//   $env:PAPER_ID="pap_..."; npx hardhat run scripts/custodian-freeze.js --network localhost
const fs = require("fs");
const path = require("path");
const { ethers, network } = require("hardhat");
const { chainPaperId, STATUS } = require("../gateway/core");

const Action = { Freeze: 0 };

async function main() {
  const paperId = process.env.PAPER_ID;
  if (!paperId) throw new Error("set PAPER_ID");
  const version = Number(process.env.PAPER_VERSION || 1);
  const d = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "deployments", network.name + ".json"), "utf8"));
  const vault = await ethers.getContractAt("ExamVault", d.ExamVault);
  const id = chainPaperId(paperId, version);
  const [c1, c2] = await Promise.all(d.gateway.custodians.slice(0, 2).map((a) => ethers.getSigner(a)));

  await (await vault.connect(c1).propose(id, Action.Freeze, 0, ethers.ZeroAddress, ethers.ZeroAddress, ethers.ZeroHash)).wait();
  const proposalId = await vault.proposalCount();
  await (await vault.connect(c2).voteProposal(proposalId)).wait();
  const p = await vault.getPaper(id);
  console.log(`proposal ${proposalId} executed - status: ${STATUS[Number(p.status)]}`);
}
main().catch((e) => { console.error(e.message || e); process.exit(1); });
