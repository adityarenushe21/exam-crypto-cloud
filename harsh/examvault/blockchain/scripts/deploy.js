// ExamVault capstone project | Harsh Kapile | MIT World Peace University, Pune
// Module: blockchain integrity (smart contracts, chain gateway, ChronoSeal)
// SPDX-License-Identifier: MIT
// Deploys OrgRegistry, ExamVault, AuditAnchor and writes addresses to deployments/<network>.json
const fs = require("fs");
const path = require("path");
const { ethers, network } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  const ttl = Number(process.env.PROPOSAL_TTL_SECONDS || 86400);

  const registry = await (await ethers.getContractFactory("OrgRegistry")).deploy(deployer.address);
  await registry.waitForDeployment();
  const vault = await (await ethers.getContractFactory("ExamVault")).deploy(await registry.getAddress(), ttl);
  await vault.waitForDeployment();
  const anchor = await (await ethers.getContractFactory("AuditAnchor")).deploy(await registry.getAddress());
  await anchor.waitForDeployment();

  const out = {
    network: network.name,
    chainId: Number((await ethers.provider.getNetwork()).chainId),
    deployer: deployer.address,
    OrgRegistry: await registry.getAddress(),
    ExamVault: await vault.getAddress(),
    AuditAnchor: await anchor.getAddress(),
    deployedAt: new Date().toISOString(),
  };
  const dir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, network.name + ".json"), JSON.stringify(out, null, 2));
  console.log(out);
}
main().catch((e) => { console.error(e); process.exit(1); });
