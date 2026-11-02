// ExamVault capstone project | Harsh Kapile | MIT World Peace University, Pune
// Module: blockchain integrity (smart contracts, chain gateway, ChronoSeal)
// SPDX-License-Identifier: MIT
// One-step local setup for the integrated demo (does not modify deploy.js):
//   deploys OrgRegistry + ExamVault + AuditAnchor, registers one organisation, grants roles,
//   and writes deployments/<network>.json including a "gateway" section for gateway/server.js.
// Run:  npx hardhat run scripts/setup-local.js --network localhost
// Accounts (Hardhat's unlocked dev accounts): 0 owner, 1 org admin, 2 controller (gateway),
//   3 analyst, 4 anchorer (gateway), 5-9 custodians.
const fs = require("fs");
const path = require("path");
const { ethers, network } = require("hardhat");

const Role = { Controller: 1, Analyst: 2, Anchorer: 3 };

async function main() {
  const s = await ethers.getSigners();
  const [owner, orgAdmin, controller, analyst, anchorer] = s;
  const custodians = s.slice(5, 10);
  const ttl = Number(process.env.PROPOSAL_TTL_SECONDS || 86400);
  const orgName = process.env.ORG_NAME || "ORG-MITWPU-EXAMS";
  const orgId = ethers.id(orgName);

  const registry = await (await ethers.getContractFactory("OrgRegistry")).deploy(owner.address);
  await registry.waitForDeployment();
  const vault = await (await ethers.getContractFactory("ExamVault")).deploy(await registry.getAddress(), ttl);
  await vault.waitForDeployment();
  const anchor = await (await ethers.getContractFactory("AuditAnchor")).deploy(await registry.getAddress());
  await anchor.waitForDeployment();

  await (await registry.registerOrg(orgId, orgAdmin.address)).wait();
  await (await registry.connect(orgAdmin).grantRole(orgId, Role.Controller, controller.address)).wait();
  await (await registry.connect(orgAdmin).grantRole(orgId, Role.Analyst, analyst.address)).wait();
  await (await registry.connect(orgAdmin).grantRole(orgId, Role.Anchorer, anchorer.address)).wait();

  const out = {
    network: network.name,
    chainId: Number((await ethers.provider.getNetwork()).chainId),
    deployer: owner.address,
    OrgRegistry: await registry.getAddress(),
    ExamVault: await vault.getAddress(),
    AuditAnchor: await anchor.getAddress(),
    deployedAt: new Date().toISOString(),
    gateway: {
      orgName, orgId,
      orgAdmin: orgAdmin.address,
      controller: controller.address,
      analyst: analyst.address,
      anchorer: anchorer.address,
      custodians: custodians.map((c) => c.address),
      threshold: 3,
      freezeThreshold: 2,
    },
  };
  const dir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, network.name + ".json"), JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out, null, 2));
}
main().catch((e) => { console.error(e); process.exit(1); });
