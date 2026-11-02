// Chain gateway for examcrypto (Aditya's Python service).
//   Terminal A:  npx hardhat node
//   Terminal B:  npx hardhat run scripts/setup-local.js --network localhost   (once per chain start)
//   Terminal B:  npx hardhat run gateway/server.js --network localhost
// Listens on http://127.0.0.1:8546 (localhost only). Uses the unlocked Hardhat accounts
// recorded by setup-local.js - no private key is stored in this repository.
"use strict";
const fs = require("fs");
const path = require("path");
const hre = require("hardhat");
const { createHandler, createServer } = require("./core");

async function main() {
  const file = path.join(__dirname, "..", "deployments", hre.network.name + ".json");
  if (!fs.existsSync(file)) throw new Error(`missing ${file} - run scripts/setup-local.js first`);
  const d = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!d.gateway) throw new Error("deployment file has no 'gateway' section - run scripts/setup-local.js");

  const { ethers } = hre;
  const controller = await ethers.getSigner(d.gateway.controller);
  const anchorer = await ethers.getSigner(d.gateway.anchorer);
  const vault = (await ethers.getContractAt("ExamVault", d.ExamVault)).connect(controller);
  const anchor = (await ethers.getContractAt("AuditAnchor", d.AuditAnchor)).connect(anchorer);

  const handle = createHandler({
    vault, anchor,
    cfg: { orgId: d.gateway.orgId, custodians: d.gateway.custodians,
           threshold: d.gateway.threshold, freezeThreshold: d.gateway.freezeThreshold },
  });
  const port = Number(process.env.GATEWAY_PORT || 8546);
  createServer(handle).listen(port, "127.0.0.1", () => {
    console.log(`chain gateway on http://127.0.0.1:${port}  network=${hre.network.name}`);
    console.log(`ExamVault ${d.ExamVault}  AuditAnchor ${d.AuditAnchor}  org ${d.gateway.orgName}`);
  });
  await new Promise(() => {}); // keep running until Ctrl+C
}
main().catch((e) => { console.error(e.message || e); process.exit(1); });
