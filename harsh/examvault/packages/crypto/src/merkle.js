"use strict";
const { keccak256 } = require("./hash");
const { concat, fromHex, toHex, equal } = require("./bytes");

// Sorted-pair keccak256 tree, byte-for-byte compatible with OpenZeppelin MerkleProof.verify
// (used by ExamVault and AuditAnchor). Odd nodes are promoted unchanged to the next level.

const asBytes = (x) => (typeof x === "string" ? fromHex(x) : x);
const hex = (u8) => "0x" + toHex(u8);

const cmp = (a, b) => {
  for (let i = 0; i < 32; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
};
const hashPair = (a, b) => (cmp(a, b) <= 0 ? keccak256(concat(a, b)) : keccak256(concat(b, a)));

const pad32Address = (addr) => {
  const a = fromHex(addr);
  if (a.length !== 20) throw new Error("bad address");
  return concat(new Uint8Array(12), a);
};

// Leaf definitions (must match the Solidity side).
//  - variant / share leaves are double-hashed (64-byte preimage hashed once more) so a leaf can never be
//    confused with an internal node (second-preimage defence).
//  - audit leaves hash a 32-byte event hash once (32-byte preimage != 64-byte node preimage).
const variantLeaf = (centreIdHash, variantHash) =>
  keccak256(keccak256(concat(asBytes(centreIdHash), asBytes(variantHash))));
const shareLeaf = (custodianAddress, shareHash) =>
  keccak256(keccak256(concat(pad32Address(custodianAddress), asBytes(shareHash))));
const auditLeaf = (eventHash) => keccak256(asBytes(eventHash));

class MerkleTree {
  /** @param {Uint8Array[]} leaves  already-hashed leaves */
  constructor(leaves) {
    if (!leaves.length) throw new Error("empty tree");
    this.leaves = leaves.map(asBytes);
    this.levels = [this.leaves];
    while (this.levels[this.levels.length - 1].length > 1) {
      const cur = this.levels[this.levels.length - 1];
      const next = [];
      for (let i = 0; i < cur.length; i += 2) {
        next.push(i + 1 < cur.length ? hashPair(cur[i], cur[i + 1]) : cur[i]);
      }
      this.levels.push(next);
    }
  }
  get root() { return this.levels[this.levels.length - 1][0]; }
  get rootHex() { return hex(this.root); }

  /** Inclusion proof (array of 0x-hex siblings) for the leaf at index. */
  proof(index) {
    if (index < 0 || index >= this.leaves.length) throw new Error("leaf index out of range");
    const out = [];
    let idx = index;
    for (let l = 0; l < this.levels.length - 1; l++) {
      const level = this.levels[l];
      const sib = idx ^ 1;
      if (sib < level.length) out.push(hex(level[sib]));
      idx = idx >> 1;
    }
    return out;
  }
}

/** Verify a proof exactly as the EVM does. */
function verifyProof(proof, root, leaf) {
  let computed = asBytes(leaf);
  for (const p of proof) computed = hashPair(computed, asBytes(p));
  return equal(computed, asBytes(root));
}

module.exports = { MerkleTree, verifyProof, variantLeaf, shareLeaf, auditLeaf, hashPair, hex };
