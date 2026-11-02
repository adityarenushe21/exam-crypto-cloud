// ExamVault capstone project | Harsh Kapile | MIT World Peace University, Pune
// Module: blockchain integrity (smart contracts, chain gateway, ChronoSeal)
// SPDX-License-Identifier: MIT
"use strict";
const { utf8, toHex, concat } = require("./bytes");
const { sha256 } = require("./hash");
const { generateDEK, aesEncrypt, aesDecrypt, rsaEncrypt, rsaDecrypt } = require("./ciphers");
const shamir = require("./shamir");
const { MerkleTree, verifyProof, variantLeaf, shareLeaf, hex } = require("./merkle");
const { canonicalJson } = require("./audit");

const aadFor = (paperId, centreId) => utf8(`${paperId}|${centreId}`);
const h0x = (u8) => "0x" + toHex(u8);

/**
 * ChronoSeal – SEAL phase (runs once, inside the isolated sealing step).
 *   1. DEK <- CSPRNG (256-bit). Never persisted, never sent to KMS or the server's database.
 *   2. For every centre: optional watermark -> AES-256-GCM(DEK, AAD = paperId|centreId) -> SHA-256 variant hash.
 *   3. Variant commitments form a Merkle manifest  (root anchored on-chain with the release time).
 *   4. DEK is Shamir-split k-of-n; each share is RSA-OAEP-encrypted to one custodian; share hashes form a
 *      second Merkle tree (verifiable shares: a bad share is detectable and attributable).
 *   5. DEK and plaintext buffers are zeroised.
 */
async function sealPaper({ paperId, paperBytes, centres, custodians, threshold, watermark = null }) {
  const dek = generateDEK();
  try {
    const variants = [];
    for (const c of centres) {
      const plain = watermark ? await watermark(paperBytes, c.id) : paperBytes;
      const ciphertext = await aesEncrypt(dek, plain, aadFor(paperId, c.id));
      const centreIdHash = sha256(utf8(c.id));
      const variantHash = sha256(ciphertext);
      variants.push({
        centreId: c.id,
        centreIdHash: h0x(centreIdHash),
        ciphertext,
        variantHash: h0x(variantHash),
        _leaf: variantLeaf(centreIdHash, variantHash),
      });
    }
    const manifest = new MerkleTree(variants.map((v) => v._leaf));
    variants.forEach((v, i) => { v.proof = manifest.proof(i); delete v._leaf; });

    const shares = shamir.split(dek, custodians.length, threshold);
    const custodianPackages = [];
    const shareLeaves = [];
    for (let i = 0; i < custodians.length; i++) {
      const raw = shamir.encodeShare(shares[i]);
      const shareHash = sha256(raw);
      const encryptedShare = await rsaEncrypt(custodians[i].rsaPublicKey, raw);
      shareLeaves.push(shareLeaf(custodians[i].address, shareHash));
      custodianPackages.push({ address: custodians[i].address, x: shares[i].x, encryptedShare, shareHash: h0x(shareHash) });
      raw.fill(0);
    }
    const shareTree = new MerkleTree(shareLeaves);
    custodianPackages.forEach((p, i) => { p.proof = shareTree.proof(i); });

    const masterHash = h0x(
      sha256(utf8(canonicalJson({ paperId, variants: variants.map((v) => [v.centreIdHash, v.variantHash]) })))
    );

    shares.forEach((s) => s.y.fill(0));
    return {
      paperId,
      variants,
      manifestRoot: manifest.rootHex,
      custodianPackages,
      shareCommitRoot: shareTree.rootHex,
      masterHash,
      threshold,
    };
  } finally {
    dek.fill(0);
  }
}

/** RELEASE phase, step 1 (custodian's browser): decrypt own share, re-encrypt it to the centre's public key. */
async function custodianReencrypt({ custodianPrivateKey, encryptedShare, centrePublicKey }) {
  const raw = await rsaDecrypt(custodianPrivateKey, encryptedShare);
  try {
    return await rsaEncrypt(centrePublicKey, raw);
  } finally {
    raw.fill(0);
  }
}

/** Public check that a centre's ciphertext is the one sealed in the manifest (no key needed). */
function verifyVariantInManifest({ centreId, variantCiphertext, proof, manifestRoot }) {
  const leaf = variantLeaf(sha256(utf8(centreId)), sha256(variantCiphertext));
  return verifyProof(proof, manifestRoot, leaf);
}

/**
 * RELEASE phase, step 2 (centre superintendent's browser): unwrap shares, verify each against the sealed
 * commitment root, recombine the DEK, decrypt this centre's variant.
 * Returns { plaintext, usedShares, rejected } where rejected lists custodians whose share failed verification.
 */
async function centreOpen({
  centrePrivateKey, wrappedShares, variantCiphertext, paperId, centreId, shareCommitRoot, threshold,
}) {
  const good = [];
  const rejected = [];
  for (const w of wrappedShares) {
    try {
      const raw = await rsaDecrypt(centrePrivateKey, w.wrapped);
      const ok = !shareCommitRoot || verifyProof(w.proof, shareCommitRoot, shareLeaf(w.address, sha256(raw)));
      if (ok) good.push({ address: w.address, share: shamir.decodeShare(raw) });
      else rejected.push(w.address);
    } catch {
      rejected.push(w.address);
    }
  }
  if (good.length < threshold) {
    const e = new Error(`only ${good.length}/${threshold} valid shares`);
    e.rejected = rejected;
    throw e;
  }
  const dek = shamir.combine(good.slice(0, threshold).map((g) => g.share));
  try {
    const plaintext = await aesDecrypt(dek, variantCiphertext, aadFor(paperId, centreId));
    return { plaintext, usedShares: good.slice(0, threshold).map((g) => g.address), rejected };
  } finally {
    dek.fill(0);
  }
}

module.exports = { sealPaper, custodianReencrypt, centreOpen, verifyVariantInManifest, aadFor };
