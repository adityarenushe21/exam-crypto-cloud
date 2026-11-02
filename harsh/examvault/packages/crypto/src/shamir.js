// ExamVault capstone project | Harsh Kapile | MIT World Peace University, Pune
// Module: blockchain integrity (smart contracts, chain gateway, ChronoSeal)
// SPDX-License-Identifier: MIT
"use strict";
const { randomBytes, concat } = require("./bytes");

// ───────────── GF(2^8) arithmetic (AES polynomial 0x11b, generator 3) ─────────────
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    let x2 = x << 1;
    if (x2 & 0x100) x2 ^= 0x11b;
    x ^= x2; // multiply by 3
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

const mul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);
const div = (a, b) => {
  if (b === 0) throw new Error("division by zero in GF(256)");
  return a === 0 ? 0 : EXP[LOG[a] + 255 - LOG[b]];
};

/** Lagrange basis value l_i(target) for the point set xs. */
function lagrangeAt(xs, i, target) {
  let num = 1, den = 1;
  for (let j = 0; j < xs.length; j++) {
    if (j === i) continue;
    num = mul(num, target ^ xs[j]);
    den = mul(den, xs[i] ^ xs[j]);
  }
  return div(num, den);
}

function checkShares(shares) {
  const xs = shares.map((s) => s.x);
  if (new Set(xs).size !== xs.length) throw new Error("duplicate share indices");
  if (xs.includes(0)) throw new Error("share index 0 is reserved for the secret");
  const len = shares[0].y.length;
  if (shares.some((s) => s.y.length !== len)) throw new Error("share length mismatch");
  return { xs, len };
}

/**
 * Split secret into n shares, any k of which reconstruct it (k-1 reveal nothing: information-theoretic).
 * Coefficients come from the CSPRNG. Returns [{x, y}].
 */
function split(secret, n, k, xs = null) {
  if (!(k >= 2 && k <= n && n <= 255)) throw new Error("need 2 <= k <= n <= 255");
  const points = xs || Array.from({ length: n }, (_, i) => i + 1);
  if (points.length !== n) throw new Error("xs length must equal n");
  const shares = points.map((x) => ({ x, y: new Uint8Array(secret.length) }));
  for (let b = 0; b < secret.length; b++) {
    const coeffs = [secret[b], ...randomBytes(k - 1)];
    for (const s of shares) {
      let acc = 0;
      for (let d = k - 1; d >= 0; d--) acc = mul(acc, s.x) ^ coeffs[d]; // Horner
      s.y[b] = acc;
    }
  }
  return shares;
}

/** Reconstruct the secret from >= k shares (Lagrange interpolation at x=0). */
function combine(shares) {
  const { xs, len } = checkShares(shares);
  const out = new Uint8Array(len);
  for (let i = 0; i < shares.length; i++) {
    const l = lagrangeAt(xs, i, 0);
    for (let b = 0; b < len; b++) out[b] ^= mul(shares[i].y[b], l);
  }
  return out;
}

const encodeShare = (s) => concat(Uint8Array.of(s.x), s.y);
const decodeShare = (u8) => ({ x: u8[0], y: u8.slice(1) });

// ───────────── Custodian rotation: blinded share extension ─────────────
// A new custodian needs a share at a fresh index WITHOUT anyone reconstructing the DEK.
// Each of k existing holders computes its Lagrange contribution c_i = l_i(newX) * y_i, then adds pairwise-
// cancelling random masks. Every blinded value is uniformly random on its own; the XOR (= GF(256) sum)
// of all of them equals f(newX). Masks are exchanged pairwise between holders in a real ceremony.

function blindedContributions(shares, newX) {
  const { xs, len } = checkShares(shares);
  if (xs.includes(newX)) throw new Error("newX collides with an existing index");
  const contribs = shares.map((s, i) => {
    const l = lagrangeAt(xs, i, newX);
    return Uint8Array.from(s.y, (b) => mul(b, l));
  });
  for (let i = 0; i < contribs.length; i++) {
    for (let j = i + 1; j < contribs.length; j++) {
      const m = randomBytes(len);
      for (let b = 0; b < len; b++) { contribs[i][b] ^= m[b]; contribs[j][b] ^= m[b]; }
    }
  }
  return contribs;
}

function assembleExtendedShare(blinded, newX) {
  const y = new Uint8Array(blinded[0].length);
  for (const c of blinded) for (let b = 0; b < y.length; b++) y[b] ^= c[b];
  return { x: newX, y };
}

// ───────────── Proactive refresh (Herzberg-style) ─────────────
// Every holder deals a random zero-constant polynomial; all holders add what they receive to their share.
// The secret is unchanged, but old shares are cryptographically incompatible with new ones, so a retired or
// compromised custodian's old share becomes useless.

function refresh(shares, k) {
  const { xs, len } = checkShares(shares);
  const updated = shares.map((s) => ({ x: s.x, y: Uint8Array.from(s.y) }));
  for (let dealer = 0; dealer < shares.length; dealer++) {
    const zero = split(new Uint8Array(len), shares.length, k, xs); // sharing of the all-zero secret
    zero.forEach((z, i) => { for (let b = 0; b < len; b++) updated[i].y[b] ^= z.y[b]; });
  }
  return updated;
}

module.exports = { split, combine, encodeShare, decodeShare, blindedContributions, assembleExtendedShare, refresh, _gf: { mul, div } };
