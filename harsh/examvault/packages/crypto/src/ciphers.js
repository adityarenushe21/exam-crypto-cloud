"use strict";
const { subtle, randomBytes, concat } = require("./bytes");

// ───────────────────────── AES-256-GCM ─────────────────────────
// Packed layout: iv(12) || ciphertext || tag(16). AAD binds ciphertext to its context (paperId, centreId).

const generateDEK = () => randomBytes(32);

async function aesEncrypt(key32, plaintext, aad = new Uint8Array(0)) {
  if (key32.length !== 32) throw new Error("AES-256 requires a 32-byte key");
  const iv = randomBytes(12);
  const k = await subtle.importKey("raw", key32, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, k, plaintext));
  return concat(iv, ct);
}

async function aesDecrypt(key32, packed, aad = new Uint8Array(0)) {
  if (key32.length !== 32) throw new Error("AES-256 requires a 32-byte key");
  const iv = packed.slice(0, 12);
  const ct = packed.slice(12);
  const k = await subtle.importKey("raw", key32, "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, k, ct));
}

// ───────────────────────── RSA-OAEP (key wrapping of shares) ─────────────────────────

async function generateRsaKeyPair(bits = 3072) {
  return subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"]
  );
}
const rsaEncrypt = async (pub, data) => new Uint8Array(await subtle.encrypt({ name: "RSA-OAEP" }, pub, data));
const rsaDecrypt = async (priv, data) => new Uint8Array(await subtle.decrypt({ name: "RSA-OAEP" }, priv, data));

const exportRsaPublic = async (pub) => new Uint8Array(await subtle.exportKey("spki", pub));
const exportRsaPrivate = async (priv) => new Uint8Array(await subtle.exportKey("pkcs8", priv));
const importRsaPublic = (spki) =>
  subtle.importKey("spki", spki, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
const importRsaPrivate = (pkcs8) =>
  subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);

// ───────────────────────── ECDSA P-256 (digital signatures) ─────────────────────────
// Browser-native, so signing keys can be generated and kept client-side (private key never reaches the server).

const generateSigningKeyPair = () =>
  subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const sign = async (priv, data) => new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, data));
const verify = (pub, sig, data) => subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, sig, data);
const exportSigningPublic = async (pub) => new Uint8Array(await subtle.exportKey("spki", pub));
const importSigningPublic = (spki) =>
  subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
const exportSigningPrivate = async (priv) => new Uint8Array(await subtle.exportKey("pkcs8", priv));
const importSigningPrivate = (pkcs8) =>
  subtle.importKey("pkcs8", pkcs8, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);

module.exports = {
  generateDEK, aesEncrypt, aesDecrypt,
  generateRsaKeyPair, rsaEncrypt, rsaDecrypt, exportRsaPublic, exportRsaPrivate, importRsaPublic, importRsaPrivate,
  generateSigningKeyPair, sign, verify, exportSigningPublic, importSigningPublic, exportSigningPrivate, importSigningPrivate,
};
