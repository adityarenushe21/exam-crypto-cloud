"use strict";
const { sha256: _sha256 } = require("@noble/hashes/sha256");
const { keccak_256 } = require("@noble/hashes/sha3");
const { toHex } = require("./bytes");

/** SHA-256 (the hash the synopsis specifies for encrypted papers and audit events). */
const sha256 = (u8) => _sha256(u8);
/** Keccak-256: used only for Merkle tree nodes so proofs verify cheaply inside the EVM. */
const keccak256 = (u8) => keccak_256(u8);
const sha256Hex = (u8) => "0x" + toHex(_sha256(u8));
const keccakHex = (u8) => "0x" + toHex(keccak_256(u8));

module.exports = { sha256, keccak256, sha256Hex, keccakHex };
