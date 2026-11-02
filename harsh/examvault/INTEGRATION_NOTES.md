# Integration notes: Harsh's folder (added 2026-10-28)

## What was ADDED (no existing file was modified)

- `blockchain/gateway/`: the chain gateway (`core.js`, `server.js`, `README.md`, `test/`)
- `blockchain/scripts/setup-local.js`, `custodian-approve.js`, `custodian-freeze.js`
- `blockchain/test/Gateway.test.js`: gateway + real contracts
- this file

`contracts/*.sol`, `packages/crypto/*`, `deploy.js`, `benchmark-anchoring.js` and the
existing tests are **byte-for-byte unchanged**.

## Design decision used (needs team/guide confirmation)

**Option A:** Aditya's Option A crypto (ML-KEM-768 + HKDF + AES-256-GCM + SHA3-256 + ML-DSA-65)
encrypts and signs papers, and stores them in S3 or local storage. Harsh's contracts are the
**release-authorization and audit layer**:

- Every sealed paper is registered in ExamVault (`masterHash` = SHA3-256 of the ciphertext).
- The release service decrypts only when ExamVault says `RELEASED`, meaning 3 of 5 custodians
  approved after `releaseTime`. Frozen, revoked or compromised papers are blocked.
- Signed, hash-chained audit events are anchored with AuditAnchor.

ChronoSeal (`packages/crypto`: Shamir + RSA-OAEP + ECDSA) is **kept but not used** in this
flow. Its Merkle and keccak helpers **are** used by the gateway.

## Review notes on the existing code (no changes made)

1. The `ExamVault.Paper.masterHash` comment says SHA-256. In the integrated flow it holds
   **SHA3-256**. Please update the comment.
2. The contracts look careful: custom errors, round invalidation, asymmetric thresholds, and
   leaf/node domain separation. The gateway relies on `releaseApprovals(paperId, round)`,
   `getPaper`, `lastSeq` and `batchCount`, and needs nothing new.
3. ChronoSeal uses RSA-OAEP-3072 and ECDSA P-256, which are **not post-quantum**. If the team
   wants threshold custody *and* post-quantum crypto (option B), wrap each Shamir share with
   ML-KEM-768 instead of RSA-OAEP, and sign with ML-DSA-65 instead of ECDSA.
4. `shamir.js` is a hand-written GF(256) implementation. That's fine for a prototype, but say so
   in the report, and prefer an audited library for anything real.

## Test status

| Suite | Where | Result |
|---|---|---|
| `packages/crypto` (7 tests, unchanged) | Linux test sandbox, Node 22, Keccak stand-in for `@noble/hashes` | 7/7 pass |
| `gateway/test/core.test.js` (10) | Linux test sandbox, Node 22, fake contracts | 10/10 pass |
| Python ↔ gateway HTTP end-to-end | Linux test sandbox, gateway core + fake contracts | 13/13 steps correct |
| `npx hardhat test` (19 existing + 7 new) | **not run**: Hardhat unavailable in sandbox | run on your PC |

## Note about `git status`

In the zip as received, `git status` already showed all 23 original files as modified, with equal
insertions and deletions. That is a line-ending (CRLF vs LF) difference against the last commit,
and it is **not** from this integration. To see only the integration's changes, look for the
untracked files: `gateway/`, the three new scripts, `test/Gateway.test.js` and this file.
