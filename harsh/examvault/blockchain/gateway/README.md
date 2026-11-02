# Chain gateway (ExamVault/AuditAnchor <-> examcrypto)

A small localhost HTTP service that lets Aditya's Python crypto service (examcrypto) use
these contracts **without the contracts being changed**. It runs inside this Hardhat
project, so it uses the existing dependencies (ethers v6 via Hardhat, plus `packages/crypto`
for Merkle trees). It adds no new npm packages.

| File | Purpose |
|---|---|
| `core.js` | All logic: record → `SealParams` mapping, status view, audit batches, HTTP wrapper |
| `server.js` | Wires `core.js` to the deployed contracts and Hardhat's unlocked accounts |
| `test/core.test.js` | 11 unit tests with fake contracts: `node --test gateway/test/core.test.js` |
| `test/fakes.js` | Test-only in-memory ExamVault/AuditAnchor |
| `../test/Gateway.test.js` | 8 integration tests against the **real** contracts (runs inside `npx hardhat test`) |
| `../scripts/setup-local.js` | Deploy + register org + grant roles + write the `gateway` section |
| `../scripts/custodian-approve.js` | 3 custodians approve release (`$env:PAPER_ID=...`) |
| `../scripts/custodian-freeze.js` | 2 custodians freeze a paper |

## HTTP API (localhost:8546)

| Method | Path | Body / result |
|---|---|---|
| GET | `/health` | org id, threshold, custodian count |
| POST | `/papers/seal` | examcrypto record → `{tx_id, chain_paper_id, manifest_root}`; 409 PaperExists, 400 BadParam, 403 NotController |
| GET | `/papers/{paper_id}/{version}` | `{found, status, release_at_unix, master_hash, approvals, threshold, ...}`; 404 if unknown |
| POST | `/audit/anchor` | `{first_seq, last_seq, event_hashes[], critical}` → `{tx_id, batch_index, root}`; 409 BadRange with `expected_first_seq` |
| GET | `/audit/last-seq` | `{last_seq}` |
| POST | `/risk/flag` | `{subject_hash, score 0-100, reason_hash, event_hash}` → `AuditAnchor.flagRisk` → `{tx_id, flag_index}` (used by the AI module for HIGH alerts) |

## Mapping (see core.js header)

- `paperId = keccak256(utf8("<paper_id>:v<version>"))`
- `masterHash` = examcrypto's SHA3-256(ciphertext)
- `manifestRoot` = 1-leaf tree of `variantLeaf(sha256("CENTRAL"), masterHash)`
- `shareCommitRoot = 0x0`, `releaseTime` = the signed release time
- custodians, threshold and org come from `deployments/<network>.json`

## Status of testing

- `core.test.js` (10 tests) **passed in the Linux test sandbox** with Node 22. Because npm was blocked
  there, `@noble/hashes` was replaced by a test-only Keccak stand-in, checked against the
  published Keccak-256 test values.
- `Gateway.test.js` and the scripts have **not been run yet** (Hardhat could not be installed in
  the sandbox). Run `npx hardhat test` on a real PC and record the result.
