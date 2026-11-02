# examcrypto — Integration Contract v1

Owner: Aditya Renushe (crypto + storage module). Last updated: 2026-10-28 (v2, integrated with Harsh's contracts).

**Status labels used below**
- **TESTED** — implemented and covered by automated tests (105 Python tests + 10 gateway tests pass in Claude's sandbox; Aditya's PC run pending).
- **PROPOSED** — the teammate has not confirmed it yet. Change it by talking to Aditya, not by editing code.
- **MOCK** — a stand-in that the teammate's real module will replace.

Nothing in this document has been agreed with Harsh, Ansh, Nayan or the guide yet.

---

## 1. For everyone: running the API locally

```powershell
python -m examcrypto init-keys      # once
python -m examcrypto dev-tokens     # once -> keys\dev_tokens.json (MOCK auth)
python -m examcrypto serve          # http://127.0.0.1:8000
```

- **Auth (MOCK):** send `Authorization: Bearer <token>` using a token from `keys\dev_tokens.json`.
  The roles are `exam_authority`, `release_officer`, `admin`, `auditor` and `student`.
- **Base path:** `/api/v1`. All times are UTC in the form `YYYY-MM-DDTHH:MM:SSZ`.
- **Every response** carries an `X-Request-Id` header, and JSON bodies include `request_id`.
- **Error body** (TESTED):
  `{"status":"FAILED","reason_code":"...","message":"...","request_id":"..."}`

## 2. Routes (TESTED, shape PROPOSED)

| Method | Path | Allowed roles | Success |
|---|---|---|---|
| GET | `/health` | anyone | 200 |
| POST | `/papers` | exam_authority | 201: multipart with `file`, `exam_id` and `release_at_utc` |
| POST | `/papers/{paper_id}/versions` | exam_authority | 201: same form, creates version n+1 |
| GET | `/papers/{paper_id}[?version=n]` | exam_authority, release_officer, admin, auditor | 200: status |
| GET | `/papers/{paper_id}/manifest[?version=n]` | same as above | 200: signed manifest (public data) |
| POST | `/papers/{paper_id}/release[?version=n]` | release_officer | 200: `application/pdf` |
| POST | `/papers/{paper_id}/anchor[?version=n]` | exam_authority | 200: re-send on-chain registration (if the chain was down at upload) |
| GET | `/events?limit=n` | admin, auditor | 200: latest events (max 1000) |
| POST | `/events/anchor` | admin | 200: anchors all not-yet-anchored events on-chain (contiguous batches) |
| GET | `/events/verify` | admin, auditor | 200: `{"ok":true,"checked":n,"signatures_checked":true}` or `{"ok":false,"bad_seq":k,"reason":"..."}` |
| POST | `/_demo/mock-chain/{paper_id}/approve` | — | DEMO ONLY: exists only with `EXAM_DEMO_MODE=1` and the mock chain |

**Upload response (201):**
```json
{"paper_id":"pap_b8cb81d91e3e033e","paper_version":1,"status":"SEALED",
 "ciphertext_sha3_256_hex":"afd70523...4d83","manifest_sha3_256_hex":"7f4df701...070a",
 "release_at_utc":"2026-12-01T09:00:00Z","signer_key_id":"d36489d6...","recipient_key_id":"8639fdee...",
 "blockchain_status":"MOCK_ANCHORED","blockchain_tx_id":"MOCK-8e85...","request_id":"..."}
```

**Status response (200):**
```json
{"paper_id":"pap_...","paper_version":1,"versions":[1],"exam_id":"CS301-ENDSEM",
 "created_at_utc":"...","release_at_utc":"...",
 "signature_status":"valid","integrity_status":"valid","release_status":"NOT_YET_RELEASABLE",
 "reason_code":null,"ciphertext_sha3_256_hex":"...","signer_key_id":"...",
 "blockchain":{"status":"MOCK_ANCHORED","tx_id":"MOCK-..."}}
```

Allowed values for each status field:
- `signature_status`: `valid`, `invalid`
- `integrity_status`: `valid`, `mismatch`, `not_checked`
- `release_status`: `NOT_YET_RELEASABLE` (before time), `AWAITING_CUSTODIANS` (time passed, fewer than 3 approvals), `RELEASABLE`, `BLOCKED` (frozen/revoked/compromised, tampering, or chain record mismatch)
- `blockchain.status` (from ExamVault): `SEALED`, `FROZEN`, `RELEASED`, `REVOKED`, `COMPROMISED`; `blockchain.found=false` if not registered; `UNAVAILABLE` if the chain cannot be reached
- `blockchain_status` in the upload response: `ANCHORED` (real chain), `MOCK_ANCHORED` (mock), `FAILED` (retry with `/anchor`)

### HTTP status codes (TESTED)

| HTTP | reason_code |
|---|---|
| 400 | INVALID_INPUT |
| 401 | AUTH_REQUIRED |
| 403 | ROLE_NOT_ALLOWED |
| 404 | PAPER_NOT_FOUND, NOT_FOUND (unknown route) |
| 405 | METHOD_NOT_ALLOWED |
| 409 | DUPLICATE_VERSION, CHAIN_UNKNOWN_PAPER |
| 413 | FILE_TOO_LARGE (limit 20 MB) |
| 415 | NOT_A_PDF |
| 422 | SIGNATURE_INVALID, UNTRUSTED_SIGNER, CIPHERTEXT_DIGEST_MISMATCH, DECRYPTION_AUTHENTICATION_FAILED, WRONG_RECIPIENT_KEY, MANIFEST_MALFORMED, UNSUPPORTED_VERSION, CHAIN_RECORD_MISMATCH |
| 423 | RELEASE_TIME_NOT_REACHED, CHAIN_NOT_RELEASED, CHAIN_PAPER_BLOCKED |
| 503 | CHAIN_UNAVAILABLE, STORAGE_UNAVAILABLE (fail closed: nothing is released) |
| 500 | INTERNAL_ERROR (no details are ever returned) |

---

## 3. Nayan — dashboard and access control

- **Paper status screen:** use `GET /papers/{id}` and display the status fields from section 2.
  Show `BLOCKED` in red, with the `reason_code` next to it.
- **Audit timeline:** use `GET /events`.
- **Never show:** PDF content, keys, tokens or the full manifest crypto fields. They aren't secret, but they're noise for users.
- **Auth (MOCK):** the dev tokens stand in for real users. When your login or JWT is ready, it only needs to give my API an `actor_id` and a `role`.
  The role names above are PROPOSED; tell me your names and I'll map them.
- **Security:** hiding a button is not access control. My backend already refuses wrong roles with 403, regardless of what the UI shows.
- **Open questions:**
  1. Does the dashboard ever download the released PDF, or only show status?
  2. Which final role names do you want?

## 4. Harsh — blockchain (INTEGRATED with his real contracts; contracts unchanged)

**How it fits together:** Python never holds an Ethereum key. examcrypto calls Harsh's
**chain gateway** (`harsh/examvault/blockchain/gateway/`, Node + ethers via Hardhat) on
`http://127.0.0.1:8546`. The gateway signs transactions with the Controller and Anchorer
accounts written by `scripts/setup-local.js`.

| examcrypto record | ExamVault.sealPaper field |
|---|---|
| `"<paper_id>:v<version>"` | `paperId = keccak256(utf8(...))` (same as `ethers.id`) |
| SHA3-256(ciphertext.bin) | `masterHash` (bytes32, stored as-is, NOT recomputed) |
| one variant, centre `"CENTRAL"` | `manifestRoot = variantLeaf(sha256("CENTRAL"), masterHash)` (1-leaf tree, empty proof) |
| no Shamir in Option A | `shareCommitRoot = 0x00…00` |
| signed `release_at_utc` | `releaseTime` (unix seconds) |
| gateway config | `orgId`, 5 `custodians`, `threshold = 3`, `freezeThreshold = 2` |

**Release rule (TESTED):** examcrypto releases only if ALL of these hold:
1. The signed release time has passed.
2. ExamVault says `RELEASED`, meaning 3 of 5 custodians approved after `releaseTime`.
3. The on-chain `masterHash` equals the signed ciphertext digest.
4. The on-chain `releaseTime` is not earlier than the signed time.

`FROZEN`, `REVOKED` and `COMPROMISED` block release. If the chain is unreachable, release fails closed with 503.
The ML-KEM private key is unlocked only after all of these checks pass.

**Rescheduling:** the contract can only move the release time *later*. examcrypto's signed time
cannot move, so the later of the two always wins.

**Audit anchoring (TESTED with fakes, real-contract test included):** examcrypto events have
`seq`, `prev_hash`, `event_hash` (SHA3-256) and an ML-DSA-65 signature. `POST /events/anchor`
sends contiguous `event_hash` batches. The gateway builds Harsh's Merkle tree
(`auditLeaf(eventHash)`) and calls `AuditAnchor.anchorBatch`, after which
`verifyInclusion(orgId, batch, eventHash, proof)` works on-chain.

**Gateway HTTP API:**
- `POST /papers/seal`
- `GET /papers/{paper_id}/{version}`
- `POST /audit/anchor`
- `GET /audit/last-seq`
- `GET /health`

See `harsh/examvault/blockchain/gateway/README.md`.

**Open questions for Harsh:**
1. ChronoSeal (Shamir + RSA + ECDSA) is kept but is not used in the integrated flow. Should it
   be a documented alternative, or should it be upgraded to ML-KEM/ML-DSA (option B)?
2. The contract comment says `masterHash` is SHA-256; in the integrated flow it holds SHA3-256.
   Update the comment.
3. Should exam centres become real variants later (more leaves in `manifestRoot`)?

## 5. AI threat detection (IMPLEMENTED in `ansh/threatdetect`, originally Ansh's role)

The consumer described below now exists: see `ansh/README.md`. It reads exactly this event feed, verifies the hash chain, writes `alerts/alerts.jsonl`, and flags HIGH alerts on-chain through the gateway's `POST /risk/flag`.


- **Event feed (TESTED):** one JSON object per line in `local_storage\events\events.jsonl`, also available from `GET /events`.
  Exactly one event is written per API call, including denied and failed calls.

```json
{"schema_version":"2","seq":6,"prev_hash":"9f2c...","event_hash":"41ab...","signature_b64":"...",
 "event_id":"6f1c...","event_type":"RELEASE_REQUEST","timestamp_utc":"2026-10-28T13:03:47Z",
 "source_component":"crypto_api","request_id":"...","actor_id":"dev-release_officer",
 "actor_role":"release_officer","result":"DENIED","reason_code":"CHAIN_NOT_RELEASED",
 "paper_id":"pap_0b772e0a21b9ab44"}
```
Fields with no value are **left out**, not sent as `null`. Use `.get("reason_code")`.
`seq`, `prev_hash`, `event_hash` and `signature_b64` make the log tamper-evident. Your model can ignore them.

- **Field values:**
  - `event_type`: `UPLOAD`, `STATUS_CHECK`, `MANIFEST_READ`, `RELEASE_REQUEST`, `AUTH`, `ANCHOR`
  - `result`: `SUCCESS`, `DENIED` (a policy said no), `FAILED` (bad data or an integrity problem)
  - `reason_code`: the codes listed in section 2
- **Fields are whitelisted (TESTED):** plaintext, keys, tokens and crypto parameters can never appear in events.
- **Useful features for your model:** failed or denied counts per `actor_id`; `RELEASE_TIME_NOT_REACHED` / `CHAIN_NOT_RELEASED` bursts;
  `SIGNATURE_INVALID` or `CIPHERTEXT_DIGEST_MISMATCH` (these suggest tampering); unusual hours; role and action mismatches.
- **Your model gives a signal, not a decision.** My checks refuse bad requests regardless of the model's score.
- **Open questions:**
  1. Do you need IP or device fields? They aren't collected now (privacy).
  2. Should your service push alerts to Nayan, or should I call your `score(event)` function?
  3. Harsh's `AuditAnchor.flagRisk(orgId, subjectHash, score, reasonHash, eventHash)` can record
     your high-risk flags on-chain. The gateway does not expose it yet; agree on the fields first.
