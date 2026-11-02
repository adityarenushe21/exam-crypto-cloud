# ExamVault: Secure Examination Paper Distribution and Audit System

B.Tech capstone project, MIT World Peace University, Pune. Guide: **Shital Kakad**.

Exam papers are encrypted with **post-quantum cryptography** and can be opened only when two things
are true: the **release time has passed**, and **3 of 5 custodians have approved on a blockchain**.
Every action goes into a **signed, tamper-evident audit log**. An **AI threat detector** watches that
log, and an **administrator dashboard** is where alerts are reviewed and access is controlled.

> This is a student prototype. It has not had a security audit and is not a production system.
>
> **Team change:** Ansh and Nayan left the project. Their modules (`ansh/`, `nayan/`) were built by
> Aditya, and Aditya and Harsh now maintain them.

📄 **Full project report:** [docs/REPORT.md](docs/REPORT.md) · ▶️ **How to run:** [HOW_TO_RUN_EVERYTHING.md](HOW_TO_RUN_EVERYTHING.md)

![Admin overview](nayan/docs/screenshots/05_admin_overview.png)

---

## Contents

1. [Architecture at a glance](#1-architecture-at-a-glance)
2. [Components](#2-components)
3. [How a paper is sealed](#3-how-a-paper-is-sealed)
4. [How a paper is released](#4-how-a-paper-is-released)
5. [Cryptographic design](#5-cryptographic-design)
6. [Data formats](#6-data-formats)
7. [Audit log, anchoring and AI monitoring](#7-audit-log-anchoring-and-ai-monitoring)
8. [Access control](#8-access-control)
9. [Trust boundaries and threat model](#9-trust-boundaries-and-threat-model)
10. [Repository layout](#10-repository-layout)
11. [APIs](#11-apis)
12. [Technology stack](#12-technology-stack)
13. [Testing](#13-testing)
14. [Quick start](#14-quick-start-windows-powershell)
15. [Honest status and limitations](#15-honest-status-and-limitations)
16. [Team and attribution](#16-team-and-attribution)

---

## 1. Architecture at a glance

```mermaid
flowchart LR
  U[Browser dashboard] -->|login, upload, release, review| CC
  subgraph CC["controlcenter server (one Python process)"]
    AUTH["nayan · access control<br/>accounts, MFA, sessions,<br/>restrictions, alert review"]
    API["aditya · examcrypto API<br/>ML-KEM-768 + HKDF + AES-256-GCM<br/>SHA3-256 + ML-DSA-65"]
    AI["ansh · AI watcher<br/>rules + Isolation Forest + Random Forest"]
  end
  API -->|ciphertext + signed manifest| ST[(local disk / private S3)]
  API -->|signed, hash-chained events| LOG[(audit log JSONL)]
  AUTH -->|login + admin events| LOG
  LOG --> AI -->|alerts| AUTH
  API <-->|register paper, check RELEASED| GW["harsh · chain gateway (Node, :8546)"]
  API -->|anchor event batches| GW
  AI -->|HIGH alerts, pseudonymised| GW
  GW <--> BC["OrgRegistry · ExamVault · AuditAnchor<br/>(Solidity on Hardhat / Ethereum)"]
  C[5 custodians] -->|approve 3-of-5 after release time| BC
```

Four modules sit in one repository. In normal use one Python process (`controlcenter serve`) hosts
the dashboard, the login and admin API, the paper API, and the AI watcher thread. The blockchain sits
behind a small Node gateway, so Python never holds an Ethereum private key.

**Release rule.** Every check below must pass, in this order. The first failure stops the release
(fail closed). The contract itself accepts custodian approvals only once the *block time* has
passed the release time, so a wrong server clock alone cannot open a paper:

> right role → manifest is well formed → signer is the trusted key → ML-DSA signature valid → stored
> ciphertext matches the **signed** SHA3-256 digest → **signed** release time has passed →
> **ExamVault reports `RELEASED` (3 of 5 custodians)** and the on-chain hash matches → **only then** is the ML-KEM private key unlocked to decrypt.

## 2. Components

| Folder | Module | What it does | Owner | Tests |
|---|---|---|---|---|
| [`aditya/`](aditya/README.md) | **examcrypto** | Secure upload, post-quantum hybrid encryption, write-once storage (local or S3), release service, REST API, signed audit events | Aditya | 107 Python |
| [`harsh/examvault/`](harsh/examvault/README.md) | **Blockchain integrity** | Smart contracts `OrgRegistry`, `ExamVault` (k-of-n custodian release, freeze or revoke), `AuditAnchor` (Merkle batches, risk flags); chain gateway; ChronoSeal JS crypto library | Harsh | 27 Hardhat, 11 gateway, 7 crypto |
| [`ansh/`](ansh/README.md) | **threatdetect** | Turns audit events into features, scores them with rules + Isolation Forest + Random Forest, and explains each alert. Stores alerts append-only and flags HIGH alerts on-chain under a pseudonym | (Ansh) → Aditya | 27 Python |
| [`nayan/`](nayan/README.md) | **controlcenter** | Accounts, scrypt passwords, TOTP MFA, lockout, sessions, restrictions, alert review, admin API, dashboard, one-process server | (Nayan) → Aditya | 32 Python + 16 browser checks |

```mermaid
flowchart TB
  subgraph nayan["nayan/controlcenter"]
    server --> admin_api --> auth
    auth --> users & sessions & restrictions & totp & passwords
    server --> web["web/ (index.html, app.js, style.css)"]
  end
  subgraph aditya["aditya/examcrypto"]
    api --> service --> pipeline
    pipeline --> kem & kdf & aead & hashing & signatures & manifest
    service --> storage & blockchain & events & keystore & authz
  end
  subgraph ansh["ansh/threatdetect"]
    watcher --> features --> scoring
    scoring --> rules & model
    watcher --> alerts & chainflag
  end
  subgraph harsh["harsh/examvault"]
    gateway["blockchain/gateway (core.js, server)"] --> contracts["contracts/*.sol"]
    chronoseal["packages/crypto (ChronoSeal)"]
  end
  server --> api
  server --> watcher
  auth -->|authenticator hook| api
  blockchain -->|HTTP JSON| gateway
  chainflag -->|HTTP JSON| gateway
```

## 3. How a paper is sealed

```mermaid
sequenceDiagram
  autonumber
  actor EA as Exam authority
  participant CC as controlcenter (auth)
  participant EC as examcrypto
  participant ST as Storage (disk/S3)
  participant GW as Chain gateway
  participant EV as ExamVault contract
  participant LOG as Audit log
  EA->>CC: POST /api/v1/papers (PDF, exam_id, release_at_utc) + session
  CC->>CC: session valid? role exam_authority? not restricted?
  CC->>EC: authenticated request
  EC->>EC: ML-KEM-768 encapsulate to release public key → shared secret
  EC->>EC: HKDF-SHA-256(shared secret, random salt, info=paper id+version) → AES key
  EC->>EC: AES-256-GCM encrypt (fresh 96-bit nonce, AAD = ids + release time)
  EC->>EC: SHA3-256(ciphertext), build manifest, ML-DSA-65 sign
  EC->>ST: write-once ciphertext.bin + manifest.json (plaintext is never stored)
  EC->>GW: POST /papers/seal (paperId, masterHash, release time, 5 custodians, k=3)
  GW->>EV: sealPaper(...)
  EV-->>GW: tx hash, block
  EC->>LOG: UPLOAD event (hash-chained, ML-DSA signed)
  EC-->>EA: 201 paper_id, status SEALED, blockchain_status ANCHORED
```

If the chain is down at upload time, the paper is still stored, with `blockchain_status: PENDING`.
`POST /papers/{id}/anchor` sends the registration again later. A paper that is not registered on
the chain can **never** be released.

## 4. How a paper is released

```mermaid
sequenceDiagram
  autonumber
  actor RO as Release officer
  actor CU as Custodians (5)
  participant EV as ExamVault
  participant EC as examcrypto
  participant KS as Keystore
  CU->>EV: approveRelease(paperId) (contract rejects it before releaseTime)
  Note over EV: 3rd approval → status RELEASED
  RO->>EC: POST /papers/{id}/release
  EC->>EC: role · manifest schema · trusted signer · ML-DSA verify
  EC->>EC: SHA3-256(stored ciphertext) == signed digest?
  EC->>EC: now ≥ signed release_at_utc?
  EC->>EV: getPaper(paperId) via gateway
  EV-->>EC: status, masterHash, approvals, chain time
  EC->>EC: RELEASED? masterHash == signed digest? not frozen/revoked?
  EC->>KS: unlock ML-KEM private key (scrypt-stretched passphrase)
  EC->>EC: decapsulate → HKDF → AES-GCM decrypt (tag checks AAD too)
  EC-->>RO: 200 application/pdf
```

The error codes are specific, so the dashboard and the AI can tell probing apart from honest mistakes:

| HTTP | Examples |
|---|---|
| 401 / 403 | `AUTH_REQUIRED`, `ROLE_NOT_ALLOWED`, `ACCOUNT_RESTRICTED` |
| 422 | `SIGNATURE_INVALID`, `UNTRUSTED_SIGNER`, `CIPHERTEXT_DIGEST_MISMATCH`, `DECRYPTION_AUTHENTICATION_FAILED`, `CHAIN_RECORD_MISMATCH` |
| 423 | `RELEASE_TIME_NOT_REACHED`, `CHAIN_NOT_RELEASED`, `CHAIN_PAPER_BLOCKED` |
| 503 | `CHAIN_UNAVAILABLE`, `STORAGE_UNAVAILABLE` (fail closed: nothing is released) |

Custodians can also **freeze** or **revoke** a paper on-chain. A k-of-n proposal does this, for
example when a leak is suspected. Release is then refused with `CHAIN_PAPER_BLOCKED`.

## 5. Cryptographic design

"Option A" uses only standardised algorithms:

| Purpose | Algorithm | Standard | Why |
|---|---|---|---|
| Key encapsulation | **ML-KEM-768** | NIST FIPS 203 | Post-quantum; a harvest-now-decrypt-later attacker cannot open papers later |
| Key derivation | **HKDF-SHA-256** | RFC 5869 | Binds the AES key to the paper id and version (`info`) and a random salt |
| Content encryption | **AES-256-GCM** | NIST SP 800-38D | Authenticated encryption; AAD binds the public metadata (ids, release time) |
| Integrity hash | **SHA3-256** | NIST FIPS 202 | Ciphertext digest; also the on-chain `masterHash` |
| Signatures | **ML-DSA-65** | NIST FIPS 204 | Post-quantum signatures on manifests and audit events, with separate keys |
| Key-file protection | **scrypt** (N=2¹⁵, r=8, p=1) → PKCS#8 PBES2 | RFC 7914 | Slows down passphrase guessing if the key folder is stolen |
| Passwords | **scrypt** + per-user salt | RFC 7914 | Dashboard accounts |
| MFA | **TOTP** (HMAC-SHA1, 30 s, ±1 step, replay-blocked) | RFC 6238 | Works with standard authenticator apps |

```mermaid
flowchart LR
  PK[Release ML-KEM-768 public key] --> ENC[Encapsulate]
  ENC --> SS[shared secret 32 B] & KC[KEM ciphertext 1088 B]
  SS --> HK["HKDF-SHA-256<br/>salt: random 32 B<br/>info: protocol|v1|paper_id|version"]
  HK --> K[AES-256 key]
  PDF[PDF plaintext] --> GCM["AES-256-GCM<br/>nonce: random 12 B<br/>AAD: ids + exam_id + release_at"]
  K --> GCM --> CT[ciphertext + 16 B tag]
  CT --> H[SHA3-256] --> D[digest]
  KC & D & meta[metadata] --> M[manifest] --> SIG["ML-DSA-65 sign<br/>context: exam-crypto-cloud/manifest/v1"]
```

**How this differs from the original PPT plan.** The plan named AES-256, SHA-256 and RSA. RSA and
ECDSA can be broken by a large quantum computer, and an exam archive must stay confidential, so we
moved to the NIST post-quantum standards from 2024. AES-256 stays because it is quantum-resistant at
this key size. Harsh's ChronoSeal library (AES-256-GCM, Shamir secret sharing, Merkle trees,
RSA-OAEP, ECDSA) is kept as a tested alternative design. The integrated system uses Option A.

## 6. Data formats

**Storage layout** (write-once; the same keys are used locally and on S3):

```
papers/<paper_id>/v<version>/ciphertext.bin     AES-GCM ciphertext + tag
papers/<paper_id>/v<version>/manifest.json      {"manifest": {...}, "signature_b64": "..."}
events/events.jsonl                             signed, hash-chained audit events
access/restrictions.jsonl                       append-only restriction history
alerts/alerts.jsonl                             append-only alert history
```

**Manifest v1** (strict schema; unknown or missing fields are rejected):
`schema_version, paper_id, paper_version, exam_id, created_at_utc, release_at_utc, content_type,
plaintext_size, kem_algorithm, recipient_key_id, kem_ciphertext_b64, kdf_algorithm, hkdf_salt_b64,
hkdf_info, aead_algorithm, aes_gcm_nonce_b64, aad, hash_algorithm, ciphertext_sha3_256_hex,
signature_algorithm, signature_context, signer_key_id`

**Audit event**: `event_id`, `event_type`, `timestamp_utc`, `source_component`, `request_id`,
`actor_id`, `actor_role`, `result`, `reason_code`, paper fields (`paper_id`, `paper_version`,
`exam_id`, digests) and admin fields (`action`, `target_actor_id`, `alert_id`), plus the chain
fields `seq`, `prev_hash`, `event_hash`. The `event_hash` is SHA3-256 of the canonical JSON, and an ML-DSA-65 signature is made with the
**audit** key, which is separate from the manifest key.

**On-chain paper record** (ExamVault): `paperId = keccak256("<paper_id>:v<n>")`, `masterHash`
(the SHA3-256 digest), `manifestRoot`, `releaseTime`, custodian set, threshold, status
(`SEALED → RELEASED`, or `FROZEN` / `REVOKED`).

## 7. Audit log, anchoring and AI monitoring

```mermaid
flowchart LR
  E[Every API/login/admin action] --> L["events.jsonl<br/>seq · prev_hash · event_hash · ML-DSA sig"]
  L -->|"verify chain + signatures first"| W[AI watcher]
  W --> F["18 features per event<br/>(per-actor sliding windows)"]
  F --> R[8 rules] & IF[Isolation Forest] & RF[Random Forest]
  R & IF & RF --> S["risk = max(rule, 100·P_rf, 65·anomaly)"]
  S -->|≥40 MEDIUM / ≥70 HIGH| A[alerts.jsonl + exact explanation]
  A --> D[Dashboard: review, close with note, restrict user]
  A -->|HIGH only| P["AuditAnchor.flagRisk<br/>(HMAC-SHA3 pseudonym, no names on-chain)"]
  L -->|batches| AN["AuditAnchor.anchorBatch<br/>Merkle root of event hashes"]
```

- **Tamper evidence.** Changing, deleting or reordering any event breaks the hash chain or a
  signature, and `GET /events/verify` reports the first bad `seq`. Batches anchored on-chain mean
  that even an administrator who rewrites the whole file is detected.
- **Detectors.** Rules catch known patterns, for example `INTEGRITY_FAILURE`,
  `AUTH_FAILURE_BURST`, `EARLY_RELEASE_PROBING`, `ROLE_PROBING`, `BLOCKED_PAPER_ACCESS` and
  `OFF_HOURS_BULK_ACCESS`. The Random Forest learns labelled patterns. Isolation Forest catches
  unusual behaviour that nobody labelled, but it is capped at MEDIUM so it can never trigger a
  restriction by itself.
- **Explanations.** The PPT planned SHAP. We use **exact** explanations instead: which rules fired,
  plus the Random Forest's decision-path feature contributions. These are exact for tree models, and
  they avoid a heavy dependency.
- **Humans decide.** HIGH means `TEMPORARY_RESTRICT` is *recommended*. An administrator reviews
  the alert and can apply a restriction from the alert in one click. Closing an alert requires a note.

## 8. Access control

| Role | Can |
|---|---|
| `exam_authority` | upload papers and new versions; view status |
| `release_officer` | release a paper (only once every check passes) |
| `admin` | manage users, restrictions and alerts; anchor events; view everything |
| `auditor` | read-only: events, verification, alerts, papers |

- Passwords: scrypt with a password policy. MFA: TOTP, with each code usable only once.
- **Lockout**: 5 failures in 15 minutes lock the account for 15 minutes. An unknown user gets the
  same error and timing as a wrong password, so attackers cannot discover usernames.
- **Sessions**: random tokens, stored only as SHA-256 hashes. They expire after 30 minutes idle or
  8 hours in total. Logout and restriction revoke them.
- **Restrictions**: append-only and they can expire. They are checked on **every request**, not
  only at login. An admin cannot restrict themselves or the last other active admin.
- **Dashboard**: vanilla JS with a strict Content-Security-Policy (no inline script) and
  `textContent` only, so no HTML injection is possible.

## 9. Trust boundaries and threat model

```mermaid
flowchart TB
  subgraph T1["Trusted: server host"]
    KS[(keys: ML-KEM + ML-DSA, scrypt-protected)]
    APP[controlcenter + examcrypto + watcher]
  end
  subgraph T2["Semi-trusted: storage (disk / S3)"]
    OBJ[(ciphertext + signed manifests)]
  end
  subgraph T3["Trust-minimised: blockchain"]
    CHAIN[(ExamVault / AuditAnchor)]
  end
  subgraph T4["Untrusted: network & browsers"]
    USERS[users, attackers]
  end
  USERS -->|HTTPS in production, sessions + MFA| APP
  APP --> OBJ
  APP --> CHAIN
  APP --- KS
```

| Threat | Mitigation | Tested by |
|---|---|---|
| Stolen storage bucket or disk | Only ciphertext is stored; the key is never in storage | pipeline tests, S3 fake-client tests |
| Tampered ciphertext or manifest | SHA3 digest inside the ML-DSA-signed manifest; GCM tag | insider-attack tests |
| Insider re-signs a manifest with their own key | Trusted signer key id is pinned; `UNTRUSTED_SIGNER` | `test_attacker_resigns_*`, `test_*_resigned` |
| Early release (clock or insider) | Signed release time **and** k-of-n custodian approval on-chain; chain time checked | chain-rule tests, real Hardhat run |
| Single rogue custodian or admin | 3-of-5 threshold; admin role cannot release | Hardhat tests, API role tests |
| Swapping the paper after sealing | On-chain `masterHash` must equal the signed digest | `CHAIN_RECORD_MISMATCH` tests |
| Audit log edited after the fact | Hash chain + ML-DSA signatures + on-chain Merkle anchors | audit-chain tests |
| Password guessing / credential stuffing | scrypt, lockout, TOTP, AI `AUTH_FAILURE_BURST` | controlcenter tests, mutation tests |
| Stolen session token | Hashed at rest, idle and absolute expiry, revoked on restriction | session tests |
| Stolen key folder | scrypt-stretched passphrase (N=2¹⁵) before PKCS#8 encryption | `test_passphrase_is_scrypt_stretched` |
| Future quantum attacker | ML-KEM-768 and ML-DSA-65 | — (by design) |

**Out of scope:** leaks after a legitimate release (photos of a printed paper), a fully compromised
server host while it is running, and side channels. As the PPT said, the system reduces risk inside
the digital workflow. It does not claim to stop leaks outside it.

## 10. Repository layout

```
exam-crypto-cloud/
├── README.md                     ← you are here (architecture)
├── docs/REPORT.md                ← full capstone report
├── HOW_TO_RUN_EVERYTHING.md      ← step-by-step guide (tests, demo, real chain, S3)
├── run_all_tests.py              ← runs every suite, prints PASS/FAIL table
├── aditya/                       examcrypto: crypto, storage, release service, API, audit events
│   ├── examcrypto/               kem, kdf, aead, hashing, signatures, manifest, pipeline, service,
│   │                             storage, blockchain, events, keystore, authz, api, cli
│   ├── tests/                    107 tests      scripts/benchmark.py
│   └── docs/                     API_CONTRACT.md, AWS_S3_SETUP.md
├── harsh/examvault/
│   ├── blockchain/contracts/     OrgRegistry.sol, ExamVault.sol, AuditAnchor.sol
│   ├── blockchain/gateway/       Node HTTP gateway (Python ↔ chain)
│   ├── blockchain/scripts/       setup-local, custodian-approve, custodian-freeze
│   └── packages/crypto/          ChronoSeal library
├── ansh/threatdetect/            schema, features, rules, model, scoring, watcher, alerts,
│                                 chainflag, synthetic, evaluate, cli   (+ reports/evaluation.md)
└── nayan/controlcenter/          passwords, totp, users, sessions, restrictions, auth,
                                  admin_api, server, cli, web/   (+ docs/screenshots/)
```

## 11. APIs

**Paper API** (examcrypto, `/api/v1`). Full contract: [aditya/docs/API_CONTRACT.md](aditya/docs/API_CONTRACT.md)

| Method | Path | Role |
|---|---|---|
| POST | `/papers` · `/papers/{id}/versions` | exam_authority |
| GET | `/papers/{id}` · `/papers/{id}/manifest` | authority, officer, admin, auditor |
| POST | `/papers/{id}/release` | release_officer |
| POST | `/papers/{id}/anchor` | exam_authority |
| GET | `/events` · `/events/verify` | admin, auditor |
| POST | `/events/anchor` | admin |

**Control-centre API** (controlcenter): `POST /auth/login|logout`, `GET /auth/me`,
`GET /dashboard/overview|papers`, `GET /alerts`, `POST /alerts/{id}/review|restrict`,
`GET|POST /access/users`, `POST /access/users/{u}/restrict|unrestrict`, `GET /access/restrictions`,
`GET /system/health`.

**Chain gateway** (Node, `:8546`): `POST /papers/seal`, `GET /papers/{id}/{v}`, `POST /audit/anchor`,
`GET /audit/last-seq`, `POST /risk/flag`.

## 12. Technology stack

| Layer | Used | Planned in the PPT |
|---|---|---|
| Crypto | Python `cryptography` 46+ (ML-KEM, ML-DSA, AES-GCM, HKDF, scrypt), `hashlib` SHA3 | AES-256, SHA-256, RSA |
| API / server | Flask 3 (one process) | Node.js / Express |
| Frontend | Vanilla JS + CSS, strict CSP | React |
| Blockchain | Solidity 0.8.24, Hardhat, ethers v6, Node gateway | Solidity, Hardhat, Ganache |
| Storage | Local disk or AWS S3 (boto3, SSE-KMS/SSE-S3, write-once) | AWS S3 + KMS |
| AI | scikit-learn: IsolationForest, RandomForestClassifier | + SHAP |
| Data store | Append-only JSONL files (signed, hash-chained) | PostgreSQL |
| Testing | unittest, Hardhat/Mocha, node:test, Playwright (Chromium) | — |

The changes from the plan were deliberate. Each one is explained in the report, §5.6.

## 13. Testing

| Suite | Count | What it covers |
|---|---|---|
| aditya | 107 | pipeline, insider attacks, CLI, API and HTTP codes, chain rules, audit chain, S3 (fake client), gateway client, key protection |
| ansh | 27 | features, rules, model, scoring, explanations, watcher, alert store, chain flags |
| nayan | 32 | passwords, TOTP, lockout, sessions, restrictions, admin API, end-to-end with examcrypto |
| harsh Hardhat | 27 | contracts (19) + gateway against real contracts (8) |
| harsh gateway unit / crypto | 11 / 7 | gateway logic / ChronoSeal |
| Browser | 16 checks | all 4 roles in real Chromium, phone width, no JS errors |
| Mutation | 14 bugs | deliberate security bugs in controlcenter, all caught |

Run everything with `python run_all_tests.py`. Performance: `python aditya/scripts/benchmark.py`
(see the report for figures).

## 14. Quick start (Windows PowerShell)

```powershell
git clone https://github.com/adityarenushe21/exam-crypto-cloud.git
cd exam-crypto-cloud
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r aditya\requirements.txt -r ansh\requirements.txt
python run_all_tests.py                      # every Python suite (+ Node suites once npm-installed)

cd aditya; python -m examcrypto init-keys; cd ..\nayan
python -m controlcenter demo-users           # prints 4 demo logins ONCE - write them down
$env:EXAM_DEMO_MODE = "1"
python -m controlcenter serve                # open http://127.0.0.1:8000
```

The full guide covers the real blockchain, custodian approvals, on-chain AI flags and S3:
[HOW_TO_RUN_EVERYTHING.md](HOW_TO_RUN_EVERYTHING.md).

## 15. Honest status and limitations

| Verified | Where |
|---|---|
| examcrypto tests (105 at the time), Harsh's 26 Hardhat tests, gateway, real local-chain seal + anchoring + correct refusals | Aditya's Windows PC (Python 3.14.7, Node 24) |
| All current Python suites (107 + 27 + 32), gateway unit tests, ChronoSeal, 16-step browser walkthrough, benchmark | a Linux test environment |
| Custodian approve → release on the real chain; 27th Hardhat test (risk flag) | **not yet**: pending on Aditya's PC |
| Real AWS S3 | **not yet**: tested against a fake S3 client only ([setup guide](aditya/docs/AWS_S3_SETUP.md)) |
| AI accuracy | **synthetic** data only ([evaluation](ansh/reports/evaluation.md)), not real-world accuracy |

Main limitations:
- Both key pairs live in one local folder (a real system would use an HSM or KMS).
- Release time comes from the server clock plus the chain's block time.
- One exam centre on-chain.
- Flask development server; HTTPS must be added in front for deployment.

## 16. Team and attribution

| Member | Module |
|---|---|
| Aditya Renushe | Secure upload, encryption and cloud storage (examcrypto); integration; maintains `ansh/`, `nayan/` |
| Harsh Kapile | Blockchain integrity: smart contracts, gateway, ChronoSeal |
| Ansh Sahni | AI threat detection (planned design; left the project) |
| Nayan D. Padghan | Alerting, access control and dashboard (planned design; left the project) |

Guide: **Shital Kakad**.
