# examcrypto: secure upload, encryption, storage and release (Aditya's module)

Part of the ExamVault monorepo; see the [root README](../README.md).

Aditya Renushe, Secure Upload, Encryption & Cloud Storage module
(Blockchain-Based Secure Examination Paper Distribution and Audit System).

Option A (PROPOSED — awaiting supervisor/team approval):
ML-KEM-768 → HKDF-SHA-256 → AES-256-GCM, SHA3-256 digest, ML-DSA-65 signed manifest,
private AWS S3 storage (Milestone 6). **Student prototype — not a security-audited system.**

## Status
| Milestone | State |
|---|---|
| 1 Environment | DONE — 12/12 checks, Win 11 / Python 3.14.7 / cryptography 50.0.2 / OpenSSL 4.0.3 |
| 2 Algorithm demos | DONE — 5 demos passed on Aditya's PC |
| 3 Combined local pipeline | DONE — time-lock confirmed on Aditya's PC |
| 4 Automated tests + demo | DONE — 54 tests passed on Aditya's PC |
| 5 API + event contract | DONE in sandbox — Flask API, signed hash-chained events |
| 6 AWS S3 | CODE DONE, tested with fake S3 only — no AWS resource created (`docs/AWS_S3_SETUP.md`) |
| 7 Team integration | DONE: release needs 3-of-5 custodians on Harsh's ExamVault; confirmed on Aditya's PC with a real local Hardhat chain |
| 8 Demo/report | dashboard demo ready (`nayan/`); report and PPT update not started |

**Tests:** 107. The version before the login hooks passed on Aditya's PC (Windows 11, Python 3.14.7); the current version passes in a fresh clone in the Linux test sandbox and has not yet been re-run on the PC.

## Setup (Windows PowerShell)
One venv for the whole repo; see the root `HOW_TO_RUN_EVERYTHING.md`. From the repo folder:
```powershell
.\.venv\Scripts\Activate.ps1
cd aditya
python -m pip install -r requirements.txt
python scripts\check_crypto_env.py
python -m unittest discover -s tests -v
python scripts\run_demo.py          # one-command story for the guide
```

## Command-line demo
```powershell
python -m examcrypto init-keys                       # once; asks for a passphrase
python scripts\benchmark.py --quick                # optional: timings on this PC
python -m examcrypto make-sample                     # fake PDF -> output\sample_paper.pdf
python -m examcrypto seal output\sample_paper.pdf --exam-id CS301-ENDSEM --release-at 2026-12-01T09:00:00Z
python -m examcrypto verify <paper_id>
python -m examcrypto release <paper_id>              # denied before release time
```

## Configuration (environment variables)
| Variable | Default | Meaning |
|---|---|---|
| `EXAM_STORAGE` | `local` | `local` or `s3` |
| `EXAM_S3_BUCKET`, `EXAM_S3_PREFIX`, `EXAM_S3_KMS_KEY_ID`, `AWS_REGION`, `AWS_PROFILE` | – | S3 settings (see docs/AWS_S3_SETUP.md) |
| `EXAM_CHAIN` | `mock` | `mock` or `gateway` (Harsh's chain gateway) |
| `EXAM_CHAIN_GATEWAY_URL` | `http://127.0.0.1:8546` | gateway address |
| `EXAM_DEMO_MODE` | off | `1` enables `--simulate-now`, `--offline`, `mock-approve` and the demo route |

## API (Milestone 5)
```powershell
python -m examcrypto dev-tokens       # once
python -m examcrypto serve            # terminal 1
python scripts\api_demo_client.py     # terminal 2
```
Full contract for teammates: `docs/API_CONTRACT.md`.

## Layout
```
examcrypto/        the module
  kem.py kdf.py aead.py hashing.py signatures.py   one file per algorithm
  manifest.py      format v1 fields, validation, canonical bytes
  keystore.py      encrypted local key files (keys/, git-ignored)
  storage.py       write-once LocalStorage (S3 adapter later, same interface)
  authz.py         MOCK roles (replaced by Nayan's auth later)
  pipeline.py      seal_paper / verify_paper / release_paper
  service.py       pipeline + events + blockchain adapter
  api.py           Flask HTTP API (/api/v1)
  events.py        whitelisted, hash-chained, ML-DSA-signed audit events
  blockchain.py    GatewayBlockchain (Harsh's real contracts) + MockBlockchain
  storage.py       LocalStorage + S3Storage (write-once, SSE)
  cli.py           command-line demo
tests/             107 unittest tests (pipeline, insider attacks, CLI, API, chain rules, audit chain, S3, gateway)
docs/              API_CONTRACT.md (team contract), AWS_S3_SETUP.md
scripts/           environment check + Milestone 2 demos
references/        teammate handoff files (unchanged until interfaces are agreed)
```

## Format v1 (proposed)
Stored objects: `papers/<paper_id>/v<n>/ciphertext.bin` and `.../manifest.json`.

- `ciphertext.bin` = AES-256-GCM output (ciphertext ‖ 16-byte tag).
- `manifest.json` = `{"manifest": {...}, "signature_b64": "..."}`.
- Signed bytes = canonical JSON of `manifest` (sorted keys, no spaces, ASCII only,
  values are strings or non-negative integers → also valid RFC 8785 JCS output).
- ML-DSA-65 context: `exam-crypto-cloud/manifest/v1`.
- HKDF info: `exam-crypto-cloud|v1|aes-256-gcm-content-key|paper_id=<id>|paper_version=<n>`.
- AES-GCM AAD: `exam-crypto-cloud|v1|paper_id=..|paper_version=..|exam_id=..|release_at_utc=..`.
- Digest for blockchain: SHA3-256 over the exact `ciphertext.bin` bytes, lowercase hex
  (`bytes32` = `0x` + hex). Not SHA-256, not Keccak-256.
- Base64 = standard with padding; time = UTC `YYYY-MM-DDTHH:MM:SSZ`.
- Key ID = first 16 bytes of SHA3-256(raw public key), hex.

## Release order (fails closed at the first problem)
role check → strict manifest validation → trusted signer key ID → ML-DSA verify →
SHA3-256 recheck → release-time check (signed time) → **blockchain check (ExamVault says
RELEASED by 3-of-5 custodians, same digest, not frozen/revoked)** → only then unlock the
ML-KEM private key → decapsulate → HKDF → AES-GCM decrypt.

## Known limitations (prototype)
- Both key pairs in one local folder with one passphrase (real system: separate services/HSM).
- Key files: the passphrase is stretched with scrypt (N=2^15, r=8, p=1, salt in `keys/key_protection.json`)
  before it encrypts the PKCS#8 PEMs, because the library's PKCS#8 encryption alone uses only 2048
  PBKDF2 iterations. Key folders made before this change still load ("legacy"); run `init-keys` again
  in a fresh folder to get scrypt protection.
- Release time uses the PC clock; a trusted time source is future work.
- `--simulate-now` exists only for demos and requires `EXAM_DEMO_MODE=1`.
- Authorization is a mock (dev bearer tokens); Flask dev server is for local use only.
- Default chain is the mock (`MOCK_ANCHORED`); the real chain needs Harsh's gateway + a Hardhat node.
- Single exam centre ("CENTRAL") on-chain; per-centre variants are future work.
- S3 adapter verified only against a fake client.
