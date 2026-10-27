# exam-crypto-cloud

Aditya Renushe — Secure Upload, Encryption & Cloud Storage module
(Blockchain-Based Secure Examination Paper Distribution and Audit System).

Proposed crypto design (Option A, awaiting supervisor/team approval):
ML-KEM-768 -> HKDF-SHA-256 -> AES-256-GCM, SHA3-256 digest, ML-DSA-65 signed manifest,
private AWS S3 storage. Student prototype — not a security-audited production system.

## Status
Milestone 1 (environment) — in progress. No application code yet.

## Setup (Windows PowerShell)
```powershell
cd C:\Projects\exam-crypto-cloud
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python scripts\check_crypto_env.py
```

## Planned layout (folders get created only when their milestone starts)
```
exam-crypto-cloud/
  scripts/            small runnable checks and demos
  src/examcrypto/     crypto modules (Milestone 2-3)
  tests/              automated tests (Milestone 3-4)
  references/         teammate handoff files
  keys/               LOCAL TEST KEYS ONLY - git-ignored (Milestone 3)
```
