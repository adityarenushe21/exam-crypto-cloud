# How to run everything (Windows PowerShell)

All commands start from the repository folder (`exam-crypto-cloud`) with the venv active
(`.\.venv\Scripts\Activate.ps1`), unless the step says otherwise.

## Part 0: Get the code and set up once

```powershell
git clone https://github.com/adityarenushe21/exam-crypto-cloud.git
cd exam-crypto-cloud
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r aditya\requirements.txt -r ansh\requirements.txt
```

To get updates later: `git pull`.

## Part A: Run all tests

```powershell
python run_all_tests.py
```

**Expected:** `PASS` for aditya (107), ansh (27) and nayan (32).

To include Harsh's suites, install Node.js LTS first, then:

```powershell
cd harsh\examvault\packages\crypto; npm install; cd ..\..\blockchain; npm install; cd ..\..\..
python run_all_tests.py --hardhat
```

**Expected:** crypto 7, gateway 11, and Hardhat 27 passing (19 contract + 8 gateway).

## Part B: The whole system with the MOCK blockchain (fastest demo)

```powershell
cd aditya; python -m examcrypto init-keys; cd ..           # once - remember the passphrase
cd nayan; python -m controlcenter demo-users               # once - write the 4 passwords down
$env:EXAM_DEMO_MODE = "1"
python -m controlcenter serve
```

Open **http://127.0.0.1:8000**:

1. Log in as **authority1** → Papers → seal a PDF with a release time 2 minutes away.
2. Log in as **officer1** → Release is refused: before the release time, then `CHAIN_NOT_RELEASED`.
3. Approve as the mock custodians (demo only). In another terminal:
   `Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/_demo/mock-chain/<paper_id>/approve`
4. As **officer1**, click **Release** → the PDF downloads.
5. Log in as **admin1** → **Alerts** (the AI flags the refused attempts) → **Restrict account**
   → officer1 is locked out immediately → **Audit log** → *Verify* and *Anchor*.

## Part C: The whole system on a REAL local blockchain (5 terminals)

| Terminal | Folder | Command (leave running unless noted) |
|---|---|---|
| 1 | `harsh\examvault\blockchain` | `npx hardhat node` |
| 2 | `harsh\examvault\blockchain` | `npx hardhat run scripts/setup-local.js --network localhost`, then `npx hardhat run gateway/server.js --network localhost` |
| 3 | `nayan` (venv) | `$env:EXAM_CHAIN = "gateway"; python -m controlcenter serve --flag-on-chain` |
| 4 | browser | http://127.0.0.1:8000: seal as authority1; release as officer1 is refused |
| 5 | `harsh\examvault\blockchain` | `$env:PAPER_ID = "pap_..."; npx hardhat run scripts/custodian-approve.js --network localhost` (runs once, then exits) |

**What you should see:**
- The paper shows `ANCHORED` with a real `0x…` transaction.
- After the custodians approve, it becomes `RELEASED 3/3`, and the officer can release it.
- **HIGH** AI alerts appear in terminal 2 as `AuditAnchor#flagRisk` transactions.
- **Freeze demo:** run `scripts/custodian-freeze.js` with the same `PAPER_ID` → the dashboard shows `BLOCKED`.

Restarting `npx hardhat node` wipes the chain. When that happens, run `setup-local.js` again and
seal new papers.

## Part D: AWS S3 storage

Follow `aditya\docs\AWS_S3_SETUP.md`. Create the bucket and app user first, and set a billing
alert. Then start the server with:

```powershell
$env:EXAM_STORAGE = "s3"; $env:EXAM_S3_BUCKET = "<bucket>"; $env:AWS_PROFILE = "examcrypto"; $env:AWS_REGION = "ap-south-1"
```

## Who owns what (for the viva)

- **Aditya (`aditya/`):**
  - upload validation
  - ML-KEM-768 / HKDF-SHA-256 / AES-256-GCM / SHA3-256 / ML-DSA-65
  - signed manifest
  - storage (local + S3)
  - release service with time and chain checks
  - API
  - signed, hash-chained audit events
- **Harsh (`harsh/examvault/`):**
  - OrgRegistry / ExamVault / AuditAnchor contracts and their tests
  - ChronoSeal (an alternative design, kept)
  - the chain gateway and scripts, which Harsh should review and own
- **AI threat detection (`ansh/`):** originally Ansh's role; built by Aditya.
- **Access control + dashboard (`nayan/`):** originally Nayan's role; built by Aditya.

Tell your guide about the team change; the work logs record everything.
