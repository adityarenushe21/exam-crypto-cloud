# How to run everything (Windows PowerShell)

- `aditya/`: secure upload, Option A cryptography, storage (local or S3), API, signed audit events.
- `harsh/examvault/`: Harsh's contracts and ChronoSeal (unchanged), plus the new chain gateway and scripts.
- `ansh/`: AI threat detection (rules + Isolation Forest + Random Forest), alert store, on-chain risk flags.
  Built after the team changed (Ansh and Nayan left; Aditya + Harsh now own all modules).
- `nayan/`: access control + dashboard. **Next module, not built yet.**

**Decision used: Option A.** Aditya's post-quantum crypto encrypts. Harsh's ExamVault decides
*when* release is allowed (3 of 5 custodians, only after the release time). AuditAnchor stores
the audit-log batches. This still needs confirmation from the team and guide.

## What was tested where (be honest in the report)

| What | Result | Where |
|---|---|---|
| Aditya: 105 Python tests | OK | Claude sandbox (Linux, Python 3.13, cryptography 50.0.1, Flask 3.1.3) |
| Aditya: earlier 54 tests | OK | **Your PC** (Windows 11, Python 3.14.7, cryptography 50.0.2) |
| Harsh: 7 ChronoSeal tests (unchanged) | 7/7 | Claude sandbox, Node 22, test-only Keccak stand-in |
| Harsh: 10 gateway unit tests | 10/10 | Claude sandbox, fake contracts |
| Python API ↔ gateway over HTTP | 13/13 steps | Claude sandbox, gateway core + fake contracts |
| Harsh: `npx hardhat test` (19 existing + 7 new) | **NOT RUN** | needs your PC (npm was blocked in the sandbox) |
| Real AWS S3 | **NOT RUN** | needs an AWS account (see `aditya/docs/AWS_S3_SETUP.md`) |

---

## Part A: Aditya's module only (no Node.js needed)

Copy everything from `aditya\` into `C:\Users\Asus\cap presentation`, replacing files when asked.
Your `.venv`, `keys` and `local_storage` folders are not in the zip, so they are kept.

```powershell
cd "C:\Users\Asus\cap presentation"
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests          # expect: Ran 105 tests ... OK
python scripts\run_demo.py                     # expect: 11/11 scenarios
```

To run the API with the **mock** chain (two terminals):

```powershell
# Terminal 1
$env:EXAM_DEMO_MODE = "1"
python -m examcrypto serve
# Terminal 2
.\.venv\Scripts\Activate.ps1
python scripts\api_demo_client.py
python -m examcrypto verify-events            # expect: EVENTS_OK
```

Your existing keys keep working; a new audit-signing key is created automatically on first use.
Papers you sealed before this update aren't on the mock chain. To register one, call
`POST /api/v1/papers/<id>/anchor`, or simply seal a new paper.

## Part B: Harsh's tests (needs Node.js LTS)

```powershell
node --version                                 # if it fails, install Node.js LTS from nodejs.org
cd harsh\examvault\packages\crypto
npm install
npm test                                       # expect: 7 pass
cd ..\..\blockchain
npm install
npx hardhat test                               # expect: 26 passing (19 existing + 7 gateway)
node --test gateway/test/core.test.js          # expect: 10 pass
```

If the Solidity compiler download is blocked, run `$env:USE_SOLCJS="1"` first (from Harsh's README).

## Part C: The whole system on a real local blockchain (5 terminals)

| Terminal | Folder | Command |
|---|---|---|
| 1 | `harsh\examvault\blockchain` | `npx hardhat node` (leave it running) |
| 2 | `harsh\examvault\blockchain` | `npx hardhat run scripts/setup-local.js --network localhost`, then `npx hardhat run gateway/server.js --network localhost` (leave it running) |
| 3 | your project | `$env:EXAM_CHAIN="gateway"; python -m examcrypto serve` (leave it running) |
| 4 | your project | `python scripts\api_demo_client.py` |
| 5 | `harsh\examvault\blockchain` | when terminal 4 asks: `$env:PAPER_ID="pap_..."; npx hardhat run scripts/custodian-approve.js --network localhost`, then press Enter in terminal 4 |

**What you should see:**
- The upload reports `blockchain_status: "ANCHORED"` with a real `0x…` transaction hash.
- An early release is refused (`423 RELEASE_TIME_NOT_REACHED`).
- After the release time it's still refused (`423 CHAIN_NOT_RELEASED`).
- The custodians approve (3 of 5) and the release succeeds.
- The audit events are anchored on-chain.

**Freeze demo:** seal another paper. Before release, run `$env:PAPER_ID="pap_..."; npx hardhat run scripts/custodian-freeze.js --network localhost`.
The release is then refused with `CHAIN_PAPER_BLOCKED`, and the private key is never unlocked.

Restarting `npx hardhat node` wipes the chain. After a restart, run `setup-local.js` again and seal
new papers (or re-anchor old ones).

## Part D: Ansh's AI module (uses the same Python venv as aditya)

```powershell
cd "C:\Users\Asus\cap presentation\cap\Capstone_Integrated\ansh"
..\aditya\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests          # expect: Ran 25 tests ... OK
python -m threatdetect train
python -m threatdetect evaluate               # writes reports\evaluation.md
python -m threatdetect demo
```

**Live, alongside Part C:** add a 6th terminal in `ansh` and run:

```powershell
python -m threatdetect watch ..\aditya\local_storage\events\events.jsonl --flag-on-chain
```

Every API request your module logs is scored within about 2 seconds. HIGH alerts are recorded
on-chain through `AuditAnchor.flagRisk`, and the gateway terminal shows the transaction.

## Who owns what (for the viva)

- **Aditya:** upload validation, ML-KEM-768 / HKDF / AES-256-GCM / SHA3-256 / ML-DSA-65, the signed
  manifest, write-once storage (local + S3 adapter), the release service and its checks, the API,
  and the signed hash-chained audit events.
- **Harsh:** OrgRegistry / ExamVault / AuditAnchor contracts and their tests, ChronoSeal
  (alternative design, kept), and the chain gateway + scripts in his folder. Harsh should
  review and own these additions.
- **AI threat detection (`ansh/`):** originally Ansh's; now built by Aditya with AI assistance.
- **Not built yet:** Nayan's dashboard and real login (next module).

Being open with your guide about which parts were AI-assisted is a good idea; the work logs make that easy.
