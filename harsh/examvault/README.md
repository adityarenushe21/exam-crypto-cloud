# ExamVault – Blockchain-Based Secure Examination Paper Distribution and Audit System

> **ExamVault capstone project · Harsh Kapile** · B.Tech CSE, MIT World Peace University, Pune · Guide: Shital Kakad
> Module: blockchain integrity (smart contracts, chain gateway, ChronoSeal) · [MIT License](../../LICENSE)

Day 1 status: **secure core** (smart contracts + ChronoSeal crypto library), fully tested.

## Layout
- blockchain/            Solidity contracts (OrgRegistry, ExamVault, AuditAnchor), Hardhat tests, deploy + benchmark scripts
- packages/crypto/       ChronoSeal library: AES-256-GCM, Shamir GF(256), Merkle, RSA-OAEP, ECDSA, signed hash-chained audit log
- (next)                 backend/ (Node API), ai-service/ (FastAPI), frontend/ (React), docs/ (compliance pack)

## Run on Windows (PowerShell)
    cd packages\crypto
    npm install
    npm test                      # 7 tests

    cd ..\..\blockchain
    npm install
    npx hardhat test              # 19 tests
    npx hardhat run scripts\benchmark-anchoring.js

    # local chain + deploy (two terminals)
    npx hardhat node
    npx hardhat run scripts\deploy.js --network localhost

If the Solidity compiler download is blocked on your network, run  `$env:USE_SOLCJS="1"`  first.

## ChronoSeal protocol (summary)
1. Seal: AES-256-GCM per-centre variants (AAD = paperId|centreId), DEK Shamir-split 3-of-5, each share RSA-OAEP-encrypted to a custodian.
2. Commit on-chain: Merkle root of variants, Merkle root of share hashes, master SHA-256, release time. No secrets on-chain.
3. Release: custodians can call approveRelease() only after releaseTime; 3 approvals authorize release; custodians re-encrypt shares to the centre; the centre recombines in-browser, verifies every share against the sealed commitment, decrypts.
4. Emergency (custodian-voted): freeze 2-of-5, unfreeze/reschedule/revoke+backup/rotate/mark-compromised 3-of-5.
5. Audit: every event signed + hash-chained, batched into Merkle roots, anchored contiguously on-chain.
