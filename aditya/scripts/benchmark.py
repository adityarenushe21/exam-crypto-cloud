# ExamVault capstone project | Aditya Renushe | MIT World Peace University, Pune
# Module: secure upload, post-quantum encryption and cloud storage
# SPDX-License-Identifier: MIT
r"""Repeatable performance benchmark for the examcrypto pipeline.

    python scripts\benchmark.py            # from the aditya folder, venv active
    python scripts\benchmark.py --quick    # fewer repetitions

Prints the environment (OS, CPU, Python, cryptography, OpenSSL) and the MEDIAN of N runs
for each operation, so results can be reproduced and compared. Uses throw-away keys,
fake PDFs and a temporary folder; nothing touches your real keys or storage.
"""

import json
import os
import platform
import shutil
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cryptography                                                     # noqa: E402
from cryptography.hazmat.backends.openssl.backend import backend       # noqa: E402
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey  # noqa: E402

from examcrypto import pipeline                                         # noqa: E402
from examcrypto.keystore import KeyStore                                # noqa: E402
from examcrypto.storage import LocalStorage                             # noqa: E402

QUICK = "--quick" in sys.argv
REPS = 5 if QUICK else 15
PASS = b"benchmark-passphrase"


def median_ms(fn, reps=REPS):
    times = []
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t) * 1000)
    return round(statistics.median(times), 3)


def main():
    env = {"os": f"{platform.system()} {platform.release()}", "machine": platform.machine(),
           "cpu": platform.processor() or "unknown", "python": platform.python_version(),
           "cryptography": cryptography.__version__, "backend": backend.openssl_version_text(),
           "repetitions": REPS, "date_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    rows = []

    k = MLKEM768PrivateKey.generate()
    pub = k.public_key()
    ss, ct = pub.encapsulate()
    d = MLDSA65PrivateKey.generate()
    msg = b"x" * 600                                         # about the size of a manifest
    sig = d.sign(msg, b"ctx")
    rows += [
        ("ML-KEM-768 key generation", median_ms(MLKEM768PrivateKey.generate)),
        ("ML-KEM-768 encapsulate", median_ms(pub.encapsulate)),
        ("ML-KEM-768 decapsulate", median_ms(lambda: k.decapsulate(ct))),
        ("ML-DSA-65 key generation", median_ms(MLDSA65PrivateKey.generate)),
        ("ML-DSA-65 sign (600 B manifest)", median_ms(lambda: d.sign(msg, b"ctx"))),
        ("ML-DSA-65 verify (600 B manifest)", median_ms(lambda: d.public_key().verify(sig, msg, b"ctx"))),
    ]

    tmp = Path(tempfile.mkdtemp())
    try:
        ks = KeyStore(tmp / "keys")
        rows.append(("Key setup: generate + encrypt + save both key pairs (scrypt)", median_ms(
            lambda: (shutil.rmtree(tmp / "k2", ignore_errors=True), KeyStore(tmp / "k2").init_keys(PASS)), reps=3)))
        ks.init_keys(PASS)
        recipient, signer = ks.recipient_public(), ks.signer_private(PASS)
        trusted = ks.signer_public()
        rows.append(("Unlock ML-KEM key, cold (scrypt + PBKDF2 + decrypt)", median_ms(lambda: KeyStore(tmp / "keys").recipient_private(PASS), reps=5)))
        priv = ks.recipient_private(PASS)
        now = datetime(2026, 11, 1, tzinfo=timezone.utc)
        later = datetime(2026, 12, 1, 9, tzinfo=timezone.utc)
        for size_mb in (0.1, 1, 5, 20):
            data = b"%PDF-1.4\n" + os.urandom(int(size_mb * 1024 * 1024) - 9)
            store = LocalStorage(tmp / f"st{size_mb}")
            pids = []

            def seal():
                r = pipeline.seal_paper(storage=store, recipient_public=recipient, signer_private=signer,
                                        plaintext=data, exam_id="BENCH", release_at_utc="2026-12-01T09:00:00Z",
                                        actor={"role": "exam_authority"}, now=now)
                pids.append(r["paper_id"])
            reps = 3 if size_mb >= 5 else (5 if QUICK else 10)
            seal_ms = median_ms(seal, reps)
            release_ms = median_ms(lambda: pipeline.release_paper(
                storage=store, paper_id=pids[0], trusted_signer_public=trusted,
                load_recipient_private=lambda: priv, actor={"role": "release_officer"}, now=later), reps)
            verify_ms = median_ms(lambda: pipeline.verify_paper(storage=store, paper_id=pids[0],
                                                                trusted_signer_public=trusted,
                                                                actor={"role": "auditor"}), reps)
            ct_size = (store.root / "papers" / pids[0] / "v1" / "ciphertext.bin").stat().st_size
            mf_size = (store.root / "papers" / pids[0] / "v1" / "manifest.json").stat().st_size
            label = f"{size_mb:g} MB PDF"
            rows += [(f"Seal {label} (encrypt + hash + sign + store)", seal_ms),
                     (f"Verify {label} (signature + SHA3 recheck)", verify_ms),
                     (f"Release {label} (all checks + decrypt; key pre-unlocked)", release_ms)]
            env[f"overhead_{label}"] = {"ciphertext_extra_bytes": ct_size - len(data), "manifest_bytes": mf_size}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("ENVIRONMENT"); print(json.dumps(env, indent=2))
    print(f"\n{'Operation':<66} median ms")
    print("-" * 78)
    for name, ms in rows:
        print(f"{name:<66} {ms:>9}")
    out = Path("benchmark_results.json")
    out.write_text(json.dumps({"environment": env, "results_ms": dict(rows)}, indent=2))
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    main()
