# ExamVault capstone project | Aditya Renushe | MIT World Peace University, Pune
# Module: secure upload, post-quantum encryption and cloud storage
# SPDX-License-Identifier: MIT
r"""
One-command demo for the project guide (Milestone 4).

Runs the whole Option A story in a TEMPORARY folder with throw-away keys and a
fake PDF. Nothing touches your real keys\, local_storage\ or AWS. The clock is
SIMULATED so the time-lock can be shown without waiting.

Run from the project root (venv active):
    python scripts\run_demo.py
"""

import json
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from examcrypto import pipeline, signatures                       # noqa: E402
from examcrypto import manifest as mf                              # noqa: E402
from examcrypto.encoding import b64e                               # noqa: E402
from examcrypto.errors import ExamCryptoError                      # noqa: E402
from examcrypto.hashing import sha3_256_hex                        # noqa: E402
from examcrypto.keystore import KeyStore                           # noqa: E402
from examcrypto.storage import LocalStorage, object_keys           # noqa: E402

PASS = b"demo-only-passphrase"
EXAM_TIME = "2026-12-01T09:00:00Z"
UPLOAD_DAY = datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc)
ONE_HOUR_EARLY = datetime(2026, 12, 1, 8, 0, tzinfo=timezone.utc)
EXAM_START = datetime(2026, 12, 1, 9, 0, tzinfo=timezone.utc)
AUTHORITY = {"actor_id": "demo-authority", "role": "exam_authority"}
OFFICER = {"actor_id": "demo-officer", "role": "release_officer"}
STUDENT = {"actor_id": "demo-student", "role": "student"}
PAPER = (b"%PDF-1.4\n% FAKE EXAM PAPER - DEMO DATA ONLY\n"
         b"Q1. Define post-quantum cryptography.\n%%EOF\n")

results = []


def step(title):
    print(f"\n{'=' * 68}\n{title}\n{'=' * 68}")


def expect(label, fn, expected_code):
    """Run fn; PASS if it fails with expected_code (or succeeds when expected_code is None)."""
    try:
        value = fn()
        ok = expected_code is None
        got = "SUCCESS"
    except ExamCryptoError as exc:
        value, ok, got = None, exc.reason_code == expected_code, exc.reason_code
    results.append((label, expected_code or "SUCCESS", got, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label:<46} -> {got}")
    return value


tmp = Path(tempfile.mkdtemp(prefix="examcrypto_demo_"))
try:
    ks = KeyStore(tmp / "keys")
    storage = LocalStorage(tmp / "storage")

    step("1. SETUP - release service (ML-KEM-768) + exam authority (ML-DSA-65) keys")
    ids = ks.init_keys(PASS)
    print(f"  recipient (ML-KEM) key ID : {ids['recipient_key_id']}")
    print(f"  signer   (ML-DSA) key ID : {ids['signer_key_id']}")
    print("  private keys stored as passphrase-encrypted PKCS#8 PEM")

    step("2. UPLOAD on 2026-11-20 - seal the paper (exam at 2026-12-01 09:00 UTC)")
    expect("student tries to upload a paper", lambda: pipeline.seal_paper(
        storage=storage, recipient_public=ks.recipient_public(),
        signer_private=ks.signer_private(PASS), plaintext=PAPER, exam_id="CS301-ENDSEM",
        release_at_utc=EXAM_TIME, actor=STUDENT, now=UPLOAD_DAY), "ROLE_NOT_ALLOWED")
    expect("upload a .exe pretending to be a paper", lambda: pipeline.seal_paper(
        storage=storage, recipient_public=ks.recipient_public(),
        signer_private=ks.signer_private(PASS), plaintext=b"MZ fake exe",
        exam_id="CS301-ENDSEM", release_at_utc=EXAM_TIME, actor=AUTHORITY,
        now=UPLOAD_DAY), "NOT_A_PDF")
    sealed = expect("exam authority seals the real paper", lambda: pipeline.seal_paper(
        storage=storage, recipient_public=ks.recipient_public(),
        signer_private=ks.signer_private(PASS), plaintext=PAPER, exam_id="CS301-ENDSEM",
        release_at_utc=EXAM_TIME, actor=AUTHORITY, now=UPLOAD_DAY), None)
    pid = sealed["paper_id"]
    ct_path = storage.root / object_keys(pid, 1)[0]
    mf_path = storage.root / object_keys(pid, 1)[1]
    print(f"\n  paper_id                 : {pid}")
    print(f"  SHA3-256 (for blockchain): 0x{sealed['ciphertext_sha3_256_hex']}")
    print(f"  stored objects           : {ct_path.name} ({ct_path.stat().st_size} B), "
          f"{mf_path.name} ({mf_path.stat().st_size} B)")
    print(f"  plaintext visible in storage? {b'FAKE EXAM PAPER' in ct_path.read_bytes()}")

    def release(now, actor=OFFICER, loader=None):
        return pipeline.release_paper(
            storage=storage, paper_id=pid, trusted_signer_public=ks.signer_public(),
            load_recipient_private=loader or (lambda: ks.recipient_private(PASS)),
            actor=actor, now=now)

    step("3. BEFORE THE EXAM - early access attempts (simulated clock)")
    expect("student requests the paper at exam time", lambda: release(EXAM_START, STUDENT),
           "ROLE_NOT_ALLOWED")
    key_touched = []
    expect("release officer asks 1 hour early", lambda: release(
        ONE_HOUR_EARLY, loader=lambda: key_touched.append(1) or ks.recipient_private(PASS)),
        "RELEASE_TIME_NOT_REACHED")
    print(f"  ML-KEM private key unlocked during early attempt? {bool(key_touched)}")

    step("4. ATTACKS on stored data (each change is undone afterwards)")
    original_ct, original_mf = ct_path.read_bytes(), mf_path.read_bytes()

    def restore():
        ct_path.write_bytes(original_ct)
        mf_path.write_bytes(original_mf)

    bad = bytearray(original_ct); bad[3] ^= 1
    ct_path.write_bytes(bytes(bad))
    expect("1 bit of encrypted file changed", lambda: release(EXAM_START),
           "CIPHERTEXT_DIGEST_MISMATCH")
    restore()

    env = json.loads(original_mf)
    env["manifest"]["release_at_utc"] = "2026-11-21T00:00:00Z"
    mf_path.write_text(json.dumps(env))
    expect("release time edited to 'tomorrow'", lambda: release(ONE_HOUR_EARLY),
           "SIGNATURE_INVALID")
    restore()

    ct_path.write_bytes(b"%PDF- attacker's fake paper")
    env = json.loads(original_mf)
    env["manifest"]["ciphertext_sha3_256_hex"] = sha3_256_hex(b"%PDF- attacker's fake paper")
    mf_path.write_text(json.dumps(env))
    expect("file swapped + hash recomputed", lambda: release(EXAM_START), "SIGNATURE_INVALID")
    restore()

    insider = json.loads(original_mf)
    early = "2026-11-21T00:00:00Z"
    insider["manifest"]["release_at_utc"] = early
    insider["manifest"]["aad"] = insider["manifest"]["aad"].replace(EXAM_TIME, early)
    insider["signature_b64"] = b64e(signatures.sign(ks.signer_private(PASS),
                                                    mf.canonical_json(insider["manifest"])))
    mf_path.write_text(json.dumps(insider))
    expect("INSIDER re-signs an earlier release time", lambda: release(ONE_HOUR_EARLY),
           "DECRYPTION_AUTHENTICATION_FAILED")
    restore()

    step("5. EXAM TIME - authorised release")
    out = expect("release officer at 09:00 UTC", lambda: release(EXAM_START), None)
    if out:
        print(f"  decrypted bytes identical to original? {out[1] == PAPER}")
        results.append(("decrypted == original", "True", str(out[1] == PAPER), out[1] == PAPER))

    step("SUMMARY")
    width = max(len(r[0]) for r in results)
    for label, expected, got, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {label:<{width}}  expected {expected:<32} got {got}")
    passed = sum(r[3] for r in results)
    print(f"\n  {passed}/{len(results)} scenarios behaved as expected")
    print("  NOTE: student prototype, simulated clock, throw-away keys, fake data.")
    sys.exit(0 if passed == len(results) else 1)
finally:
    shutil.rmtree(tmp, ignore_errors=True)
