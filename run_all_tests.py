r"""Run every test suite in the project with one command.

    python run_all_tests.py              # Python suites + Node suites (if node_modules are installed)
    python run_all_tests.py --hardhat    # also run `npx hardhat test` (slower; needs npm install)

Uses the Python interpreter that runs this script, so activate the project venv first.
"""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NPX = shutil.which("npx") or shutil.which("npx.cmd")
NODE = shutil.which("node")

SUITES = [
    ("aditya  - crypto, storage, API, chain rules", ROOT / "aditya", [sys.executable, "-m", "unittest", "discover", "-s", "tests"]),
    ("ansh    - AI threat detection", ROOT / "ansh", [sys.executable, "-m", "unittest", "discover", "-s", "tests"]),
    ("nayan   - access control + dashboard", ROOT / "nayan", [sys.executable, "-m", "unittest", "discover", "-s", "tests"]),
]
if NODE:
    crypto = ROOT / "harsh" / "examvault" / "packages" / "crypto"
    chain = ROOT / "harsh" / "examvault" / "blockchain"
    if (crypto / "node_modules").is_dir():
        SUITES.append(("harsh   - ChronoSeal crypto library", crypto, [NODE, "--test", "test/crypto.test.js"]))
        SUITES.append(("harsh   - chain gateway (unit)", chain, [NODE, "--test", "gateway/test/core.test.js"]))
    if "--hardhat" in sys.argv and NPX and (chain / "node_modules").is_dir():
        SUITES.append(("harsh   - contracts + gateway (Hardhat)", chain, [NPX, "hardhat", "test"]))


def main() -> int:
    results = []
    for name, cwd, cmd in SUITES:
        if not cwd.is_dir():
            results.append((name, "MISSING", 0.0, ""))
            continue
        t = time.time()
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=dict(os.environ, PYTHONWARNINGS="ignore"))
        out = (p.stdout + p.stderr).strip().splitlines()
        summary = next((l for l in reversed(out) if l.startswith(("Ran ", "# pass", "ℹ pass")) or "passing" in l), "")
        results.append((name, "PASS" if p.returncode == 0 else "FAIL", time.time() - t, summary.strip()))
        if p.returncode != 0:
            print(f"\n----- {name} FAILED -----\n" + "\n".join(out[-40:]))
    print("\n" + "=" * 78)
    for name, status, secs, summary in results:
        print(f"{status:<8} {name:<44} {secs:5.1f}s  {summary}")
    skipped = [] if NODE else ["Node suites skipped: node not found"]
    if NODE and not (ROOT / "harsh/examvault/packages/crypto/node_modules").is_dir():
        skipped.append("Node suites skipped: run `npm install` in harsh/examvault/packages/crypto")
    for s in skipped:
        print("NOTE     " + s)
    print("=" * 78)
    return 0 if all(r[1] == "PASS" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
