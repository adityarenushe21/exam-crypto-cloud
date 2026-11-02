r"""
Talks to the RUNNING API like a teammate's app would (standard library only).

Terminal 1:  python -m examcrypto serve
Terminal 2:  python scripts\api_demo_client.py

Uses the dev tokens in keys\dev_tokens.json and output\sample_paper.pdf.
Seals the paper with a release time 20 seconds in the future, shows the early
release being refused, waits, shows that custodians must still approve on the
blockchain, gets the approvals, then releases it.

Custodian approvals:
  * mock chain (default): the server must run with EXAM_DEMO_MODE=1, the client
    then calls the demo-only route that plays the custodians;
  * real chain (EXAM_CHAIN=gateway): run Harsh's script when asked:
        $env:PAPER_ID="pap_..."; npx hardhat run scripts/custodian-approve.js --network localhost
"""

import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = "http://127.0.0.1:8000/api/v1"
tokens = json.loads(Path("keys/dev_tokens.json").read_text(encoding="utf-8"))
TOKEN = {v["role"]: t for t, v in tokens.items()}
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # never use a proxy for localhost


def call(method, path, role=None, body=None, content_type=None):
    req = urllib.request.Request(BASE + path, data=body, method=method)
    if role:
        req.add_header("Authorization", f"Bearer {TOKEN[role]}")
    if content_type:
        req.add_header("Content-Type", content_type)
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, r.headers.get_content_type(), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get_content_type(), e.read()
    except urllib.error.URLError:
        sys.exit("Cannot reach the API. Start it first:  python -m examcrypto serve")


def show(label, status, ctype, data):
    print(f"\n--- {label}: HTTP {status}")
    if ctype == "application/json":
        print(json.dumps(json.loads(data), indent=2)[:900])
    else:
        print(f"    {ctype}, {len(data)} bytes")


def multipart(fields, file_field, file_path):
    boundary = uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; '
                 f'filename="{Path(file_path).name}"\r\nContent-Type: application/pdf\r\n\r\n'.encode()
                 + Path(file_path).read_bytes() + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


show("health", *call("GET", "/health"))

release_at = (datetime.now(timezone.utc) + timedelta(seconds=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
body, ctype = multipart({"exam_id": "CS301-ENDSEM", "release_at_utc": release_at},
                        "file", "output/sample_paper.pdf")
show("student tries to upload", *call("POST", "/papers", "student", body, ctype))
status, ct, data = call("POST", "/papers", "exam_authority", body, ctype)
show("exam authority uploads", status, ct, data)
if status != 201:
    sys.exit("Upload failed - see above.")
pid = json.loads(data)["paper_id"]

show("status (admin)", *call("GET", f"/papers/{pid}", "admin"))
show("release too early (release officer)", *call("POST", f"/papers/{pid}/release", "release_officer"))
show("release by admin (wrong role)", *call("POST", f"/papers/{pid}/release", "admin"))

print(f"\nWaiting until {release_at} ...")
while datetime.now(timezone.utc) < datetime.strptime(release_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc):
    time.sleep(1)
time.sleep(1)

status, ct, data = call("POST", f"/papers/{pid}/release", "release_officer")
show("release at exam time, before custodian approval", status, ct, data)

if status == 423:
    s2, c2, d2 = call("POST", f"/_demo/mock-chain/{pid}/approve")
    if s2 == 200:
        show("mock custodians approve (demo route)", s2, c2, d2)
    else:
        print("\n>>> Real blockchain: in Harsh's blockchain folder run")
        print(f'>>>   $env:PAPER_ID="{pid}"; npx hardhat run scripts/custodian-approve.js --network localhost')
        input(">>> then press Enter here ... ")
    show("status after approvals", *call("GET", f"/papers/{pid}", "admin"))
    status, ct, data = call("POST", f"/papers/{pid}/release", "release_officer")
    show("release after custodian approval", status, ct, data)
if status == 200:
    out = Path("output/released_via_api"); out.mkdir(parents=True, exist_ok=True)
    path = out / f"{pid}_v1.pdf"
    path.write_bytes(data)
    print(f"    saved to {path}; identical to original? {data == Path('output/sample_paper.pdf').read_bytes()}")

status, ct, data = call("GET", "/events?limit=8", "admin")
print("\n--- last events (what Ansh's AI and Nayan's dashboard would read)")
for e in json.loads(data)["events"]:
    print(f"    #{e['seq']:<4} {e['timestamp_utc']}  {e['event_type']:<16} {e['result']:<8} "
          f"{e.get('reason_code', ''):<26} role={e['actor_role']}")

show("anchor audit events on the blockchain", *call("POST", "/events/anchor", "admin"))
show("verify signed audit chain", *call("GET", "/events/verify", "admin"))
