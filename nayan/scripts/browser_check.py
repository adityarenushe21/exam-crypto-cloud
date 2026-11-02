r"""Optional end-to-end check of the dashboard in a real (headless) Chromium browser.

Needs:  pip install playwright   and   python -m playwright install chromium
Run against a FRESH demo server (it creates papers and restricts officer1):

    # terminal 1 (nayan folder): fresh data folder + demo accounts + demo mode
    $env:CONTROLCENTER_DATA_DIR = "$PWD\browser_check_data"; $env:EXAM_DEMO_MODE = "1"
    python -m controlcenter demo-users > demo_users.txt
    python -c "import sys; sys.path.insert(0, r'..\aditya'); from examcrypto.keystore import KeyStore; KeyStore(r'browser_check_data\keys').init_keys(b'browser-check-passphrase')"
    $env:EXAM_KEY_PASSPHRASE = "browser-check-passphrase"; python -m controlcenter serve --port 8123
    # terminal 2 (nayan folder)
    python scripts\browser_check.py screenshots demo_users.txt

16 checks: login errors, sealing from the browser, release refused before custodian approval,
release + download after approval, AI alert -> admin restricts the account -> account locked out and
session killed, audit verification + anchoring, auditor read-only, phone-width layout, no JS errors.
"""
import json, os, re, sys, time, urllib.request
from datetime import datetime, timedelta, timezone
from playwright.sync_api import sync_playwright, expect

BASE = "http://127.0.0.1:8123"
SHOTS = sys.argv[1]
os.makedirs(SHOTS, exist_ok=True)
creds = {}
for line in open(sys.argv[2]):
    m = re.match(r"\s+(\S+)\s+\S+\s+password: (\S+)", line)
    if m: creds[m.group(1)] = m.group(2)
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
results = []

def check(name, cond):
    results.append((name, bool(cond))); print(("PASS " if cond else "FAIL ") + name)

def api(method, path, token=None, body=None):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + token} if token else {})})
    try:
        with op.open(req) as r: return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        with e: return e.code, json.loads(e.read() or b"{}")

def login(page, user, pw=None):
    page.goto(BASE + "/")
    page.fill("input[name=username]", user); page.fill("input[name=password]", pw or creds[user])
    page.click("button[type=submit]")

with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": 1280, "height": 860}, accept_downloads=True)
    page = ctx.new_page()
    console_errors = []
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: console_errors.append(str(e)))

    # 1. login page + wrong password
    page.goto(BASE + "/")
    expect(page.locator("h1")).to_have_text("Sign in")
    page.screenshot(path=f"{SHOTS}/01_login.png")
    login(page, "authority1", "Wrong-password-1")
    expect(page.locator("#login-msg")).to_contain_text("invalid username or password")
    check("wrong password shows generic error", True)

    # 2. exam authority seals a paper through the form
    login(page, "authority1")
    expect(page.locator("h1")).to_have_text("Papers")
    check("authority lands on Papers (no admin pages in nav)", page.locator("#nav a").all_inner_texts() == ["Papers"])
    pdf = SHOTS + "/sample.pdf"
    open(pdf, "wb").write(b"%PDF-1.4\nBROWSER TEST PAPER\n%%EOF\n")
    page.set_input_files("input[type=file]", pdf)
    page.fill("input[placeholder=CS301-ENDSEM]", "CS301-ENDSEM")
    soon = page.evaluate("""() => { const d = new Date(Date.now() + 3 * 60000);
        const z = (n) => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${z(d.getMonth() + 1)}-${z(d.getDate())}T${z(d.getHours())}:${z(d.getMinutes())}`; }""")
    page.fill("input[type=datetime-local]", soon)
    page.click("text=Encrypt & seal")
    expect(page.locator("#banner")).to_contain_text("Sealed pap_")
    expect(page.locator("tbody tr")).to_have_count(1)
    check("paper sealed from the browser", "MOCK_ANCHORED" in page.locator("#banner").inner_text())
    page.screenshot(path=f"{SHOTS}/02_authority_papers.png")
    form_pid = re.search(r"pap_[0-9a-f]+", page.locator("#banner").inner_text()).group(0)

    # a second paper via API with a release time 5 seconds away (seconds precision)
    st, tok = api("POST", "/api/v1/auth/login", body={"username": "authority1", "password": creds["authority1"]})
    rel = (datetime.now(timezone.utc) + timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    import uuid
    bnd = uuid.uuid4().hex
    data = (f"--{bnd}\r\nContent-Disposition: form-data; name=\"exam_id\"\r\n\r\nCS302-ENDSEM\r\n"
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"release_at_utc\"\r\n\r\n{rel}\r\n"
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"p.pdf\"\r\nContent-Type: application/pdf\r\n\r\n").encode() \
           + b"%PDF-1.4\nSECOND PAPER\n%%EOF\n" + f"\r\n--{bnd}--\r\n".encode()
    req = urllib.request.Request(BASE + "/api/v1/papers", data=data, method="POST",
                                 headers={"Authorization": "Bearer " + tok["token"], "Content-Type": f"multipart/form-data; boundary={bnd}"})
    with op.open(req) as r: pid = json.loads(r.read())["paper_id"]
    page.click("text=Log out")

    # 3. release officer: refused before custodians approve, then release + download
    time.sleep(6)
    login(page, "officer1")
    expect(page.locator("h1")).to_have_text("Papers")
    row = page.locator("tr", has_text=pid)
    expect(row).to_contain_text("AWAITING_CUSTODIANS")
    row.get_by_role("button", name="Release").click()
    expect(page.locator("#banner")).to_contain_text("CHAIN_NOT_RELEASED")
    check("officer refused before custodian approval", True)
    page.screenshot(path=f"{SHOTS}/03_officer_refused.png")
    st, votes = api("POST", f"/api/v1/_demo/mock-chain/{pid}/approve")
    check("mock custodians approve (demo route)", st == 200)
    page.reload()
    row = page.locator("tr", has_text=pid)
    expect(row).to_contain_text("RELEASABLE")
    with page.expect_download() as dl:
        row.get_by_role("button", name="Release").click()
    path = dl.value.path()
    check("released PDF downloads and matches", open(path, "rb").read() == b"%PDF-1.4\nSECOND PAPER\n%%EOF\n")
    page.screenshot(path=f"{SHOTS}/04_officer_released.png")
    page.click("text=Log out")

    # 4. generate an AI alert: failed-login burst for a REAL account (auditor1)
    for _ in range(4):
        api("POST", "/api/v1/auth/login", body={"username": "auditor1", "password": "Wrong-password-9"})
    for _ in range(6):
        api("POST", "/api/v1/auth/login", body={"username": "nobody", "password": "Wrong-password-9"})
    # tampering-style failures by the officer account -> HIGH alert for a registered user
    st, otok = api("POST", "/api/v1/auth/login", body={"username": "officer1", "password": creds["officer1"]})
    for _ in range(5):
        api("POST", f"/api/v1/papers/{form_pid}/release", token=otok["token"])   # early -> RELEASE_TIME_NOT_REACHED
    time.sleep(3)                                                                # watcher polls every 2 s

    # 5. admin: overview, alerts, restrict, audit, access, system
    login(page, "admin1")
    expect(page.locator("h1")).to_have_text("Overview")
    expect(page.locator(".stat").first).to_contain_text("2")
    page.screenshot(path=f"{SHOTS}/05_admin_overview.png", full_page=True)
    page.click("#nav >> text=Alerts")
    expect(page.locator("h1")).to_have_text("AI alerts")
    officer_row = page.locator("tbody tr", has_text="officer1").first
    expect(officer_row).to_contain_text("EARLY_RELEASE_PROBING")
    check("AI alert for officer1 early-release probing visible", True)
    page.screenshot(path=f"{SHOTS}/06_admin_alerts.png", full_page=True)
    answers = iter(["24"])
    page.on("dialog", lambda d: d.accept(next(answers, "")) if d.type == "prompt" else d.accept())
    officer_row.get_by_role("button", name="Restrict account").click()
    expect(page.locator("#banner")).to_contain_text("officer1 restricted")
    check("admin restricted officer1 from the alert", True)
    st, body = api("POST", "/api/v1/auth/login", body={"username": "officer1", "password": creds["officer1"]})
    check("restricted officer1 cannot log in (403 ACCOUNT_RESTRICTED)", (st, body.get("reason_code")) == (403, "ACCOUNT_RESTRICTED"))
    st, _ = api("GET", "/api/v1/dashboard/papers", token=otok["token"])
    check("officer1's existing session was killed", st == 401)

    page.click("#nav >> text=Audit log")
    page.click("text=Verify signatures & chain")
    expect(page.locator(".toolbar")).to_contain_text("events checked")
    check("audit chain verifies in the UI", "valid" in page.locator(".toolbar").inner_text())
    page.click("text=Anchor new events on-chain")
    expect(page.locator("#banner")).to_contain_text("Anchored events 1-")
    page.screenshot(path=f"{SHOTS}/07_admin_audit.png")

    page.click("#nav >> text=Access")
    expect(page.locator("h1")).to_have_text("Access control")
    expect(page.locator("table").first.locator("tbody tr", has_text="officer1")).to_contain_text("RESTRICTED")
    check("access page shows officer1 as RESTRICTED", True)
    page.screenshot(path=f"{SHOTS}/08_admin_access.png", full_page=True)
    page.click("#nav >> text=System")
    expect(page.locator("h1")).to_have_text("System health")
    page.screenshot(path=f"{SHOTS}/09_admin_system.png")
    page.click("text=Log out")

    # 6. auditor: read-only, no action buttons
    login(page, "auditor1")
    expect(page.locator("h1")).to_have_text("Overview")
    page.click("#nav >> text=Alerts")
    expect(page.locator("h1")).to_have_text("AI alerts")
    expect(page.locator("tbody tr").first).to_be_visible()
    check("auditor sees alerts but no action buttons", page.get_by_role("button", name="Restrict account").count() == 0
          and page.locator("button", has_text="Acknowledge").count() == 0)
    page.click("#nav >> text=Access")
    expect(page.locator("h1")).to_have_text("Access control")
    check("auditor sees no restrict/create controls", page.locator("text=Create account").count() == 0
          and page.locator("button", has_text="Restrict").count() == 0)

    # 7. mobile width renders without horizontal overflow
    m = b.new_context(viewport={"width": 390, "height": 800}).new_page()
    m.goto(BASE + "/")
    m.fill("input[name=username]", "admin1"); m.fill("input[name=password]", creds["admin1"]); m.click("button[type=submit]")
    expect(m.locator("h1")).to_have_text("Overview")
    check("mobile: no horizontal page scroll", m.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"))
    m.screenshot(path=f"{SHOTS}/10_mobile_overview.png", full_page=True)

    expected_http = ("status of 401", "status of 403", "status of 423")       # refusals the test triggers on purpose
    check("no JavaScript errors in the console", not [e for e in console_errors if not any(x in e for x in expected_http)])
    if console_errors: print("console:", console_errors[:5])
    b.close()

print(f"\n{sum(ok for _, ok in results)}/{len(results)} browser checks passed")
sys.exit(0 if all(ok for _, ok in results) else 1)
