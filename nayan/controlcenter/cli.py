r"""Command line (run from the nayan folder, with the project venv active).

    python -m controlcenter create-user --username admin1 --role admin      (asks for a password)
    python -m controlcenter enable-mfa --username admin1                    (prints the TOTP secret)
    python -m controlcenter list-users
    python -m controlcenter demo-users                                      (4 demo accounts, random passwords)
    python -m controlcenter serve                                           (http://127.0.0.1:8000)

Environment (same as examcrypto): EXAM_CHAIN=mock|gateway, EXAM_STORAGE=local|s3, EXAM_KEY_PASSPHRASE,
EXAM_DEMO_MODE=1. CONTROLCENTER_DATA_DIR overrides where keys/ and local_storage/ live
(default: the aditya folder, so the CLI and the server share the same keys and papers).
"""
import argparse
import getpass
import json
import os
import secrets
import string
import sys
from pathlib import Path

from . import bootstrap
from .users import ROLES, UserError, UserStore

DATA_DIR = Path(os.environ.get("CONTROLCENTER_DATA_DIR", bootstrap.ADITYA))


def _users():
    return UserStore(DATA_DIR / "keys" / "users.json")


def _now():
    from examcrypto.encoding import utc_now
    return utc_now()


def _print(o):
    print(json.dumps(o, indent=2))


def _ask_password():
    p1 = getpass.getpass("New password (hidden): ")
    if getpass.getpass("Repeat password: ") != p1:
        sys.exit("passwords did not match")
    return p1


def cmd_create_user(a):
    try:
        _print({"status": "USER_CREATED", **_users().create(a.username, a.role, _ask_password(), _now())})
    except UserError as e:
        sys.exit(f"FAILED: {e}")


def cmd_enable_mfa(a):
    from .totp import provisioning_uri
    us = _users()
    if not us.exists(a.username):
        sys.exit("no such user")
    secret = us.enable_totp(a.username)
    print("Add this to your authenticator app (Google/Microsoft Authenticator -> enter a setup key):")
    print(f"  account: {a.username}\n  key:     {secret}\n  type:    time-based")
    print(f"  or URI:  {provisioning_uri(secret, a.username)}")
    print("From now on this account needs the 6-digit code at login.")


def cmd_list_users(a):
    _print({"users": _users().list_public()})


def cmd_demo_users(a):
    """Creates one account per role with a random strong password, printed ONCE."""
    us, out = _users(), {}
    alphabet = string.ascii_letters + string.digits
    for role, name in [("admin", "admin1"), ("auditor", "auditor1"),
                       ("exam_authority", "authority1"), ("release_officer", "officer1")]:
        if us.exists(name):
            out[name] = "(already exists - unchanged)"
            continue
        pw = "".join(secrets.choice(alphabet) for _ in range(14)) + "-7a"
        us.create(name, role, pw, _now())
        out[name] = f"{role:<16} password: {pw}"
    print("DEMO ACCOUNTS - write these down now; passwords are not stored anywhere in plain text:")
    for k, v in out.items():
        print(f"  {k:<11} {v}")


def cmd_serve(a):
    from examcrypto.cli import make_service
    from .server import build
    pw = os.environ.get("EXAM_KEY_PASSPHRASE")
    passphrase = (pw or getpass.getpass("Key passphrase (hidden): ")).encode("utf-8")
    ks, service = make_service(passphrase, DATA_DIR / "keys", DATA_DIR / "local_storage")
    if not _users().list_public():
        sys.exit("No user accounts yet. Run:  python -m controlcenter demo-users   (or create-user)")
    model_dir = bootstrap.ANSH / "models"
    if not a.no_watcher and not (model_dir / "model.joblib").exists():
        print("No trained AI model yet - training on synthetic data (one-time, a few seconds)...")
        from threatdetect.features import extract
        from threatdetect.model import ThreatModel
        from threatdetect.synthetic import generate
        ev, y, _ = generate(days=60, seed=1)
        ThreatModel.train(extract(ev), y, notes="auto-trained by controlcenter serve").save(model_dir)
    flagger = None
    if a.flag_on_chain:
        from threatdetect.chainflag import GatewayFlagger, load_or_create_salt
        flagger = GatewayFlagger(load_or_create_salt(DATA_DIR / "keys" / "pseudonym_salt.bin"),
                                 os.environ.get("EXAM_CHAIN_GATEWAY_URL", "http://127.0.0.1:8546"))
    app, ctx = build(service=service, keystore=ks, data_dir=DATA_DIR, ansh_dir=bootstrap.ANSH,
                     watcher=not a.no_watcher, flagger=flagger,
                     demo_mode=os.environ.get("EXAM_DEMO_MODE") == "1")
    if ctx.watcher:
        ctx.watcher.start()
    print(f"Control center on http://127.0.0.1:{a.port}   (Ctrl+C to stop)")
    print(f"storage={type(service.storage).__name__}  chain={service.blockchain.MODE}  "
          f"threat-watcher={ctx.watcher_status().get('model')}  on-chain-flags={bool(flagger)}")
    print("Development server - for local use only.")
    app.run(host="127.0.0.1", port=a.port, debug=False, threaded=True)


def main(argv=None):
    p = argparse.ArgumentParser(prog="controlcenter")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-user"); c.add_argument("--username", required=True)
    c.add_argument("--role", required=True, choices=ROLES); c.set_defaults(func=cmd_create_user)
    m = sub.add_parser("enable-mfa"); m.add_argument("--username", required=True); m.set_defaults(func=cmd_enable_mfa)
    sub.add_parser("list-users").set_defaults(func=cmd_list_users)
    sub.add_parser("demo-users").set_defaults(func=cmd_demo_users)
    s = sub.add_parser("serve"); s.add_argument("--port", type=int, default=8000)
    s.add_argument("--no-watcher", action="store_true", help="do not run the AI threat watcher")
    s.add_argument("--flag-on-chain", action="store_true", help="record HIGH alerts on-chain (needs the gateway)")
    s.set_defaults(func=cmd_serve)
    a = p.parse_args(argv)
    a.func(a)
