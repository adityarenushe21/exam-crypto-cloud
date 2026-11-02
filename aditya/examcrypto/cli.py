r"""Command-line demo for Milestone 3.

    python -m examcrypto init-keys
    python -m examcrypto make-sample
    python -m examcrypto seal output\sample_paper.pdf --exam-id CS301-ENDSEM --release-at 2026-12-01T09:00:00Z
    python -m examcrypto verify <paper_id>
    python -m examcrypto release <paper_id>        (needs custodian approval on-chain)
    python -m examcrypto verify-events             (check the signed audit chain)

Passphrase: you are asked to type it (hidden). EXAM_KEY_PASSPHRASE is read if
set, but avoid it on your PC: PowerShell saves typed commands in its history.

--simulate-now (release) only works when EXAM_DEMO_MODE=1. It exists so the
time-lock can be demonstrated without waiting; the Milestone 5 API will NOT
have it.
"""

import argparse
import getpass
import json
import os
from pathlib import Path

from .encoding import parse_utc
from .errors import ExamCryptoError
from .keystore import KeyStore
from .storage import LocalStorage

KEYS_DIR = Path("keys")
STORAGE_DIR = Path("local_storage")
OUTPUT_DIR = Path("output")


def _passphrase(confirm: bool = False) -> bytes:
    env = os.environ.get("EXAM_KEY_PASSPHRASE")
    if env:
        return env.encode("utf-8")
    first = getpass.getpass("Key passphrase (hidden): ")
    if confirm and getpass.getpass("Repeat passphrase: ") != first:
        raise ExamCryptoError("INVALID_INPUT", "passphrases did not match")
    return first.encode("utf-8")


def _print(obj) -> None:
    print(json.dumps(obj, indent=2))


def _actor(args, default_role: str) -> dict:
    return {"actor_id": args.actor_id, "role": args.role or default_role}


def _now(args):
    if args.simulate_now:
        if os.environ.get("EXAM_DEMO_MODE") != "1":
            raise ExamCryptoError("ROLE_NOT_ALLOWED",
                                  "--simulate-now needs EXAM_DEMO_MODE=1 (demo/testing only)")
        print(f"!! DEMO ONLY: pretending the time is {args.simulate_now}")
        return parse_utc(args.simulate_now)
    return None


def cmd_init_keys(args):
    ids = KeyStore(KEYS_DIR).init_keys(_passphrase(confirm=True))
    _print({"status": "KEYS_CREATED", "folder": str(KEYS_DIR), **ids})
    print("Keep the passphrase safe. If it is lost, sealed papers can NEVER be opened.")


def cmd_make_sample(args):
    OUTPUT_DIR.mkdir(exist_ok=True)
    path = OUTPUT_DIR / "sample_paper.pdf"
    text = "FAKE EXAM PAPER - TEST DATA ONLY"
    stream = f"BT /F1 18 Tf 72 720 Td ({text}) Tj ET".encode("ascii")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    path.write_bytes(bytes(out))
    _print({"status": "SAMPLE_CREATED", "path": str(path), "bytes": len(out)})


def cmd_seal(args):
    _, service = make_service(_passphrase())
    if args.simulate_now:
        fixed = _now(args)
        service.clock = lambda: fixed
    result = service.seal(plaintext=Path(args.file).read_bytes(), exam_id=args.exam_id,
                          release_at_utc=args.release_at, actor=_actor(args, "exam_authority"),
                          paper_id=args.paper_id)
    _print(result)


def cmd_verify(args):
    _, service = make_service(_passphrase())
    _print(service.status(paper_id=args.paper_id, version=args.version,
                          actor=_actor(args, "auditor")))


def cmd_release(args):
    ks, service = make_service(_passphrase())
    if args.simulate_now:
        fixed = _now(args)
        service.clock = lambda: fixed
    if args.offline:
        if os.environ.get("EXAM_DEMO_MODE") != "1":
            raise ExamCryptoError("ROLE_NOT_ALLOWED", "--offline needs EXAM_DEMO_MODE=1 (skips blockchain)")
        print("!! DEMO ONLY: blockchain authorization SKIPPED")
        service.require_chain_release = False
    manifest, plaintext = service.release(paper_id=args.paper_id, version=args.version,
                                          actor=_actor(args, "release_officer"))
    out_dir = OUTPUT_DIR / "released"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{manifest['paper_id']}_v{manifest['paper_version']}.pdf"
    with open(out, "xb") as f:                 # never overwrite
        f.write(plaintext)
    _print({"status": "RELEASED", "paper_id": manifest["paper_id"],
            "paper_version": manifest["paper_version"], "written_to": str(out),
            "bytes": len(plaintext)})


def cmd_mock_approve(args):
    """DEMO ONLY: plays the custodians on the MOCK chain (real chain: Harsh's scripts)."""
    if os.environ.get("EXAM_DEMO_MODE") != "1":
        raise ExamCryptoError("ROLE_NOT_ALLOWED", "mock-approve needs EXAM_DEMO_MODE=1")
    chain = make_chain()
    if chain.MODE != "mock":
        raise ExamCryptoError("INVALID_INPUT", "mock-approve only works with EXAM_CHAIN=mock")
    if args.simulate_now:
        fixed = _now(args)
        chain.clock = lambda: fixed
    version = args.version or max(LocalStorage(STORAGE_DIR).versions(args.paper_id) or [1])
    votes = []
    for c in range(args.count):
        try:
            votes.append(chain.approve_release(args.paper_id, version, c))
        except ValueError as exc:
            votes.append({"custodian": c, "error": str(exc)})
    _print({"status": "MOCK_VOTES", "votes": votes,
            "chain": chain.get_status(args.paper_id, version)})


def cmd_anchor_events(args):
    _, service = make_service(_passphrase())
    _print(service.anchor_events(actor=_actor(args, "admin")))


def cmd_dev_tokens(args):
    import secrets
    path = KEYS_DIR / "dev_tokens.json"
    if path.exists():
        raise ExamCryptoError("KEY_ALREADY_EXISTS", f"{path} already exists")
    roles = ["exam_authority", "release_officer", "admin", "auditor", "student"]
    tokens = {secrets.token_urlsafe(24): {"actor_id": f"dev-{r}", "role": r} for r in roles}
    KEYS_DIR.mkdir(exist_ok=True)
    with open(path, "x", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    _print({"status": "TOKENS_CREATED", "path": str(path),
            "roles": roles, "note": "DEV ONLY - tokens are in the file, keep it out of Git"})


def make_storage():
    """EXAM_STORAGE=local (default) or s3 (needs EXAM_S3_BUCKET, optional EXAM_S3_KMS_KEY_ID)."""
    kind = os.environ.get("EXAM_STORAGE", "local").lower()
    if kind == "s3":
        from .storage import S3Storage
        bucket = os.environ.get("EXAM_S3_BUCKET")
        if not bucket:
            raise ExamCryptoError("INVALID_INPUT", "EXAM_STORAGE=s3 needs EXAM_S3_BUCKET")
        return S3Storage(bucket, prefix=os.environ.get("EXAM_S3_PREFIX", ""),
                         kms_key_id=os.environ.get("EXAM_S3_KMS_KEY_ID") or None,
                         region=os.environ.get("AWS_REGION") or None)
    return LocalStorage(STORAGE_DIR)


def make_chain():
    """EXAM_CHAIN=mock (default) or gateway (Harsh's chain gateway, EXAM_CHAIN_GATEWAY_URL)."""
    from .blockchain import GatewayBlockchain, MockBlockchain
    if os.environ.get("EXAM_CHAIN", "mock").lower() == "gateway":
        return GatewayBlockchain(os.environ.get("EXAM_CHAIN_GATEWAY_URL", "http://127.0.0.1:8546"))
    return MockBlockchain(STORAGE_DIR / "blockchain_mock" / "state.json")


def make_service(passphrase: bytes):
    from .events import JsonlEventSink
    from .service import PaperService
    ks = KeyStore(KEYS_DIR)
    ks.signer_private(passphrase)              # fail fast on a wrong passphrase
    events = JsonlEventSink(STORAGE_DIR / "events" / "events.jsonl",
                            signer=ks.audit_private(passphrase))
    return ks, PaperService(storage=make_storage(), keystore=ks, passphrase=passphrase,
                            events=events, blockchain=make_chain())


def cmd_serve(args):
    from .api import create_app, load_tokens
    ks, service = make_service(_passphrase())
    demo = os.environ.get("EXAM_DEMO_MODE") == "1"
    app = create_app(service, load_tokens(KEYS_DIR / "dev_tokens.json"),
                     audit_public=ks.audit_public(), demo_mode=demo)
    print(f"examcrypto API on http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    print(f"storage={type(service.storage).__name__}  chain={service.blockchain.MODE}"
          f"  demo_mode={demo}")
    print("Development server - for local testing only.")
    app.run(host="127.0.0.1", port=args.port, debug=False)


def cmd_verify_events(args):
    from .events import JsonlEventSink, verify_chain
    ks = KeyStore(KEYS_DIR)
    events = JsonlEventSink(STORAGE_DIR / "events" / "events.jsonl").read(limit=0)
    result = verify_chain(events, ks.audit_public())
    _print({"status": "EVENTS_OK" if result["ok"] else "EVENTS_TAMPERED", **result})


def build_parser():
    p = argparse.ArgumentParser(prog="examcrypto")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("--role", help="override role (to test denials)")
        sp.add_argument("--actor-id", default="local-cli-user")

    sub.add_parser("init-keys").set_defaults(func=cmd_init_keys)
    sub.add_parser("make-sample").set_defaults(func=cmd_make_sample)
    sub.add_parser("dev-tokens").set_defaults(func=cmd_dev_tokens)
    sub.add_parser("verify-events").set_defaults(func=cmd_verify_events)
    sv = sub.add_parser("serve")
    sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(func=cmd_serve)

    s = sub.add_parser("seal"); common(s)
    s.add_argument("file")
    s.add_argument("--exam-id", required=True)
    s.add_argument("--release-at", required=True, help="UTC, e.g. 2026-12-01T09:00:00Z")
    s.add_argument("--paper-id", help="add a NEW VERSION to an existing paper")
    s.add_argument("--simulate-now", help=argparse.SUPPRESS)
    s.set_defaults(func=cmd_seal)

    v = sub.add_parser("verify"); common(v)
    v.add_argument("paper_id"); v.add_argument("--version", type=int)
    v.set_defaults(func=cmd_verify)

    r = sub.add_parser("release"); common(r)
    r.add_argument("paper_id"); r.add_argument("--version", type=int)
    r.add_argument("--simulate-now", help="DEMO ONLY: pretend current UTC time")
    r.add_argument("--offline", action="store_true", help="DEMO ONLY: skip blockchain check")
    r.set_defaults(func=cmd_release)

    m = sub.add_parser("mock-approve", help="DEMO ONLY: mock custodians approve release")
    m.add_argument("paper_id"); m.add_argument("--version", type=int)
    m.add_argument("--count", type=int, default=3)
    m.add_argument("--simulate-now", help=argparse.SUPPRESS)
    m.set_defaults(func=cmd_mock_approve)

    a = sub.add_parser("anchor-events"); common(a)
    a.set_defaults(func=cmd_anchor_events)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
        return 0
    except ExamCryptoError as exc:
        _print({"status": "FAILED", "reason_code": exc.reason_code, "detail": str(exc)})
        return 2
    except FileNotFoundError as exc:
        _print({"status": "FAILED", "reason_code": "INVALID_INPUT", "detail": f"file not found: {exc.filename}"})
        return 2
    except FileExistsError as exc:
        _print({"status": "FAILED", "reason_code": "OUTPUT_EXISTS", "detail": f"{exc.filename} already exists"})
        return 2
