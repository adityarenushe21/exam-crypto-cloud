r"""Command line.

    python -m threatdetect train                     # train on synthetic data -> models\
    python -m threatdetect evaluate                  # metrics -> reports\evaluation.md
    python -m threatdetect score PATH\events.jsonl   # one-off scoring -> alerts
    python -m threatdetect watch PATH\events.jsonl   # live: follow the log, append alerts
    python -m threatdetect demo                      # synthetic stream, print alerts
"""

import argparse
import json
import sys
from pathlib import Path

from .model import ThreatModel

MODEL_DIR = Path("models")
REPORT_DIR = Path("reports")


def _model(required=True):
    if (MODEL_DIR / "model.joblib").exists():
        return ThreatModel.load(MODEL_DIR)
    if required:
        sys.exit("No trained model in models\\ - run:  python -m threatdetect train")
    return None


def _row(a):
    return (f"{a.get('event_time_utc', a['created_at_utc'])}  {a['severity']:<6} {a['risk_score']:>3}  "
            f"{a.get('actor_role', '?')}:{a.get('actor_id', '?'):<10} {','.join(a['reason_codes'])}"
            + (f"  (+{a['suppressed_count']} similar)" if a.get("suppressed_count") else ""))


def cmd_train(args):
    from .features import extract
    from .synthetic import generate
    ev, y, _ = generate(days=args.days, seed=args.seed)
    m = ThreatModel.train(extract(ev), y, notes=f"days={args.days} seed={args.seed}")
    m.save(MODEL_DIR)
    print(json.dumps({"status": "TRAINED", "folder": str(MODEL_DIR), **{k: m.meta[k] for k in
                      ("n_train", "n_attack", "sklearn_version", "training_data")}}, indent=2))


def cmd_evaluate(args):
    from . import evaluate
    report, _ = evaluate.run(days=args.days)
    REPORT_DIR.mkdir(exist_ok=True)
    (REPORT_DIR / "evaluation.json").write_text(json.dumps(report, indent=2))
    md = evaluate.to_markdown(report)
    (REPORT_DIR / "evaluation.md").write_text(md, encoding="utf-8")
    print(md)


def cmd_score(args):
    from .schema import load_events
    from .scoring import Scorer
    alerts = Scorer(_model()).process_all(load_events(args.events, verify=not args.no_verify))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            for a in alerts:
                f.write(json.dumps(a, sort_keys=True) + "\n")
    for a in alerts:
        print(_row(a))
    print(f"{len(alerts)} alert(s)")


def cmd_watch(args):
    from .watcher import Watcher
    flagger = None
    if args.flag_on_chain:
        from .chainflag import GatewayFlagger, load_or_create_salt
        flagger = GatewayFlagger(load_or_create_salt(Path("keys") / "pseudonym_salt.bin"), args.gateway)
    w = Watcher(args.events, args.out, _model(), flagger=flagger)
    print(f"watching {args.events} -> {args.out} (Ctrl+C to stop)")
    try:
        w.run_forever(args.interval, on_alert=lambda a: print(_row(a), flush=True))
    except KeyboardInterrupt:
        print("stopped")


def cmd_demo(args):
    from .scoring import Scorer
    from .synthetic import generate
    ev, y, sc = generate(days=7, seed=99, attacks_per_kind=1)
    alerts = Scorer(_model(required=False)).process_all(ev)
    for a in alerts:
        print(_row(a))
    print(f"\n{len(ev)} events, {sum(y)} attack events in {len({s.split('#')[0] for s in sc if s != 'normal'})} "
          f"attack types -> {len(alerts)} alerts (suppression folds repeats)")


def main(argv=None):
    p = argparse.ArgumentParser(prog="threatdetect")
    sub = p.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("train"); t.add_argument("--days", type=int, default=60)
    t.add_argument("--seed", type=int, default=1); t.set_defaults(func=cmd_train)
    e = sub.add_parser("evaluate"); e.add_argument("--days", type=int, default=60)
    e.set_defaults(func=cmd_evaluate)
    s = sub.add_parser("score"); s.add_argument("events"); s.add_argument("--out")
    s.add_argument("--no-verify", action="store_true", help="skip hash-chain check (synthetic files)")
    s.set_defaults(func=cmd_score)
    w = sub.add_parser("watch"); w.add_argument("events")
    w.add_argument("--out", default="alerts/alerts.jsonl"); w.add_argument("--interval", type=float, default=2.0)
    w.add_argument("--flag-on-chain", action="store_true", help="record HIGH alerts via AuditAnchor.flagRisk")
    w.add_argument("--gateway", default="http://127.0.0.1:8546")
    w.set_defaults(func=cmd_watch)
    sub.add_parser("demo").set_defaults(func=cmd_demo)
    args = p.parse_args(argv)
    args.func(args)
