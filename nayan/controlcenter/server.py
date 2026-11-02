"""ONE server for the whole system (except the blockchain node + Harsh's gateway):

    examcrypto API (/api/v1/papers...)   Aditya   - crypto, storage, chain-checked release
    login + admin API (/api/v1/auth...)  Nayan's  - accounts, sessions, restrictions, alert review
    dashboard (/)                        Nayan's  - web UI
    threat watcher thread                Ansh's   - scores new audit events every few seconds

Paths (all git-ignored), relative to DATA_DIR (default: <repo>/aditya):
    keys/                 crypto keys + users.json + pseudonym_salt.bin
    local_storage/        papers, events/events.jsonl, access/restrictions.jsonl, alerts/alerts.jsonl
"""
import threading
import time
from pathlib import Path

from . import bootstrap  # noqa: F401  (adds aditya/ and ansh/ to sys.path)
from flask import Response, send_from_directory

from examcrypto.api import create_app
from examcrypto.encoding import format_utc, utc_now
from examcrypto.errors import ExamCryptoError

from .admin_api import make_blueprint
from .auth import AuthService
from .restrictions import RestrictionStore
from .sessions import SessionManager
from .users import UserStore

WEB = Path(__file__).resolve().parent / "web"
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class WatcherThread:
    """Runs Ansh's Watcher.poll() in the background; never crashes the server."""

    def __init__(self, watcher, interval: float = 2.0):
        self.watcher, self.interval = watcher, interval
        self.status = {"running": False, "last_poll_utc": None, "alerts_written": 0, "error": None,
                       "model": "rules + Isolation Forest + Random Forest" if watcher.scorer.model else "rules only (no trained model found)",
                       "on_chain_flags": watcher.flagger is not None}
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, name="threat-watcher", daemon=True)

    def start(self):
        self.status["running"] = True
        self._t.start()
        return self

    def stop(self):
        self._stop.set()
        self._t.join(timeout=5)
        self.status["running"] = False

    def poll_once(self):
        try:
            self.status["alerts_written"] += len(self.watcher.poll())
            self.status["error"] = None
        except Exception as exc:                          # keep serving even if scoring fails
            self.status["error"] = f"{type(exc).__name__}: {exc}"[:200]
        self.status["last_poll_utc"] = format_utc(utc_now())
        self.status["last_seq"] = self.watcher.last_seq
        self.status["log_tampered"] = self.watcher.tampered

    def _run(self):
        while not self._stop.is_set():
            self.poll_once()
            self._stop.wait(self.interval)


class Context:
    def __init__(self, service, auth, alerts, audit_public, watcher=None):
        self.service, self.auth, self.alerts, self.audit_public = service, auth, alerts, audit_public
        self.watcher = watcher

    def watcher_status(self):
        return dict(self.watcher.status) if self.watcher else {"running": False, "model": "disabled"}

    def chain_health(self):
        bc = self.service.blockchain
        out = {"mode": getattr(bc, "MODE", "unknown")}
        try:
            out["anchored_events_up_to_seq"] = bc.anchored_seq()
            out["reachable"] = True
        except ExamCryptoError as exc:
            out.update(reachable=False, reason_code=exc.reason_code)
        return out


def build(*, service, keystore, data_dir: Path, ansh_dir: Path | None = None, clock=None,
          watcher: bool = True, interval: float = 2.0, flagger=None, demo_mode: bool = False):
    """Wire everything together. Returns (flask_app, context). Used by `serve` and by tests."""
    from threatdetect.alerts import AlertStore
    from threatdetect.watcher import Watcher

    data_dir = Path(data_dir)
    storage_dir = data_dir / "local_storage"
    users = UserStore(data_dir / "keys" / "users.json")
    restrictions = RestrictionStore(storage_dir / "access" / "restrictions.jsonl")
    auth = AuthService(users, SessionManager(), restrictions, service.events, clock=clock or service.clock)
    alerts_path = storage_dir / "alerts" / "alerts.jsonl"
    alerts = AlertStore(alerts_path)

    wt = None
    if watcher:
        model = None
        if ansh_dir and (Path(ansh_dir) / "models" / "model.joblib").exists():
            from threatdetect.model import ThreatModel
            model = ThreatModel.load(Path(ansh_dir) / "models")
        w = Watcher(service.events.path, alerts_path, model=model, flagger=flagger)
        wt = WatcherThread(w, interval)

    audit_public = keystore.audit_public()
    app = create_app(service, authenticator=auth.authenticate, audit_public=audit_public, demo_mode=demo_mode)
    ctx = Context(service, auth, alerts, audit_public, wt)
    app.register_blueprint(make_blueprint(ctx))

    @app.get("/")
    def index():
        return send_from_directory(WEB, "index.html")

    @app.get("/ui/<path:name>")
    def ui(name):
        if name not in ("app.js", "style.css"):
            return Response("not found", status=404)
        return send_from_directory(WEB, name)

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    app.extensions["controlcenter"] = ctx
    return app, ctx
