"""HTTP API (Flask) for teammates. Base path /api/v1. Format v1 - PROPOSED.

Auth (MOCK, replaced by Nayan's real auth later):
    Authorization: Bearer <dev token>    tokens live in keys/dev_tokens.json
Run:
    python -m examcrypto serve           -> http://127.0.0.1:8000  (this PC only)
"""

import hmac
import json
import uuid
from pathlib import Path

from flask import Flask, Response, g, jsonify, request
from werkzeug.exceptions import HTTPException

from .constants import MAX_UPLOAD_BYTES
from .errors import ExamCryptoError
from .events import build_event

# reason_code -> HTTP status
HTTP_STATUS = {
    "AUTH_REQUIRED": 401,
    "LOGIN_FAILED": 401,
    "MFA_REQUIRED": 401,
    "ACCOUNT_LOCKED": 429,
    "ACCOUNT_RESTRICTED": 403,
    "CONFLICT": 409,
    "ROLE_NOT_ALLOWED": 403,
    "INVALID_INPUT": 400,
    "NOT_A_PDF": 415,
    "FILE_TOO_LARGE": 413,
    "PAPER_NOT_FOUND": 404,
    "DUPLICATE_VERSION": 409,
    "RELEASE_TIME_NOT_REACHED": 423,
    "MANIFEST_MALFORMED": 422,
    "UNSUPPORTED_VERSION": 422,
    "UNTRUSTED_SIGNER": 422,
    "SIGNATURE_INVALID": 422,
    "CIPHERTEXT_DIGEST_MISMATCH": 422,
    "DECRYPTION_AUTHENTICATION_FAILED": 422,
    "WRONG_RECIPIENT_KEY": 422,
    "CHAIN_NOT_RELEASED": 423,
    "CHAIN_PAPER_BLOCKED": 423,
    "CHAIN_UNKNOWN_PAPER": 409,
    "CHAIN_RECORD_MISMATCH": 422,
    "CHAIN_UNAVAILABLE": 503,
    "STORAGE_UNAVAILABLE": 503,
}
# Server-side problems: details are NOT shown to the caller.
INTERNAL_CODES = {"KEY_MISSING", "KEY_PASSPHRASE_INVALID", "KEY_ALREADY_EXISTS"}


def load_tokens(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {t: v for t, v in data.items() if isinstance(v, dict) and "role" in v}


def create_app(service, tokens: dict | None = None, audit_public=None, demo_mode: bool = False,
               authenticator=None) -> Flask:
    """tokens: MOCK dev bearer tokens (examcrypto serve).
    authenticator(request) -> actor dict: real login (Nayan's controlcenter). It must raise
    ExamCryptoError(AUTH_REQUIRED / ACCOUNT_RESTRICTED) itself. Exactly one of the two is used."""
    tokens = tokens or {}
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + 64 * 1024   # file + form fields

    def fail(code: str, message: str = "", http: int | None = None):
        if code in INTERNAL_CODES:
            http, message = 500, "internal server error"
        body = {"status": "FAILED", "reason_code": code if http != 500 else "INTERNAL_ERROR",
                "message": message, "request_id": g.get("request_id")}
        return jsonify(body), http or HTTP_STATUS.get(code, 500)

    @app.before_request
    def _start():
        g.request_id = str(uuid.uuid4())

    @app.after_request
    def _headers(resp):
        resp.headers["X-Request-Id"] = g.get("request_id", "")
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    def actor_or_401():
        if authenticator is not None:
            return authenticator(request)
        header = request.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            supplied = header[7:].strip().encode()
            for token, actor in tokens.items():
                if hmac.compare_digest(supplied, token.encode()):
                    return actor
        service.events.emit(build_event("AUTH", actor=None, reason_code="AUTH_REQUIRED",
                                        request_id=g.request_id))
        raise ExamCryptoError("AUTH_REQUIRED", "missing or unknown bearer token")

    @app.errorhandler(ExamCryptoError)
    def _crypto_error(exc):
        msg = str(exc).split(": ", 1)[-1] if ": " in str(exc) else ""
        return fail(exc.reason_code, msg)

    @app.errorhandler(413)
    def _too_large(_):
        return fail("FILE_TOO_LARGE", f"limit is {MAX_UPLOAD_BYTES} bytes")

    @app.errorhandler(404)
    def _no_route(_):
        return fail("NOT_FOUND", "no such route", 404)

    @app.errorhandler(405)
    def _bad_method(_):
        return fail("METHOD_NOT_ALLOWED", "method not allowed", 405)

    @app.errorhandler(Exception)
    def _unexpected(exc):                         # never leak stack traces
        if isinstance(exc, HTTPException):        # e.g. malformed multipart body
            code = exc.code or 400
            return fail("INVALID_INPUT" if code < 500 else "INTERNAL_ERROR",
                        exc.name, code if code < 500 else 500)
        app.logger.error("unexpected error (request %s): %s", g.get("request_id"),
                         type(exc).__name__)
        return fail("INTERNAL_ERROR", "internal server error", 500)

    def int_arg(name):
        raw = request.args.get(name)
        if raw is None:
            return None
        if not raw.isdigit() or int(raw) < 1:
            raise ExamCryptoError("INVALID_INPUT", f"{name} must be a positive integer")
        return int(raw)

    # ---------------------------------------------------------------- routes
    @app.get("/api/v1/health")
    def health():
        return jsonify({"status": "OK", "service": "examcrypto", "api_version": "1",
                        "storage": type(service.storage).__name__,
                        "blockchain": getattr(service.blockchain, "MODE", "unknown")})

    def _upload(paper_id=None):
        actor = actor_or_401()
        f = request.files.get("file")
        if f is None:
            raise ExamCryptoError("INVALID_INPUT", "multipart field 'file' is required")
        result = service.seal(plaintext=f.read(), exam_id=request.form.get("exam_id", ""),
                              release_at_utc=request.form.get("release_at_utc", ""),
                              actor=actor, request_id=g.request_id, paper_id=paper_id)
        return jsonify({**result, "request_id": g.request_id}), 201

    @app.post("/api/v1/papers")
    def upload():
        return _upload()

    @app.post("/api/v1/papers/<paper_id>/versions")
    def upload_version(paper_id):
        return _upload(paper_id)

    @app.get("/api/v1/papers/<paper_id>")
    def status(paper_id):
        out = service.status(paper_id=paper_id, actor=actor_or_401(),
                             version=int_arg("version"), request_id=g.request_id)
        return jsonify({**out, "request_id": g.request_id})

    @app.get("/api/v1/papers/<paper_id>/manifest")
    def manifest(paper_id):
        out = service.signed_manifest(paper_id=paper_id, actor=actor_or_401(),
                                      version=int_arg("version"), request_id=g.request_id)
        return jsonify({**out, "request_id": g.request_id})

    @app.post("/api/v1/papers/<paper_id>/release")
    def release(paper_id):
        manifest, plaintext = service.release(paper_id=paper_id, actor=actor_or_401(),
                                              version=int_arg("version"),
                                              request_id=g.request_id)
        name = f"{manifest['paper_id']}_v{manifest['paper_version']}.pdf"
        return Response(plaintext, status=200, mimetype="application/pdf", headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Paper-Id": manifest["paper_id"],
            "X-Paper-Version": str(manifest["paper_version"]),
        })

    @app.post("/api/v1/papers/<paper_id>/anchor")
    def retry_anchor(paper_id):
        out = service.retry_anchor(paper_id=paper_id, actor=actor_or_401(),
                                   version=int_arg("version"), request_id=g.request_id)
        return jsonify({**out, "request_id": g.request_id})

    @app.post("/api/v1/events/anchor")
    def anchor_events():
        out = service.anchor_events(actor=actor_or_401(), request_id=g.request_id)
        return jsonify({**out, "request_id": g.request_id})

    @app.get("/api/v1/events/verify")
    def verify_events():
        out = service.verify_events(actor=actor_or_401(), audit_public=audit_public,
                                    request_id=g.request_id)
        return jsonify({**out, "signatures_checked": audit_public is not None,
                        "request_id": g.request_id})

    if demo_mode and getattr(service.blockchain, "MODE", "") == "mock":
        @app.post("/api/v1/_demo/mock-chain/<paper_id>/approve")
        def demo_approve(paper_id):
            """DEMO ONLY (EXAM_DEMO_MODE=1 + mock chain): plays the custodians' role."""
            version = int_arg("version") or max(service.storage.versions(paper_id) or [1])
            results = []
            for c in range(service.blockchain.threshold):
                try:
                    results.append(service.blockchain.approve_release(paper_id, version, c))
                except ValueError as exc:
                    results.append({"error": str(exc)})
            return jsonify({"mock_custodian_votes": results, "request_id": g.request_id})

    @app.get("/api/v1/events")
    def events():
        limit = int_arg("limit") or 100
        return jsonify({"events": service.recent_events(actor=actor_or_401(), limit=limit,
                                                        request_id=g.request_id),
                        "request_id": g.request_id})

    app.config["EXAMCRYPTO_SERVICE"] = service
    app.extensions["examcrypto_actor"] = actor_or_401      # lets other blueprints reuse auth
    return app
