"""Login + administrator API (Flask blueprint), mounted on examcrypto's app.

Roles (PROPOSED names): admin = full control; auditor = read-only oversight;
exam_authority / release_officer use the paper routes of examcrypto's API.
"""
from collections import Counter

from flask import Blueprint, current_app, g, jsonify, request

from examcrypto.errors import ExamCryptoError

READ_ROLES = {"admin", "auditor"}
ADMIN_ROLES = {"admin"}
REVIEW_STATUSES = ("NEW", "ACKNOWLEDGED", "REVIEWING", "CLOSED")


def make_blueprint(ctx) -> Blueprint:
    """ctx: object with .auth, .service, .alerts (AlertStore), .watcher_status(), .chain_health()."""
    bp = Blueprint("controlcenter_api", __name__)

    def body() -> dict:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ExamCryptoError("INVALID_INPUT", "JSON object body required")
        return data

    def need(roles) -> dict:
        actor = ctx.auth.authenticate(request)
        if actor["role"] not in roles:
            ctx.auth._event("ADMIN_ACTION", actor["actor_id"], actor["role"], "ROLE_NOT_ALLOWED",
                            g.get("request_id"), action=f"{request.method} {request.path}"[:60])
            raise ExamCryptoError("ROLE_NOT_ALLOWED", f"role {actor['role']!r} may not do this")
        return actor

    def reply(obj, code=200):
        return jsonify({**obj, "request_id": g.get("request_id")}), code

    # ------------------------------------------------------------------ auth
    @bp.post("/api/v1/auth/login")
    def login():
        b = body()
        return reply(ctx.auth.login(b.get("username", ""), b.get("password", ""), b.get("totp"),
                                    request_id=g.get("request_id")))

    @bp.post("/api/v1/auth/logout")
    def logout():
        actor = ctx.auth.authenticate(request)
        ctx.auth.logout(ctx.auth.bearer(request), actor, g.get("request_id"))
        return reply({"status": "LOGGED_OUT"})

    @bp.get("/api/v1/auth/me")
    def me():
        actor = ctx.auth.authenticate(request)
        return reply({"username": actor["actor_id"], "role": actor["role"],
                      **{k: v for k, v in ctx.auth.users.public(actor["actor_id"]).items() if k in ("mfa_enabled",)}})

    # ------------------------------------------------------------- dashboard
    @bp.get("/api/v1/dashboard/papers")
    def papers():
        actor = need({"admin", "auditor", "exam_authority", "release_officer"})
        verify_actor = {"actor_id": actor["actor_id"], "role": actor["role"]}
        return reply({"papers": ctx.service.list_papers(actor=verify_actor, request_id=g.get("request_id"))})

    @bp.get("/api/v1/dashboard/overview")
    def overview():
        actor = need(READ_ROLES)
        now = ctx.auth.clock()
        plist = ctx.service.list_papers(actor=actor, request_id=g.get("request_id"))
        alerts = list(ctx.alerts.load().values())
        open_alerts = [a for a in alerts if a.get("status") != "CLOSED"]
        events = ctx.service.events.read(limit=0)
        return reply({
            "papers": {"total": len(plist), "by_release_status": dict(Counter(p.get("release_status") for p in plist))},
            "alerts": {"total": len(alerts), "open": len(open_alerts),
                       "open_by_severity": dict(Counter(a.get("severity") for a in open_alerts)),
                       "by_status": dict(Counter(a.get("status") for a in alerts))},
            "access": {"users": len(ctx.auth.users.list_public()),
                       "restricted": len(ctx.auth.restrictions.active(now)),
                       "active_sessions": ctx.auth.sessions.active_count(now)},
            "audit": {"events": len(events), "last_seq": events[-1]["seq"] if events else 0,
                      "denied_or_failed": sum(e.get("result") != "SUCCESS" for e in events)},
            "chain": ctx.chain_health(), "watcher": ctx.watcher_status(),
        })

    # ---------------------------------------------------------------- alerts
    @bp.get("/api/v1/alerts")
    def alerts():
        need(READ_ROLES)
        sev, st = request.args.get("severity"), request.args.get("status")
        items = ctx.alerts.list(severity=sev or None, status=st or None, limit=500)
        return reply({"alerts": list(reversed(items))})

    @bp.post("/api/v1/alerts/<alert_id>/review")
    def review(alert_id):
        admin = need(ADMIN_ROLES)
        b = body()
        status, note = b.get("status"), str(b.get("note", ""))[:500]
        if status not in REVIEW_STATUSES or status == "NEW":
            raise ExamCryptoError("INVALID_INPUT", "status must be ACKNOWLEDGED, REVIEWING or CLOSED")
        if alert_id not in ctx.alerts.load():
            raise ExamCryptoError("PAPER_NOT_FOUND", "no such alert")
        if status == "CLOSED" and not note.strip():
            raise ExamCryptoError("INVALID_INPUT", "closing an alert needs a note (what was decided and why)")
        ctx.alerts.update(alert_id, by=admin["actor_id"], status=status, review_note=note,
                          reviewed_by=admin["actor_id"])
        ctx.auth._admin_event(admin, f"ALERT_{status}", None, alert_id, g.get("request_id"))
        return reply({"alert": ctx.alerts.load()[alert_id]})

    @bp.post("/api/v1/alerts/<alert_id>/restrict")
    def restrict_from_alert(alert_id):
        admin = need(ADMIN_ROLES)
        b = body()
        a = ctx.alerts.load().get(alert_id)
        if a is None:
            raise ExamCryptoError("PAPER_NOT_FOUND", "no such alert")
        target = (a.get("actor_id") or "").lower()
        if not ctx.auth.users.exists(target):
            raise ExamCryptoError("CONFLICT", f"actor {a.get('actor_id')!r} is not a registered account "
                                              "(e.g. anonymous failed logins) - nothing to restrict")
        rec = ctx.auth.restrict(admin, target, b.get("reason") or f"alert {alert_id}: {','.join(a.get('reason_codes', []))}",
                                b.get("hours"), alert_id, g.get("request_id"))
        upd = {"access_action": {"action": "RESTRICTED", "by": admin["actor_id"], "until_utc": rec["until_utc"]}}
        if a.get("status") == "NEW":
            upd["status"] = "REVIEWING"
        ctx.alerts.update(alert_id, by=admin["actor_id"], **upd)
        return reply({"restriction": rec, "alert": ctx.alerts.load()[alert_id]})

    # ---------------------------------------------------------------- access
    @bp.get("/api/v1/access/users")
    def users():
        need(READ_ROLES)
        now = ctx.auth.clock()
        active = ctx.auth.restrictions.active(now)
        return reply({"users": [{**u, "restriction": active.get(u["username"])} for u in ctx.auth.users.list_public()]})

    @bp.post("/api/v1/access/users")
    def create_user():
        admin = need(ADMIN_ROLES)
        b = body()
        return reply({"user": ctx.auth.create_user(admin, b.get("username", ""), b.get("role", ""),
                                                   b.get("password", ""), g.get("request_id"))}, 201)

    @bp.post("/api/v1/access/users/<username>/restrict")
    def restrict(username):
        admin = need(ADMIN_ROLES)
        b = body()
        return reply({"restriction": ctx.auth.restrict(admin, username, b.get("reason", ""), b.get("hours"),
                                                       None, g.get("request_id"))})

    @bp.post("/api/v1/access/users/<username>/unrestrict")
    def unrestrict(username):
        admin = need(ADMIN_ROLES)
        b = body()
        return reply({"lifted": ctx.auth.unrestrict(admin, username, b.get("reason", ""), g.get("request_id"))})

    @bp.get("/api/v1/access/restrictions")
    def restriction_history():
        need(READ_ROLES)
        return reply({"history": list(reversed(ctx.auth.restrictions.history()))})

    # ---------------------------------------------------------------- system
    @bp.get("/api/v1/system/health")
    def health():
        need(READ_ROLES)
        svc = ctx.service
        return reply({"api": "OK", "storage": type(svc.storage).__name__,
                      "chain": ctx.chain_health(), "watcher": ctx.watcher_status(),
                      "audit_log": svc.verify_events(actor={"actor_id": "system", "role": "admin"},
                                                     audit_public=ctx.audit_public),
                      "release_requires_chain": svc.require_chain_release})

    return bp
