"""AuthService: login, per-request authentication, and access restrictions.

Login order (every outcome is one audit event, event_type AUTH, action LOGIN):
  1. username format          -> LOGIN_FAILED (generic message, no user enumeration)
  2. account locked?          -> ACCOUNT_LOCKED (5 failures in 15 min -> 15 min lock)
  3. password (scrypt; a dummy hash is checked for unknown users: same timing)
                              -> LOGIN_FAILED (+1 failure)
  4. account disabled         -> LOGIN_FAILED
  5. account restricted       -> ACCOUNT_RESTRICTED
  6. TOTP enabled: no code    -> MFA_REQUIRED; wrong/replayed code -> LOGIN_FAILED (+1 failure)
  7. success: failures cleared, session token issued
"""
import re

from examcrypto.encoding import format_utc, utc_now
from examcrypto.errors import ExamCryptoError
from examcrypto.events import build_event

from . import totp
from .users import USERNAME_RE


class AuthService:
    def __init__(self, users, sessions, restrictions, events, clock=utc_now):
        self.users, self.sessions, self.restrictions, self.events = users, sessions, restrictions, events
        self.clock = clock

    # ------------------------------------------------------------- helpers
    def _event(self, event_type, username, role, reason=None, request_id=None, **fields):
        self.events.emit(build_event(event_type, actor={"actor_id": username or "unknown", "role": role or "unknown"},
                                     reason_code=reason, request_id=request_id, **fields))

    def _fail(self, code, message, username, role=None, request_id=None):
        self._event("AUTH", username, role, code, request_id, action="LOGIN")
        raise ExamCryptoError(code, message)

    # --------------------------------------------------------------- login
    def login(self, username: str, password: str, totp_code: str | None = None, request_id=None) -> dict:
        now = self.clock()
        username = (username or "").strip().lower()
        safe_name = username if USERNAME_RE.match(username) else "invalid"
        generic = "invalid username or password"
        if safe_name == "invalid":
            self.users.check_password("x", password or "")           # keep timing uniform
            self._fail("LOGIN_FAILED", generic, safe_name, request_id=request_id)
        locked = self.users.locked_until(username, now)
        if locked:
            self._fail("ACCOUNT_LOCKED", f"too many failed attempts; try again after {format_utc(locked)}",
                       username, self.users.get(username)["role"], request_id)
        if not self.users.check_password(username, password or ""):
            known = self.users.get(username)
            if known:
                self.users.record_failure(username, now)
            self._fail("LOGIN_FAILED", generic, username, known["role"] if known else None, request_id)
        u = self.users.get(username)
        if not u["active"]:
            self._fail("LOGIN_FAILED", generic, username, u["role"], request_id)
        r = self.restrictions.is_restricted(username, now)
        if r:
            until = r["until_utc"] or "an administrator lifts it"
            self._fail("ACCOUNT_RESTRICTED", f"account restricted until {until}", username, u["role"], request_id)
        if u["totp_secret"]:
            if not totp_code:
                self._fail("MFA_REQUIRED", "enter the 6-digit code from your authenticator app",
                           username, u["role"], request_id)
            step = totp.verify(u["totp_secret"], totp_code, now.timestamp(), u["totp_last_step"])
            if step is None:
                self.users.record_failure(username, now)
                self._fail("LOGIN_FAILED", "invalid or already-used code", username, u["role"], request_id)
            self.users.set_totp_last_step(username, step)
        self.users.clear_failures(username)
        token, expires = self.sessions.create(username, u["role"], now)
        self._event("AUTH", username, u["role"], None, request_id, action="LOGIN")
        return {"token": token, "username": username, "role": u["role"],
                "expires_at_utc": format_utc(expires), "mfa_enabled": bool(u["totp_secret"])}

    def logout(self, token: str, actor: dict, request_id=None) -> None:
        self.sessions.revoke(token)
        self._event("AUTH", actor["actor_id"], actor["role"], None, request_id, action="LOGOUT")

    # ------------------------------------------------ per-request authentication
    @staticmethod
    def bearer(request) -> str:
        h = request.headers.get("Authorization", "")
        return h[7:].strip() if h.startswith("Bearer ") else ""

    def authenticate(self, request) -> dict:
        """Used by examcrypto's API and the admin API for EVERY protected request."""
        now = self.clock()
        s = self.sessions.resolve(self.bearer(request), now)
        if s is None:
            self._event("AUTH", None, None, "AUTH_REQUIRED", action="REQUEST")
            raise ExamCryptoError("AUTH_REQUIRED", "log in first (missing, unknown or expired session)")
        if self.restrictions.is_restricted(s["username"], now):
            self.sessions.revoke_user(s["username"])
            self._event("AUTH", s["username"], s["role"], "ACCOUNT_RESTRICTED", action="REQUEST")
            raise ExamCryptoError("ACCOUNT_RESTRICTED", "this account has been restricted by an administrator")
        u = self.users.get(s["username"])
        if not u or not u["active"] or u["role"] != s["role"]:
            self.sessions.revoke_user(s["username"])
            raise ExamCryptoError("AUTH_REQUIRED", "session no longer valid - log in again")
        return {"actor_id": s["username"], "role": s["role"]}

    # ------------------------------------------------------------ admin actions
    def _admin_event(self, admin, action, target=None, alert_id=None, request_id=None, reason=None):
        self._event("ADMIN_ACTION", admin["actor_id"], admin["role"], reason, request_id,
                    action=action, target_actor_id=target, alert_id=alert_id)

    def restrict(self, admin: dict, username: str, reason: str, hours: float | None = None,
                 alert_id: str | None = None, request_id=None) -> dict:
        now = self.clock()
        username = (username or "").lower()
        if not self.users.exists(username):
            raise ExamCryptoError("INVALID_INPUT", "no such user account")
        if username == admin["actor_id"]:
            raise ExamCryptoError("CONFLICT", "administrators cannot restrict their own account")
        u = self.users.get(username)
        if u["role"] == "admin":
            other_admins = [x for x in self.users.list_public()
                            if x["role"] == "admin" and x["active"] and x["username"] != username
                            and not self.restrictions.is_restricted(x["username"], now)]
            if not other_admins:
                raise ExamCryptoError("CONFLICT", "cannot restrict the last active administrator")
        if hours is not None and not (0 < float(hours) <= 24 * 30):
            raise ExamCryptoError("INVALID_INPUT", "hours must be between 0 and 720")
        if not (reason or "").strip():
            raise ExamCryptoError("INVALID_INPUT", "a reason is required")
        rec = self.restrictions.restrict(username, admin["actor_id"], reason.strip(), now, hours, alert_id)
        revoked = self.sessions.revoke_user(username)
        self._admin_event(admin, "RESTRICT_ACCOUNT", username, alert_id, request_id)
        return {**rec, "sessions_revoked": revoked}

    def unrestrict(self, admin: dict, username: str, reason: str, request_id=None) -> dict:
        now = self.clock()
        username = (username or "").lower()
        if not self.restrictions.is_restricted(username, now):
            raise ExamCryptoError("CONFLICT", "account is not restricted")
        if not (reason or "").strip():
            raise ExamCryptoError("INVALID_INPUT", "a reason is required")
        rec = self.restrictions.lift(username, admin["actor_id"], reason.strip(), now)
        self._admin_event(admin, "LIFT_RESTRICTION", username, None, request_id)
        return rec

    def create_user(self, admin: dict, username: str, role: str, password: str, request_id=None) -> dict:
        from .users import UserError
        try:
            out = self.users.create(username, role, password, self.clock())
        except UserError as exc:
            raise ExamCryptoError("INVALID_INPUT", str(exc)) from exc
        self._admin_event(admin, "CREATE_USER", out["username"], None, request_id)
        return out
