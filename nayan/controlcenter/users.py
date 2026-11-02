"""User accounts (JSON file in the git-ignored keys folder, written atomically).

Never stored: plaintext passwords. The TOTP secret is stored (it must be, to check codes);
the keys folder must stay private, like the other key files.
"""
import json
import os
import re
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .passwords import hash_password, policy_problems, verify_password
from .totp import generate_secret

ROLES = ("exam_authority", "release_officer", "admin", "auditor")
USERNAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,31}$")
MAX_FAILURES, FAILURE_WINDOW, LOCK_TIME = 5, timedelta(minutes=15), timedelta(minutes=15)
FMT = "%Y-%m-%dT%H:%M:%SZ"


class UserError(ValueError):
    pass


def _fmt(dt):
    return dt.astimezone(timezone.utc).strftime(FMT)


def _parse(s):
    return datetime.strptime(s, FMT).replace(tzinfo=timezone.utc)


class UserStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()

    # ------------------------------------------------------------ persistence
    def _load(self) -> dict:
        if not self.path.exists():
            return {"version": 1, "users": {}}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)                     # atomic on Windows and Linux

    # ------------------------------------------------------------------ admin
    def create(self, username: str, role: str, password: str, now: datetime) -> dict:
        username = (username or "").strip().lower()
        if not USERNAME_RE.match(username):
            raise UserError("username: 3-32 chars, start with a letter; a-z 0-9 . _ -")
        if role not in ROLES:
            raise UserError(f"role must be one of {', '.join(ROLES)}")
        problems = policy_problems(password, username)
        if problems:
            raise UserError("weak password: " + "; ".join(problems))
        with self._lock:
            data = self._load()
            if username in data["users"]:
                raise UserError("username already exists")
            data["users"][username] = {"role": role, "password_hash": hash_password(password),
                                       "active": True, "created_at": _fmt(now), "totp_secret": None,
                                       "totp_last_step": None, "failures": [], "locked_until": None}
            self._save(data)
        return self.public(username)

    def set_password(self, username: str, password: str) -> None:
        problems = policy_problems(password, username)
        if problems:
            raise UserError("weak password: " + "; ".join(problems))
        self._update(username, password_hash=hash_password(password))

    def enable_totp(self, username: str) -> str:
        secret = generate_secret()
        self._update(username, totp_secret=secret, totp_last_step=None)
        return secret

    def disable_totp(self, username: str) -> None:
        self._update(username, totp_secret=None, totp_last_step=None)

    def set_active(self, username: str, active: bool) -> None:
        self._update(username, active=bool(active))

    # --------------------------------------------------------------- queries
    def get(self, username: str) -> dict | None:
        return self._load()["users"].get((username or "").lower())

    def exists(self, username: str) -> bool:
        return self.get(username) is not None

    def public(self, username: str) -> dict:
        u = self.get(username)
        return {"username": username, "role": u["role"], "active": u["active"],
                "mfa_enabled": bool(u["totp_secret"]), "created_at": u["created_at"],
                "locked_until": u["locked_until"]}

    def list_public(self) -> list[dict]:
        return [self.public(n) for n in sorted(self._load()["users"])]

    def count_role(self, role: str) -> int:
        return sum(1 for u in self._load()["users"].values() if u["role"] == role and u["active"])

    # ----------------------------------------------------------- login state
    def check_password(self, username: str, password: str) -> bool:
        u = self.get(username)
        from .passwords import DUMMY_HASH
        ok = verify_password(password, u["password_hash"] if u else DUMMY_HASH)
        return bool(u) and ok

    def locked_until(self, username: str, now: datetime) -> datetime | None:
        u = self.get(username)
        if u and u["locked_until"] and _parse(u["locked_until"]) > now:
            return _parse(u["locked_until"])
        return None

    def record_failure(self, username: str, now: datetime) -> datetime | None:
        """Returns the lock expiry if this failure caused a lock."""
        with self._lock:
            data = self._load()
            u = data["users"].get(username)
            if not u:
                return None
            recent = [t for t in u["failures"] if now - _parse(t) <= FAILURE_WINDOW] + [_fmt(now)]
            u["failures"], locked = recent, None
            if len(recent) >= MAX_FAILURES:
                locked = now + LOCK_TIME
                u["locked_until"], u["failures"] = _fmt(locked), []
            self._save(data)
            return locked

    def clear_failures(self, username: str) -> None:
        self._update(username, failures=[], locked_until=None)

    def set_totp_last_step(self, username: str, step: int) -> None:
        self._update(username, totp_last_step=step)

    def _update(self, username: str, **fields) -> None:
        with self._lock:
            data = self._load()
            if username not in data["users"]:
                raise UserError("no such user")
            data["users"][username].update(fields)
            self._save(data)
