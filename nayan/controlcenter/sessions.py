"""Login sessions: random bearer tokens, stored ONLY as SHA-256 hashes, in memory.

Idle timeout 30 min, absolute lifetime 8 h, revocable (logout, restriction).
Restarting the server logs everyone out (documented prototype behaviour).
"""
import hashlib
import secrets
import threading
from datetime import datetime, timedelta

IDLE, ABSOLUTE = timedelta(minutes=30), timedelta(hours=8)


def _h(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SessionManager:
    def __init__(self, idle: timedelta = IDLE, absolute: timedelta = ABSOLUTE):
        self.idle, self.absolute = idle, absolute
        self._s = {}
        self._lock = threading.Lock()

    def create(self, username: str, role: str, now: datetime) -> tuple[str, datetime]:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._s[_h(token)] = {"username": username, "role": role, "created": now, "seen": now}
        return token, min(now + self.idle, now + self.absolute)

    def resolve(self, token: str, now: datetime) -> dict | None:
        if not token:
            return None
        key = _h(token)
        with self._lock:
            s = self._s.get(key)
            if not s:
                return None
            if now - s["seen"] > self.idle or now - s["created"] > self.absolute:
                del self._s[key]
                return None
            s["seen"] = now
            return dict(s)

    def revoke(self, token: str) -> None:
        with self._lock:
            self._s.pop(_h(token or ""), None)

    def revoke_user(self, username: str) -> int:
        with self._lock:
            keys = [k for k, s in self._s.items() if s["username"] == username]
            for k in keys:
                del self._s[k]
            return len(keys)

    def active_count(self, now: datetime) -> int:
        with self._lock:
            return sum(1 for s in self._s.values()
                       if now - s["seen"] <= self.idle and now - s["created"] <= self.absolute)
