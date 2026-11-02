"""Password hashing with scrypt (memory-hard, Python standard library).

Stored format:  scrypt$<n>$<r>$<p>$<salt_b64>$<hash_b64>
Parameters are stored with each hash, so they can be raised later without breaking
existing accounts.
"""
import base64
import hashlib
import hmac
import os

N, R, P, DKLEN, SALT_BYTES = 2 ** 14, 8, 1, 32, 16
MIN_LENGTH = 10
COMMON = {"password12", "password123", "1234567890", "qwertyuiop", "letmein123", "admin12345",
          "welcome123", "iloveyou12", "exam123456", "mitwpu1234"}


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          dklen=DKLEN, maxmem=64 * 1024 * 1024)


def hash_password(password: str) -> str:
    salt = os.urandom(SALT_BYTES)
    dk = _scrypt(password, salt, N, R, P)
    b = lambda x: base64.b64encode(x).decode("ascii")
    return f"scrypt${N}${R}${P}${b(salt)}${b(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        dk = _scrypt(password, base64.b64decode(salt_b64), int(n), int(r), int(p))
        return hmac.compare_digest(dk, base64.b64decode(dk_b64))
    except (ValueError, TypeError):
        return False


# Used when the username does not exist, so a wrong username takes as long as a wrong
# password (no user-enumeration by timing).
DUMMY_HASH = hash_password("dummy-password-for-timing")


def policy_problems(password: str, username: str = "") -> list[str]:
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"at least {MIN_LENGTH} characters")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    if password.lower() in COMMON:
        problems.append("too common")
    classes = sum(any(f(c) for c in password) for f in (str.islower, str.isupper, str.isdigit,
                                                         lambda c: not c.isalnum()))
    if classes < 2:
        problems.append("mix at least two of: lowercase, uppercase, digits, symbols")
    return problems
