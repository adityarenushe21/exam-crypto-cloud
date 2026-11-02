"""TOTP two-factor codes (RFC 6238 / RFC 4226), standard library only.

Works with Google Authenticator, Microsoft Authenticator, etc.: add the secret (or the
otpauth:// URI) to the app. Codes are 6 digits, 30-second steps, +-1 step clock drift.
A code can be used only once (replay protection via the last accepted step).
"""
import base64
import hashlib
import hmac
import secrets
import struct
import urllib.parse

STEP, DIGITS, WINDOW = 30, 6, 1


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret_b32: str) -> bytes:
    s = secret_b32.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(key: bytes, counter: int, digits: int = DIGITS, algo=hashlib.sha1) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), algo).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def code_at(secret_b32: str, unix_time: float) -> str:
    return hotp(_key(secret_b32), int(unix_time) // STEP)


def verify(secret_b32: str, code: str, unix_time: float, last_step: int | None = None) -> int | None:
    """Returns the matched time step, or None. Rejects steps <= last_step (replay)."""
    code = (code or "").strip()
    if not (code.isdigit() and len(code) == DIGITS):
        return None
    now_step = int(unix_time) // STEP
    key = _key(secret_b32)
    for step in range(now_step - WINDOW, now_step + WINDOW + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(hotp(key, step), code):
            return step
    return None


def provisioning_uri(secret_b32: str, username: str, issuer: str = "ExamCryptoCloud") -> str:
    label = urllib.parse.quote(f"{issuer}:{username}")
    q = urllib.parse.urlencode({"secret": secret_b32, "issuer": issuer, "digits": DIGITS, "period": STEP})
    return f"otpauth://totp/{label}?{q}"
