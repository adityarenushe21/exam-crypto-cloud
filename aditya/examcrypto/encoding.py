"""Exact byte/text encodings used by format v1.

- Base64: standard alphabet WITH padding (RFC 4648 section 4).
- Hex: lowercase.
- Time: UTC, second precision, 'YYYY-MM-DDTHH:MM:SSZ'.
- Canonical JSON: sorted keys, no whitespace, ASCII only. Manifest values are
  restricted to ASCII strings and non-negative integers (no floats, no nulls),
  so this output is also valid RFC 8785 (JCS) output - a Node.js teammate can
  reproduce the exact same bytes.
"""

import base64
import binascii
import json
from datetime import datetime, timezone

from .errors import ExamCryptoError, INVALID_INPUT, MANIFEST_MALFORMED

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, AttributeError) as exc:
        raise ExamCryptoError(MANIFEST_MALFORMED, "bad base64 field") from exc


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def format_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ExamCryptoError(INVALID_INPUT, "timestamp must be timezone-aware")
    return dt.astimezone(timezone.utc).strftime(TIME_FORMAT)


def parse_utc(text: str) -> datetime:
    try:
        return datetime.strptime(text, TIME_FORMAT).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError) as exc:
        raise ExamCryptoError(INVALID_INPUT, "time must look like 2026-12-01T09:00:00Z") from exc


def canonical_json(obj: dict) -> bytes:
    _check_canonical_values(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _check_canonical_values(obj: dict) -> None:
    for k, v in obj.items():
        if not isinstance(k, str) or not k.isascii():
            raise ExamCryptoError(MANIFEST_MALFORMED, "keys must be ASCII strings")
        if isinstance(v, bool) or not isinstance(v, (str, int)):
            raise ExamCryptoError(MANIFEST_MALFORMED, f"field {k!r} must be str or int")
        if isinstance(v, str) and not v.isascii():
            raise ExamCryptoError(MANIFEST_MALFORMED, f"field {k!r} must be ASCII")
        if isinstance(v, int) and v < 0:
            raise ExamCryptoError(MANIFEST_MALFORMED, f"field {k!r} must be >= 0")
