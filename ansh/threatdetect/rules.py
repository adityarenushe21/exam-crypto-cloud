"""Transparent rule baseline. Each rule adds points and a human-readable reason code.
Thresholds are prototype values chosen against the synthetic scenarios - documented,
tested, and meant to be tuned, not universal security constants."""

from .features import FEATURES

IDX = {n: i for i, n in enumerate(FEATURES)}

# (reason_code, points, test(features) -> bool, description)
RULES = [
    ("INTEGRITY_FAILURE", 80, lambda f: f[IDX["integrity_fail_1h"]] >= 1,
     "signature/digest/decryption check failed - possible tampering"),
    ("AUTH_FAILURE_BURST", 75, lambda f: f[IDX["auth_fail_10m"]] >= 8,
     ">= 8 failed logins / requests without a valid token in 10 minutes"),
    ("EARLY_RELEASE_PROBING", 75, lambda f: f[IDX["early_release_1h"]] >= 4,
     ">= 4 release attempts before the paper was releasable in 1 hour"),
    ("BLOCKED_PAPER_ACCESS", 70, lambda f: f[IDX["blocked_paper_1h"]] >= 2,
     "repeated attempts on a frozen/revoked/compromised paper, or by a restricted account"),
    ("ROLE_PROBING", 70, lambda f: f[IDX["role_denied_1h"]] >= 3,
     ">= 3 actions outside the actor's role in 1 hour"),
    ("OFF_HOURS_BULK_ACCESS", 65, lambda f: f[IDX["off_hours"]] == 1 and f[IDX["distinct_papers_1h"]] >= 5,
     "many different papers touched outside 08:00-20:00 IST"),
    ("HIGH_REQUEST_RATE", 45, lambda f: f[IDX["events_10m"]] >= 15,
     ">= 15 requests in 10 minutes"),
    ("REPEATED_DENIALS", 40, lambda f: f[IDX["denied_10m"]] >= 3,
     ">= 3 denied requests in 10 minutes"),
]


def evaluate(features: list[float]) -> tuple[int, list[str]]:
    """Returns (score 0-100, reason codes). Score = highest rule + 5 per extra rule, capped."""
    hits = [(code, pts) for code, pts, test, _ in RULES if test(features)]
    if not hits:
        return 0, []
    hits.sort(key=lambda x: -x[1])
    score = min(100, hits[0][1] + 5 * (len(hits) - 1))
    return score, [c for c, _ in hits]
