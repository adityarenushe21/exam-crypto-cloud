# ExamVault capstone project | Aditya Renushe | MIT World Peace University, Pune
# Module: secure upload, post-quantum encryption and cloud storage
# SPDX-License-Identifier: MIT
"""MOCK authorization. Nayan's real auth/RBAC replaces this later.

Actor = {"actor_id": "...", "role": "..."}. Role names are PROPOSED.
"""

from .errors import ExamCryptoError, ROLE_NOT_ALLOWED

ALLOWED_ROLES = {
    "seal": {"exam_authority"},
    "verify": {"exam_authority", "release_officer", "admin", "auditor"},
    "release": {"release_officer"},
    "read_events": {"admin", "auditor"},
    "anchor_events": {"admin"},
}


def require(actor: dict, action: str) -> None:
    role = actor.get("role") if isinstance(actor, dict) else None
    if role not in ALLOWED_ROLES.get(action, set()):
        raise ExamCryptoError(ROLE_NOT_ALLOWED, f"role {role!r} may not {action}")
