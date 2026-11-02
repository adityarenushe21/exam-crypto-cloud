"""controlcenter - access control, alert review and administrator dashboard.

Originally Nayan's module (Alerting, Access Control & Administrator Dashboard); built by
Aditya after the team changed. Runs as ONE server together with
Aditya's examcrypto API and Ansh's threat detector:

    login (scrypt + optional TOTP + lockout) -> session token -> every API call
    restricted accounts are refused everywhere; admins review AI alerts and restrict
    accounts (human decision; the AI only recommends); every admin action is an
    audit event in examcrypto's signed, hash-chained log.
"""
__version__ = "0.1.0"
