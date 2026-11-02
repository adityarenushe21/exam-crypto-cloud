# ExamVault capstone project | Aditya Renushe | MIT World Peace University, Pune
# Module: secure upload, post-quantum encryption and cloud storage
# SPDX-License-Identifier: MIT
"""Fixed identifiers for format v1. Changing any of these requires a version bump."""

PROTOCOL = "exam-crypto-cloud"
SCHEMA_VERSION = "1"

KEM_ALGORITHM = "ML-KEM-768"
KDF_ALGORITHM = "HKDF-SHA-256"
AEAD_ALGORITHM = "AES-256-GCM"
HASH_ALGORITHM = "SHA3-256"
SIGNATURE_ALGORITHM = "ML-DSA-65"

SIGNATURE_CONTEXT = "exam-crypto-cloud/manifest/v1"   # ML-DSA context string

AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
HKDF_SALT_BYTES = 32

MAX_UPLOAD_BYTES = 20 * 1024 * 1024        # 20 MB prototype limit
PDF_MAGIC = b"%PDF-"

# Allowed characters for IDs that end up inside AAD/HKDF labels.
ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"
