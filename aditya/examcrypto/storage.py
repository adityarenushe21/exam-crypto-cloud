# ExamVault capstone project | Aditya Renushe | MIT World Peace University, Pune
# Module: secure upload, post-quantum encryption and cloud storage
# SPDX-License-Identifier: MIT
"""Storage adapters: LocalStorage (development) and S3Storage (private AWS bucket).

Object layout (same keys will be used in S3):
    papers/<paper_id>/v<version>/ciphertext.bin
    papers/<paper_id>/v<version>/manifest.json
Objects are WRITE-ONCE: putting an existing key fails.
"""

import re
from pathlib import Path

from .errors import ExamCryptoError, DUPLICATE_VERSION, PAPER_NOT_FOUND, STORAGE_UNAVAILABLE

_KEY_RE = re.compile(r"^papers/[A-Za-z0-9_-]{1,64}/v[0-9]{1,6}/(ciphertext\.bin|manifest\.json)$")


def object_keys(paper_id: str, version: int) -> tuple[str, str]:
    base = f"papers/{paper_id}/v{version}"
    return f"{base}/ciphertext.bin", f"{base}/manifest.json"


class LocalStorage:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _path(self, key: str) -> Path:
        if not _KEY_RE.match(key):              # blocks ../ path tricks
            raise ValueError(f"illegal object key: {key!r}")
        return self.root / key

    def put(self, key: str, data: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(path, "xb") as f:
                f.write(data)
        except FileExistsError as exc:
            raise ExamCryptoError(DUPLICATE_VERSION, f"{key} already exists") from exc

    def get(self, key: str) -> bytes:
        path = self._path(key)
        if not path.exists():
            raise ExamCryptoError(PAPER_NOT_FOUND, f"{key} not found")
        return path.read_bytes()

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def versions(self, paper_id: str) -> list[int]:
        folder = self.root / "papers" / paper_id
        if not folder.is_dir():
            return []
        return sorted(int(p.name[1:]) for p in folder.iterdir()
                      if p.is_dir() and re.fullmatch(r"v[0-9]{1,6}", p.name))

    def list_papers(self) -> list[str]:
        folder = self.root / "papers"
        if not folder.is_dir():
            return []
        return sorted(p.name for p in folder.iterdir()
                      if p.is_dir() and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", p.name))


# ============================================================================ S3
class S3Storage:
    """Same interface as LocalStorage, backed by a PRIVATE Amazon S3 bucket.

    * Write-once: PutObject with If-None-Match: "*" (S3 conditional write), so an
      existing object is never overwritten.
    * Server-side encryption on every object: SSE-KMS if kms_key_id is given,
      otherwise SSE-S3 (AES256). This is an EXTRA storage layer - the objects are
      already ML-KEM/AES-GCM ciphertext before they reach AWS.
    * Credentials come from the AWS CLI profile / environment (never from code).

    `client` can be injected (tests use a fake); otherwise boto3 is imported lazily,
    so the rest of the project does not need boto3 installed.
    """

    def __init__(self, bucket: str, prefix: str = "", client=None, kms_key_id: str | None = None,
                 region: str | None = None):
        if client is None:
            import boto3  # optional dependency: pip install -r requirements-aws.txt
            client = boto3.client("s3", region_name=region)
        self.client = client
        self.bucket = bucket
        self.prefix = prefix.strip("/") + "/" if prefix.strip("/") else ""
        self.kms_key_id = kms_key_id

    def _full(self, key: str) -> str:
        if not _KEY_RE.match(key):
            raise ValueError(f"illegal object key: {key!r}")
        return self.prefix + key

    @staticmethod
    def _code(exc) -> str:
        return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))

    def put(self, key: str, data: bytes) -> None:
        args = {"Bucket": self.bucket, "Key": self._full(key), "Body": data,
                "IfNoneMatch": "*", "ContentType": "application/octet-stream"}
        if self.kms_key_id:
            args.update(ServerSideEncryption="aws:kms", SSEKMSKeyId=self.kms_key_id)
        else:
            args.update(ServerSideEncryption="AES256")
        try:
            self.client.put_object(**args)
        except Exception as exc:
            code = self._code(exc)
            if code in ("PreconditionFailed", "412"):          # object already exists
                raise ExamCryptoError(DUPLICATE_VERSION, f"{key} already exists") from exc
            # 409 Conflict = concurrent delete; AWS says retry -> report as temporary outage
            raise ExamCryptoError(STORAGE_UNAVAILABLE, f"S3 put failed ({code or type(exc).__name__})") from exc

    def get(self, key: str) -> bytes:
        try:
            obj = self.client.get_object(Bucket=self.bucket, Key=self._full(key))
            return obj["Body"].read()
        except ExamCryptoError:
            raise
        except Exception as exc:
            code = self._code(exc)
            if code in ("NoSuchKey", "404", "NotFound"):
                raise ExamCryptoError(PAPER_NOT_FOUND, f"{key} not found") from exc
            raise ExamCryptoError(STORAGE_UNAVAILABLE, f"S3 get failed ({code or type(exc).__name__})") from exc

    def exists(self, key: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket, Key=self._full(key))
            return True
        except Exception as exc:
            if self._code(exc) in ("404", "NoSuchKey", "NotFound"):
                return False
            raise ExamCryptoError(STORAGE_UNAVAILABLE, "S3 head failed") from exc

    def versions(self, paper_id: str) -> list[int]:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", paper_id):
            return []
        prefix = f"{self.prefix}papers/{paper_id}/"
        found, token = set(), None
        try:
            while True:
                args = {"Bucket": self.bucket, "Prefix": prefix, "Delimiter": "/"}
                if token:
                    args["ContinuationToken"] = token
                page = self.client.list_objects_v2(**args)
                for cp in page.get("CommonPrefixes", []):
                    m = re.fullmatch(r"v([0-9]{1,6})/", cp["Prefix"][len(prefix):])
                    if m:
                        found.add(int(m.group(1)))
                if not page.get("IsTruncated"):
                    break
                token = page.get("NextContinuationToken")
        except Exception as exc:
            raise ExamCryptoError(STORAGE_UNAVAILABLE, "S3 list failed") from exc
        return sorted(found)

    def list_papers(self) -> list[str]:
        prefix = f"{self.prefix}papers/"
        found, token = set(), None
        try:
            while True:
                args = {"Bucket": self.bucket, "Prefix": prefix, "Delimiter": "/"}
                if token:
                    args["ContinuationToken"] = token
                page = self.client.list_objects_v2(**args)
                for cp in page.get("CommonPrefixes", []):
                    name = cp["Prefix"][len(prefix):].rstrip("/")
                    if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
                        found.add(name)
                if not page.get("IsTruncated"):
                    break
                token = page.get("NextContinuationToken")
        except Exception as exc:
            raise ExamCryptoError(STORAGE_UNAVAILABLE, "S3 list failed") from exc
        return sorted(found)
