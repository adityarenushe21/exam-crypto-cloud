# AWS S3 setup for examcrypto (Milestone 6)

**Status: S3 adapter code is written and tested against a FAKE S3 client only. No AWS
resource has been created. Nothing here has run against real AWS yet.**

Do this only when you are ready, because it uses a real AWS account.

## 0. Cost and safety (read first)

- S3 charges for stored GB, requests and data transfer out. A few test PDFs cost very little,
  and the AWS Free Tier may cover it. Check the current S3 pricing page for your region before
  you start; this guide does not quote prices.
- **SSE-S3 (AES256)** has no extra charge. **SSE-KMS with your own key** adds a monthly key
  charge plus a per-request charge. For the prototype, SSE-S3 is enough. Use KMS only if your
  guide wants it.
- Turn on a **billing alarm / budget** in the AWS console before you create anything.
- **Never** paste access keys into chat, code, `.env` files that get committed, or screenshots.

## 1. Choose names

- Region: `ap-south-1` (Mumbai), close to Pune.
- Bucket: globally unique and lowercase, e.g. `examcrypto-aditya-<random-6-digits>`.

## 2. Create the private bucket (AWS CLI, PowerShell)

Your AWS CLI is 2.28.9 (Milestone 0). Use an **admin** profile only for this setup step:

```powershell
$B = "examcrypto-aditya-123456"     # your bucket name
$R = "ap-south-1"
aws s3api create-bucket --bucket $B --region $R --create-bucket-configuration LocationConstraint=$R
aws s3api put-public-access-block --bucket $B --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
aws s3api put-bucket-encryption --bucket $B --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'
aws s3api put-bucket-versioning --bucket $B --versioning-configuration Status=Enabled
```

Versioning keeps old copies if something is ever deleted. Old versions are billed as stored data.

**Deny non-HTTPS access.** Save this as `bucket-policy.json`, with your bucket name filled in:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyInsecureTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::BUCKET", "arn:aws:s3:::BUCKET/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
  }]
}
```

```powershell
aws s3api put-bucket-policy --bucket $B --policy file://bucket-policy.json
```

## 3. Least-privilege identity for the app

In the IAM console, create a user (or role) called `examcrypto-app` with **only** this inline
policy. It allows no delete permission and no access to any other bucket:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "ListPapersOnly", "Effect": "Allow", "Action": "s3:ListBucket",
     "Resource": "arn:aws:s3:::BUCKET",
     "Condition": {"StringLike": {"s3:prefix": ["papers/*"]}}},
    {"Sid": "ReadWritePaperObjects", "Effect": "Allow",
     "Action": ["s3:PutObject", "s3:GetObject"],
     "Resource": "arn:aws:s3:::BUCKET/papers/*"}
  ]
}
```

- If you set `EXAM_S3_PREFIX` (for example `dev`), change `papers/*` to `dev/papers/*` in both places.
- With SSE-KMS, also allow `kms:GenerateDataKey` and `kms:Decrypt` on that one key's ARN.

Create an access key for `examcrypto-app` and store it **only** in the AWS CLI profile:

```powershell
aws configure --profile examcrypto      # paste the keys here, in your own terminal only
aws sts get-caller-identity --profile examcrypto
```

## 4. Run examcrypto against S3

```powershell
python -m pip install -r requirements-aws.txt
python -m pip show boto3                  # write the version into SELF_DONE_STUFF.txt
$env:AWS_PROFILE = "examcrypto"
$env:AWS_REGION = "ap-south-1"
$env:EXAM_STORAGE = "s3"
$env:EXAM_S3_BUCKET = "examcrypto-aditya-123456"
python -m examcrypto serve
```

The server's start-up line should then say `storage=S3Storage`.

## 5. Checks to record (with real output)

1. Upload through the API, then run `aws s3 ls s3://$B/papers/ --recursive --profile examcrypto`.
   You should see `ciphertext.bin` and `manifest.json`, and nothing else.
2. Run `aws s3 cp s3://$B/papers/<id>/v1/ciphertext.bin . --profile examcrypto` and open the file.
   It should be unreadable bytes, never the PDF.
3. Run `aws s3api put-object --bucket $B --key papers/<id>/v1/ciphertext.bin --body x.bin --if-none-match "*" --profile examcrypto`.
   It should fail with `412 Precondition Failed`, which proves write-once.
4. Open the object URL `https://<bucket>.s3.ap-south-1.amazonaws.com/papers/...` in a browser.
   It should show `AccessDenied`, because there is no public access.
5. Run `aws s3api delete-object ... --profile examcrypto`.
   It should show `AccessDenied`, because the app has no delete permission.

## What S3 encryption does and does not do

S3 encryption (SSE-S3 or SSE-KMS) protects the disks inside AWS. The papers are **already**
ML-KEM-768 + AES-256-GCM ciphertext before they leave your machine, so AWS never sees a
readable paper or any decryption key. AWS KMS is not used for ML-KEM here; the ML-KEM private
key stays in the release service's encrypted key file.
