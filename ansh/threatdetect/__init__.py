"""threatdetect - AI-based threat detection for the exam-paper security system.

Reads the signed, hash-chained audit events written by examcrypto (Aditya's module),
turns them into behavioural features, and scores each event with
  * transparent rules (baseline),
  * Isolation Forest (unsupervised anomaly detection, trained on normal behaviour),
  * Random Forest (supervised, trained on a LABELLED SYNTHETIC dataset),
then produces explainable alerts (risk score, severity, reasons, recommended action).

Student prototype. Model output is a signal for human review / access control,
not proof that a person is malicious.
"""
__version__ = "0.1.0"
MODEL_NAME = "threatdetect-rules+iforest+rf"
