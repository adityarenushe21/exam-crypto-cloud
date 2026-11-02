# threatdetect evaluation (LABELLED SYNTHETIC data)

Train: seed 1, 1835 events (462 attack). Test: independent seed 2, 1806 events (450 attack). alert if score >= 40 (MEDIUM).

## Event level

| Detector | Precision | Recall | F1 | False-positive rate | TP/FP/FN/TN |
|---|---|---|---|---|---|
| rules | 1.0 | 0.8489 | 0.9183 | 0.0 | 382/0/68/1356 |
| isolation_forest | 0.9735 | 0.4889 | 0.6509 | 0.0044 | 220/6/230/1350 |
| random_forest | 0.9867 | 0.9911 | 0.9889 | 0.0044 | 446/6/4/1350 |
| combined | 0.9802 | 0.9911 | 0.9856 | 0.0066 | 446/9/4/1347 |

## Episode level (detected / episodes)

| Scenario | Rules | Isolation Forest | Random Forest | Combined |
|---|---|---|---|---|
| early_release_probing | 6/6 | 6/6 | 6/6 | 6/6 |
| credential_stuffing | 6/6 | 4/6 | 6/6 | 6/6 |
| role_probing | 6/6 | 6/6 | 6/6 | 6/6 |
| tampering | 6/6 | 0/6 | 6/6 | 6/6 |
| off_hours_bulk_access | 6/6 | 1/6 | 6/6 | 6/6 |
| blocked_paper_access | 6/6 | 3/6 | 6/6 | 6/6 |

## Unseen attack type: `off_hours_bulk_access` removed from training

| Rules | Isolation Forest | Random Forest | Combined | Combined FPR |
|---|---|---|---|---|
| 6/6 | 1/6 | 0/6 | 6/6 | 0.0081 |

**Limits:** synthetic data written by the same team that wrote the rules, so these numbers are optimistic and are NOT a measure of real-world accuracy. They show the pipeline works and how the detectors complement each other.
