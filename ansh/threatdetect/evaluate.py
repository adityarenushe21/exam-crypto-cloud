"""Honest evaluation on LABELLED SYNTHETIC data.

* Train on one synthetic run (seed A), test on an independent run (seed B).
* Report every detector separately (rules, Isolation Forest, Random Forest) and combined.
* Event level: precision, recall, F1, false-positive rate, confusion matrix.
* Episode level: an attack episode counts as detected if ANY of its events is >= MEDIUM.
* Unseen attack: retrain the Random Forest WITHOUT one attack type and check whether the
  combined system still catches it (this is what real, novel attacks look like).
"""

from collections import defaultdict

import numpy as np

from . import rules
from .features import extract
from .model import ThreatModel
from .scoring import IF_WEIGHT, MEDIUM
from .synthetic import ATTACKS, generate


def _metrics(y, pred) -> dict:
    y, pred = np.asarray(y), np.asarray(pred)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0,
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
            "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}}


def _scores(model, X):
    rule = np.array([rules.evaluate(x)[0] for x in X], dtype=float)
    rf = 100 * model.attack_proba(X)
    iso = IF_WEIGHT * model.anomaly(X)
    return {"rules": rule, "isolation_forest": iso, "random_forest": rf,
            "combined": np.maximum.reduce([rule, rf, iso])}


def _episodes(labels, scenarios):
    """{(kind, episode_id): [event indexes]} - one entry per generated attack."""
    eps = defaultdict(list)
    for i, (lab, sc) in enumerate(zip(labels, scenarios)):
        if lab:
            eps[(sc.split("#")[0], sc)].append(i)
    return eps


def run(train_seed: int = 1, test_seed: int = 2, days: int = 60, holdout: str = "off_hours_bulk_access"):
    """Seeds: 1 = training, 3 = validation (used while designing thresholds), 2 = final test."""
    tr_ev, tr_y, _ = generate(days=days, seed=train_seed)
    te_ev, te_y, te_sc = generate(days=days, seed=test_seed)
    Xtr, Xte = extract(tr_ev), extract(te_ev)
    model = ThreatModel.train(Xtr, tr_y)
    sc = _scores(model, Xte)

    report = {"data": "LABELLED SYNTHETIC (threatdetect.synthetic)",
              "train": {"seed": train_seed, "events": len(tr_y), "attack_events": int(sum(tr_y))},
              "test": {"seed": test_seed, "events": len(te_y), "attack_events": int(sum(te_y))},
              "threshold": f"alert if score >= {MEDIUM} (MEDIUM)", "event_level": {}, "episode_level": {}}
    for name, s in sc.items():
        report["event_level"][name] = _metrics(te_y, (s >= MEDIUM).astype(int))

    eps = _episodes(te_y, te_sc)
    for kind in ATTACKS:
        ks = [idx for (k, _), idx in eps.items() if k == kind]
        report["episode_level"][kind] = {
            name: f"{sum(any(s[i] >= MEDIUM for i in idx) for idx in ks)}/{len(ks)}" for name, s in sc.items()}

    # unseen attack type: RF never sees `holdout` during training
    kinds = tuple(k for k in ATTACKS if k != holdout)
    h_ev, h_y, _ = generate(days=days, seed=train_seed, kinds=kinds)
    m2 = ThreatModel.train(extract(h_ev), h_y)
    s2 = _scores(m2, Xte)
    ks = [idx for (k, _), idx in eps.items() if k == holdout]
    report["unseen_attack"] = {
        "held_out_type": holdout,
        "episodes_detected": {name: f"{sum(any(s[i] >= MEDIUM for i in idx) for idx in ks)}/{len(ks)}"
                              for name, s in s2.items()},
        "false_positive_rate_combined": _metrics(te_y, (s2["combined"] >= MEDIUM).astype(int))["false_positive_rate"],
    }
    return report, model


def to_markdown(r: dict) -> str:
    out = ["# threatdetect evaluation (LABELLED SYNTHETIC data)", "",
           f"Train: seed {r['train']['seed']}, {r['train']['events']} events "
           f"({r['train']['attack_events']} attack). Test: independent seed {r['test']['seed']}, "
           f"{r['test']['events']} events ({r['test']['attack_events']} attack). {r['threshold']}.", "",
           "## Event level", "", "| Detector | Precision | Recall | F1 | False-positive rate | TP/FP/FN/TN |",
           "|---|---|---|---|---|---|"]
    for n, m in r["event_level"].items():
        c = m["confusion"]
        out.append(f"| {n} | {m['precision']} | {m['recall']} | {m['f1']} | {m['false_positive_rate']} | "
                   f"{c['tp']}/{c['fp']}/{c['fn']}/{c['tn']} |")
    out += ["", "## Episode level (detected / episodes)", "",
            "| Scenario | Rules | Isolation Forest | Random Forest | Combined |", "|---|---|---|---|---|"]
    for k, v in r["episode_level"].items():
        out.append(f"| {k} | {v['rules']} | {v['isolation_forest']} | {v['random_forest']} | {v['combined']} |")
    u = r["unseen_attack"]
    out += ["", f"## Unseen attack type: `{u['held_out_type']}` removed from training", "",
            "| Rules | Isolation Forest | Random Forest | Combined | Combined FPR |", "|---|---|---|---|---|",
            f"| {u['episodes_detected']['rules']} | {u['episodes_detected']['isolation_forest']} | "
            f"{u['episodes_detected']['random_forest']} | {u['episodes_detected']['combined']} | "
            f"{u['false_positive_rate_combined']} |", "",
            "**Limits:** synthetic data written by the same team that wrote the rules, so these numbers are "
            "optimistic and are NOT a measure of real-world accuracy. They show the pipeline works and how "
            "the detectors complement each other."]
    return "\n".join(out) + "\n"
