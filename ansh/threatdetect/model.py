"""Isolation Forest + Random Forest training, persistence, scoring and explanation.

Explanations: SHAP is not a dependency here. For the Random Forest we use the exact
"decision-path" decomposition (Saabas / treeinterpreter): for each tree, the change in
the predicted attack probability at every split is credited to that split's feature.
Property (tested): bias + sum(contributions) == predict_proba exactly.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from . import MODEL_NAME, __version__
from .features import FEATURES


class ThreatModel:
    def __init__(self, iforest, rf, if_low: float, if_high: float, meta: dict):
        self.iforest, self.rf = iforest, rf
        self.if_low, self.if_high = if_low, if_high      # normalisation anchors
        self.meta = meta

    # ---------------------------------------------------------------- train
    @classmethod
    def train(cls, X, y, seed: int = 7, notes: str = "") -> "ThreatModel":
        X, y = np.asarray(X, dtype=float), np.asarray(y, dtype=int)
        normal = X[y == 0]
        iforest = IsolationForest(n_estimators=300, contamination="auto", random_state=seed).fit(normal)
        raw = -iforest.score_samples(normal)              # higher = more anomalous
        # anchors from NORMAL training data only (no labels involved):
        # anomaly 0 at the 97th percentile of normal behaviour, 1 at the 99.9th
        if_low, if_high = float(np.percentile(raw, 97)), float(np.percentile(raw, 99.9))
        rf = RandomForestClassifier(n_estimators=200, max_depth=8, min_samples_leaf=2,
                                    class_weight="balanced", random_state=seed).fit(X, y)
        meta = {
            "model_name": MODEL_NAME, "threatdetect_version": __version__,
            "sklearn_version": sklearn.__version__, "numpy_version": np.__version__,
            "features": FEATURES, "trained_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "n_train": int(len(y)), "n_attack": int(y.sum()), "seed": seed,
            "training_data": "LABELLED SYNTHETIC data (threatdetect.synthetic)", "notes": notes,
        }
        return cls(iforest, rf, if_low, if_high, meta)

    # ---------------------------------------------------------------- score
    def anomaly(self, X) -> np.ndarray:
        raw = -self.iforest.score_samples(np.asarray(X, dtype=float))
        return np.clip((raw - self.if_low) / max(self.if_high - self.if_low, 1e-9), 0.0, 1.0)

    def attack_proba(self, X) -> np.ndarray:
        proba = self.rf.predict_proba(np.asarray(X, dtype=float))
        classes = list(self.rf.classes_)
        return proba[:, classes.index(1)] if 1 in classes else np.zeros(len(proba))

    # -------------------------------------------------------------- explain
    def contributions(self, x) -> tuple[float, np.ndarray]:
        """(bias, per-feature contribution) for the attack class, averaged over trees."""
        x = np.asarray(x, dtype=float).reshape(1, -1)
        cls_idx = list(self.rf.classes_).index(1) if 1 in self.rf.classes_ else None
        bias, contrib = 0.0, np.zeros(x.shape[1])
        if cls_idx is None:
            return 0.0, contrib
        for est in self.rf.estimators_:
            tree = est.tree_
            vals = tree.value[:, 0, :]
            vals = vals / vals.sum(axis=1, keepdims=True)  # class proportions per node
            path = est.decision_path(x).indices            # root -> leaf, in order
            bias += vals[path[0], cls_idx]
            for parent, child in zip(path[:-1], path[1:]):
                contrib[tree.feature[parent]] += vals[child, cls_idx] - vals[parent, cls_idx]
        n = len(self.rf.estimators_)
        return bias / n, contrib / n

    def top_features(self, x, k: int = 3) -> list[dict]:
        _, c = self.contributions(x)
        order = np.argsort(-c)[:k]
        return [{"feature": FEATURES[i], "value": float(np.asarray(x)[i]),
                 "contribution": round(float(c[i]), 4)} for i in order if c[i] > 0]

    # -------------------------------------------------------------- persist
    def save(self, folder: str | Path) -> None:
        folder = Path(folder)
        folder.mkdir(parents=True, exist_ok=True)
        joblib.dump({"iforest": self.iforest, "rf": self.rf, "if_low": self.if_low,
                     "if_high": self.if_high}, folder / "model.joblib")
        (folder / "model_meta.json").write_text(json.dumps(self.meta, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, folder: str | Path) -> "ThreatModel":
        """joblib uses pickle: ONLY load model files you trained yourself."""
        folder = Path(folder)
        meta = json.loads((folder / "model_meta.json").read_text(encoding="utf-8"))
        if meta.get("features") != FEATURES:
            raise ValueError("model was trained with a different feature list - retrain it")
        d = joblib.load(folder / "model.joblib")
        return cls(d["iforest"], d["rf"], d["if_low"], d["if_high"], meta)
