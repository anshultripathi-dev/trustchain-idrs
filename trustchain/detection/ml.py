"""ML layer: Isolation Forest (unsupervised novelty) + Random Forest (attack-class)."""
from __future__ import annotations

import os
import threading
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from .features import FEATURES

CLASSES = ["NORMAL", "BRUTE_FORCE", "REQUEST_FLOOD", "SERVICE_PROBING", "SENSOR_ANOMALY", "STEALTH_SURGE"]
CLF_CONFIDENCE = 0.7
IF_RISK_SCALE = 0.10
IF_MARGIN = 0.03      # an Isolation-Forest anomaly must be clearly past the threshold, not just borderline


class ModelBundle:
    def __init__(self, iforest: IsolationForest, clf: RandomForestClassifier, threshold: float, metrics: dict[str, Any] | None = None):
        clf.n_jobs = 1          # single-sample inference: thread fan-out only adds overhead
        iforest.n_jobs = 1
        self.iforest = iforest
        self.clf = clf
        self.threshold = float(threshold)   # decision_function below this => anomalous
        self.metrics = metrics or {}
        self.features = FEATURES
        self.classes = list(clf.classes_)

    def score_batch(self, X: np.ndarray) -> list[dict[str, Any]]:
        X = np.atleast_2d(X)
        s = self.iforest.decision_function(X)
        proba = self.clf.predict_proba(X)
        out = []
        for i in range(len(X)):
            j = int(np.argmax(proba[i]))
            cls = self.classes[j]
            anomalous = bool(s[i] < self.threshold - IF_MARGIN)
            out.append({
                "if_score": float(s[i]),
                "if_anomaly": anomalous,
                "ml_risk": float(min(1.0, max(0.0, (self.threshold - s[i]) / IF_RISK_SCALE))) if anomalous else 0.0,
                "cls": cls,
                "cls_conf": float(proba[i][j]),
                "cls_attack": bool(cls != "NORMAL" and proba[i][j] >= CLF_CONFIDENCE),
            })
        return out

    def score(self, x: np.ndarray) -> dict[str, Any]:
        return self.score_batch(x)[0]

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: str) -> "ModelBundle | None":
        if not os.path.exists(path):
            return None
        try:
            obj = joblib.load(path)
            return obj if isinstance(obj, ModelBundle) else None
        except Exception:  # stale pickle from another sklearn version -> retrain
            return None


_train_lock = threading.Lock()
