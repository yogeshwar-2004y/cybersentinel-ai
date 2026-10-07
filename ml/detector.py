"""Isolation Forest on log-scaled numeric telemetry with reference-only normalization."""

from __future__ import annotations
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from config import FEATURES
from utils import validate_logs, stable_id


class AnomalyDetector:
    def __init__(self, contamination: float = 0.08, random_state: int = 42) -> None:
        self.contamination = contamination
        self.random_state = random_state
        self.model: IsolationForest | None = None
        self.reference_scores = np.array([], dtype=float)
        self.reference_id = ""

    def fit(self, reference: pd.DataFrame) -> "AnomalyDetector":
        """Fit only on explicitly supplied reference data; scoring never refits."""
        frame = validate_logs(reference)
        if len(frame) < 32:
            raise ValueError("At least 32 reference rows are required.")
        x = np.log1p(frame[list(FEATURES)].to_numpy(dtype=float))
        self.model = IsolationForest(
            n_estimators=200,
            max_samples=min(1024, len(frame)),
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=1,
        )
        self.model.fit(x)
        self.reference_scores = np.sort(-self.model.score_samples(x))
        self.reference_id = stable_id(
            {
                "features": frame[list(FEATURES)].to_dict("list"),
                "contamination": self.contamination,
                "seed": self.random_state,
                "estimators": 200,
                "max_samples": min(1024, len(frame)),
                "transform": "log1p:v1",
            },
            "MODEL",
        )
        return self

    def score(self, logs: pd.DataFrame) -> pd.DataFrame:
        """Return -1 anomaly, +1 normal; higher anomaly score means more unusual."""
        if self.model is None:
            raise RuntimeError("Fit the detector on reference data before scoring.")
        frame = validate_logs(logs)
        x = np.log1p(frame[list(FEATURES)].to_numpy(dtype=float))
        scores = -self.model.score_samples(x)
        percentile = np.searchsorted(self.reference_scores, scores, side="right") / len(self.reference_scores)
        frame["prediction"] = self.model.predict(x).astype(int)
        frame["anomaly_score"] = scores
        frame["decision_function"] = self.model.decision_function(x)
        # Distance from the model decision boundary is a heuristic, NOT a probability.
        boundary = 1 - self.contamination
        conf = np.where(
            percentile >= boundary,
            0.5 + 0.5 * (percentile - boundary) / self.contamination,
            0.5 + 0.5 * (boundary - percentile) / boundary,
        )
        frame["confidence"] = np.clip(conf, 0.5, 1)
        frame["reference_percentile"] = percentile
        frame["model_id"] = self.reference_id
        return frame

    def save_metadata(self, path: Path) -> None:
        """Write non-executable model metadata; use trainer to reproduce the estimator."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "model_id": self.reference_id,
                    "features": FEATURES,
                    "contamination": self.contamination,
                    "seed": self.random_state,
                },
                indent=2,
            )
        )
