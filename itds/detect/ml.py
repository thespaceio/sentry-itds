"""Isolation Forest detector.

Rules catch what someone thought to write down; z-scores catch one feature at
a time. The forest catches combinations: a day that is unremarkable on every
single axis but unlike any day anyone has had before.

It is unsupervised because labelled insider threat data does not exist in any
organization at useful scale. It is trained on history only (the pipeline
enforces that) and on log-scaled features, because activity volumes are
heavy-tailed and a raw-bytes axis would drown every other signal.

Explanations use leave-one-out attribution: for each feature, put it back to
the training median and measure how much less anomalous the day becomes. It is
not Shapley, but it ranks drivers correctly in practice and costs twenty
model calls per flagged day rather than thousands.
"""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from ..baseline.profiler import FEATURE_NAMES, DailyFeatures
from ..config import MLConfig
from .attack import techniques_for_features
from .base import FEATURE_LABELS, Detection, fmt_value

MIN_TRAINING_DAYS = 50
MAX_CONFIDENCE = 0.8


def _transform(x: np.ndarray) -> np.ndarray:
    return np.log1p(np.maximum(x, 0.0))


class AnomalyDetector:
    def __init__(self, config: MLConfig | None = None) -> None:
        self.config = config or MLConfig()
        self.model: IsolationForest | None = None
        self._median: np.ndarray | None = None

    @property
    def is_fitted(self) -> bool:
        return self.model is not None

    def fit(self, training: list[DailyFeatures]) -> AnomalyDetector:
        if len(training) < MIN_TRAINING_DAYS:
            self.model = None
            return self
        X = _transform(np.vstack([f.vector() for f in training]))
        c = self.config
        self.model = IsolationForest(
            n_estimators=c.n_estimators,
            contamination=c.contamination,
            max_samples=c.max_samples,
            random_state=c.random_state,
        ).fit(X)
        self._median = np.median(X, axis=0)
        return self

    def anomaly_score(self, features: DailyFeatures) -> float:
        """Paper-scale anomaly score in (0, 1): ~0.5 ordinary, towards 1 anomalous."""
        if self.model is None:
            return 0.0
        x = _transform(features.vector()).reshape(1, -1)
        return float(-self.model.score_samples(x)[0])

    def score_batch(self, features: list[DailyFeatures]) -> list[float]:
        """Anomaly scores for many days in one model call (much faster)."""
        if self.model is None or not features:
            return [0.0] * len(features)
        X = _transform(np.vstack([f.vector() for f in features]))
        return [float(v) for v in -self.model.score_samples(X)]

    def attribution(self, features: DailyFeatures) -> list[tuple[str, float]]:
        """Leave-one-out drivers, largest first: (feature, score reduction)."""
        assert self.model is not None and self._median is not None
        x = _transform(features.vector())
        base = -self.model.score_samples(x.reshape(1, -1))[0]
        trials = np.tile(x, (len(FEATURE_NAMES), 1))
        idx = np.arange(len(FEATURE_NAMES))
        trials[idx, idx] = self._median
        scores = -self.model.score_samples(trials)
        drops = base - scores
        order = np.argsort(-drops)
        return [(FEATURE_NAMES[i], float(drops[i])) for i in order if drops[i] > 0.005]

    def evaluate(self, features: DailyFeatures, *, baseline_kind: str = "self",
                 score: float | None = None) -> list[Detection]:
        if self.model is None:
            return []
        if score is None:
            score = self.anomaly_score(features)
        if score < self.config.score_threshold:
            return []
        ranked = self.attribution(features)
        # Lead with drivers that are present; "0 B emailed" explains little.
        drivers = ([d for d in ranked if features.get(d[0]) > 0] or ranked)[:3]
        if not drivers:
            return []
        names = [n for n, _ in drivers]
        parts = [f"{FEATURE_LABELS[n]} {fmt_value(n, features.get(n))}" for n in names]
        # Only claim ATT&CK techniques for drivers that are genuinely elevated,
        # not for a feature that is merely unusual at a tiny value.
        typical = np.expm1(self._median)
        elevated = [
            n for n in names
            if features.get(n) > 0
            and features.get(n) >= max(2.0, 3 * typical[FEATURE_NAMES.index(n)])
        ]
        confidence = min(MAX_CONFIDENCE, 0.4 + (score - self.config.score_threshold) * 3)
        if baseline_kind != "self":
            confidence *= 0.8
        severity = "high" if score >= self.config.score_threshold + 0.1 else "medium"
        tags = []
        if features.get("night_event_count") >= 10:
            tags.append("off_hours")
        if features.get("restricted_file_count") >= 10:
            tags.append("restricted_data")
        return [
            Detection(
                actor_id=features.actor_id,
                day=features.day,
                engine="ml",
                name="behavioural_anomaly",
                title="Unusual combination of activity",
                severity=severity,
                confidence=confidence,
                explanation=(
                    f"A day unlike the organization's history (anomaly score {score:.2f}). "
                    f"Main drivers: {'; '.join(parts)}."
                ),
                evidence={
                    "anomaly_score": round(score, 3),
                    "drivers": {n: round(d, 3) for n, d in drivers},
                    "values": {n: features.get(n) for n in names},
                },
                tags=tags,
                attack=techniques_for_features(elevated),
            )
        ]
