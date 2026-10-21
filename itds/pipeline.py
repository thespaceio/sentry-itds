"""The pipeline.

Wires collection through to a ranked case queue. Every stage is independently
testable and independently replaceable; this module only decides the order and
carries state between them.

Training and scoring are deliberately separated by ``as_of``. Baselines and the
ML model are fitted on data strictly *before* the scoring window, so a user's
own anomalous behaviour never gets absorbed into the definition of their
normal. Getting this wrong is the most common way an anomaly detection project
quietly stops working while still looking fine.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import date, datetime, timedelta
from pathlib import Path

from .baseline.profiler import Profiler, extract_daily_features
from .config import Config
from .detect.base import Detection
from .detect.ml import AnomalyDetector
from .detect.rules import RuleEngine, load_rules
from .detect.statistical import StatisticalDetector
from .feedback import FeedbackStore
from .privacy import Pseudonymizer
from .schema import Event, Identity
from .scoring.risk import RiskScorer, evaluate_queue
from .storage import Store


class Pipeline:
    """End-to-end run: events in, cases out."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self.profiler = Profiler(self.config.baseline)
        self.rule_engine = RuleEngine(load_rules(self.config.rules_dir))
        self.statistical = StatisticalDetector(self.config.statistical)
        self.ml = AnomalyDetector(self.config.ml)
        self.scorer = RiskScorer(self.config.risk)
        self.pseudonymizer = Pseudonymizer(self.config.privacy)
        self.store: Store | None = None

    # -- setup ----------------------------------------------------------

    def attach_store(self, path: str | Path | None = None) -> Store:
        self.store = Store(path or self.config.db_path)
        return self.store

    # -- run ------------------------------------------------------------

    def run(
        self,
        events: Iterable[Event],
        identities: dict[str, Identity] | None = None,
        *,
        train_until: datetime | None = None,
        score_from: datetime | None = None,
    ) -> dict:
        """Fit baselines on history, then score the recent window.

        ``train_until`` bounds the training data. ``score_from`` starts the
        window being assessed. They normally meet: train on everything up to
        two weeks ago, score the last two weeks.
        """
        events = sorted(events, key=lambda e: e.timestamp)
        if not events:
            return _empty_result()

        identities = identities or {}
        last_ts = events[-1].timestamp

        # Analyst feedback: active suppressions and learned detection weights.
        suppressions: set[tuple[str, str]] = set()
        if self.store is not None:
            feedback = FeedbackStore(self.store)
            suppressions = feedback.suppression_set()
            self.scorer.learned_weights = feedback.learned_weights()
        score_from = score_from or (last_ts - timedelta(days=14))
        train_until = train_until or score_from

        peer_groups = {a: i.peer_group for a, i in identities.items()}

        # -- fit on history only
        self.profiler.fit(events, peer_groups=peer_groups, as_of=train_until)

        training_features = [
            f
            for (actor, day), f in extract_daily_features(
                [e for e in events if e.timestamp < train_until]
            ).items()
        ]
        self.ml.fit(training_features)

        # -- score the window
        scoring_events = [e for e in events if e.timestamp >= score_from]
        features = extract_daily_features(scoring_events)

        events_by_day: dict[tuple[str, date], list[Event]] = defaultdict(list)
        for e in scoring_events:
            events_by_day[(e.actor_id, e.timestamp.date())].append(e)

        detections_by_actor: dict[str, list[Detection]] = defaultdict(list)
        skipped_insufficient: set[str] = set()

        # Score every person-day with the model in one batch.
        keys = list(features)
        ml_scores = dict(zip(keys, self.ml.score_batch([features[k] for k in keys]), strict=True))

        for (actor_id, day), feats in sorted(features.items(), key=lambda kv: kv[0][1]):
            day_events = events_by_day[(actor_id, day)]
            identity = identities.get(actor_id)
            profile = self.profiler.profile_for(actor_id)
            baseline_kind = self.profiler.baseline_kind(actor_id)

            # Rules always run — they do not depend on a baseline, which is
            # exactly why they are the first thing to ship.
            detections_by_actor[actor_id].extend(
                self.rule_engine.evaluate(actor_id, day, day_events, feats, identity)
            )

            if profile.days_observed < 1:
                skipped_insufficient.add(actor_id)
                continue

            detections_by_actor[actor_id].extend(
                self.statistical.evaluate(feats, profile, baseline_kind=baseline_kind)
            )
            detections_by_actor[actor_id].extend(
                self.ml.evaluate(feats, baseline_kind=baseline_kind,
                                 score=ml_scores[(actor_id, day)])
            )

        suppressed = 0
        if suppressions:
            for actor_id, dets in detections_by_actor.items():
                kept = [d for d in dets if (actor_id, d.name) not in suppressions]
                suppressed += len(dets) - len(kept)
                detections_by_actor[actor_id] = kept

        cases = self.scorer.build_cases(
            dict(detections_by_actor),
            identities,
            as_of=last_ts,
            pseudonymizer=self.pseudonymizer,
        )

        new_case_ids: list[str] = []
        if self.store is not None:
            all_detections = [d for ds in detections_by_actor.values() for d in ds]
            self.store.insert_detections(all_detections)
            new_case_ids = self.store.upsert_cases(cases)
            # Daily timelines for every entity with a case, for the dashboard.
            case_actors = {c.actor_id for c in cases}
            if case_actors:
                all_feats = extract_daily_features(
                    [e for e in events if e.actor_id in case_actors])
                per_actor: dict[str, list] = defaultdict(list)
                for (actor_id, day), f in sorted(all_feats.items(), key=lambda kv: kv[0][1]):
                    per_actor[actor_id].append(
                        (day.isoformat(), f.values, day >= score_from.date()))
                for actor_id, days in per_actor.items():
                    self.store.save_entity_days(actor_id, days)

        total_detections = sum(len(v) for v in detections_by_actor.values())
        return {
            "cases": cases,
            "detections_by_actor": dict(detections_by_actor),
            "total_detections": total_detections,
            "entities_with_detections": sum(
                1 for v in detections_by_actor.values() if v
            ),
            "insufficient_history": sorted(skipped_insufficient),
            "ml_fitted": self.ml.is_fitted,
            "events_scored": len(scoring_events),
            "events_trained": len(events) - len(scoring_events),
            "scored_from": score_from.isoformat(),
            "suppressed_detections": suppressed,
            "new_case_ids": new_case_ids,
            "learned_weights": dict(self.scorer.learned_weights),
        }

    # -- evaluation -----------------------------------------------------

    def evaluate(self, result: dict, labels: dict[str, str]) -> dict:
        """Score the run against known ground truth. Only meaningful on
        synthetic or benchmark data where labels exist."""
        return evaluate_queue(
            result["cases"], labels, self.config.risk.alert_budget
        )


def _empty_result() -> dict:
    return {
        "cases": [],
        "detections_by_actor": {},
        "total_detections": 0,
        "entities_with_detections": 0,
        "insufficient_history": [],
        "ml_fitted": False,
        "events_scored": 0,
        "events_trained": 0,
        "scored_from": None,
        "suppressed_detections": 0,
        "new_case_ids": [],
        "learned_weights": {},
    }
