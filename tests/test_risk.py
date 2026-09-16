from datetime import UTC, datetime, timedelta

import pytest

from itds.config import RiskConfig
from itds.detect.base import Detection
from itds.schema import Identity
from itds.scoring.risk import RiskScorer, evaluate_queue

NOW = datetime(2026, 6, 30, tzinfo=UTC)


def det(name="x", severity="high", day=None, engine="rules", confidence=1.0):
    return Detection(
        actor_id="u1",
        day=day or NOW.date(),
        engine=engine,
        name=name,
        severity=severity,
        confidence=confidence,
        explanation="something happened",
    )


def test_detection_without_explanation_is_rejected():
    with pytest.raises(ValueError, match="no explanation"):
        Detection(
            actor_id="u1",
            day=NOW.date(),
            engine="ml",
            name="anomaly",
            severity="high",
            explanation="   ",
        )


def test_invalid_severity_is_rejected():
    with pytest.raises(ValueError, match="severity must be"):
        Detection(
            actor_id="u1",
            day=NOW.date(),
            engine="ml",
            name="x",
            severity="catastrophic",
            explanation="why",
        )


def test_decay_halves_at_one_half_life():
    scorer = RiskScorer(RiskConfig(half_life_days=7))
    assert scorer.decay_factor(0) == 1.0
    assert scorer.decay_factor(7) == pytest.approx(0.5)
    assert scorer.decay_factor(14) == pytest.approx(0.25)


def test_older_findings_contribute_less():
    scorer = RiskScorer()
    fresh, _ = scorer.score_entity("u1", [det(day=NOW.date())], as_of=NOW)
    stale, _ = scorer.score_entity(
        "u1", [det(day=(NOW - timedelta(days=21)).date())], as_of=NOW
    )
    assert fresh > stale


def test_departure_multiplies_risk():
    scorer = RiskScorer()
    plain, _ = scorer.score_entity("u1", [det()], None, as_of=NOW)
    departing = Identity(
        actor_id="u1",
        departure_notice_on=NOW - timedelta(days=10),
        last_day_on=NOW + timedelta(days=5),
    )
    raised, _ = scorer.score_entity("u1", [det()], departing, as_of=NOW)
    assert raised > plain


def test_repeated_same_signal_does_not_stack_linearly():
    """The core anti-noise property. Twenty repeats of one behaviour must not
    outrank a genuinely broad set of findings."""
    scorer = RiskScorer()
    repeated, _ = scorer.score_entity(
        "u1",
        [det(name="same", day=NOW.date() - timedelta(days=i)) for i in range(20)],
        as_of=NOW,
    )
    single, _ = scorer.score_entity("u1", [det(name="same")], as_of=NOW)
    assert repeated < single * 3


def test_multiple_engines_corroborate():
    scorer = RiskScorer()
    one_engine, _ = scorer.score_entity(
        "u1",
        [det(name="a", engine="rules"), det(name="b", engine="rules")],
        as_of=NOW,
    )
    three_engines, _ = scorer.score_entity(
        "u1",
        [
            det(name="a", engine="rules"),
            det(name="b", engine="statistical"),
            det(name="c", engine="ml"),
        ],
        as_of=NOW,
    )
    assert three_engines > one_engine


def test_score_is_capped():
    scorer = RiskScorer(RiskConfig(max_score=100))
    score, _ = scorer.score_entity(
        "u1",
        [det(name=f"sig{i}", severity="critical") for i in range(50)],
        as_of=NOW,
    )
    assert score <= 100


def test_queue_is_truncated_to_the_alert_budget():
    scorer = RiskScorer(RiskConfig(alert_budget=3, case_threshold=1))
    by_actor = {
        f"u{i}": [
            Detection(
                actor_id=f"u{i}",
                day=NOW.date(),
                engine="rules",
                name="x",
                severity="critical",
                explanation="why",
            )
        ]
        for i in range(10)
    }
    cases = scorer.build_cases(by_actor, as_of=NOW)
    assert len(cases) == 3


def test_below_threshold_opens_no_case():
    scorer = RiskScorer(RiskConfig(case_threshold=90))
    cases = scorer.build_cases({"u1": [det(severity="low")]}, as_of=NOW)
    assert cases == []


def test_evaluation_ignores_negligent_users_as_threats():
    from itds.scoring.risk import Case

    cases = [
        Case("c1", "u1", 90, NOW, NOW),
        Case("c2", "u2", 80, NOW, NOW),
    ]
    metrics = evaluate_queue(cases, {"u1": "departing_exfil", "u2": "negligent_sharer"}, 20)
    assert metrics["threats_planted"] == 1
    assert metrics["recall_at_budget"] == 1.0
    assert metrics["precision_at_budget"] == 0.5
