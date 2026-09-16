from datetime import timedelta

import pytest
from conftest import BASE, make_event

from itds.baseline.profiler import extract_daily_features
from itds.detect.rules import Rule, RuleEngine, load_rules
from itds.schema import Category, Identity


def test_shipped_rules_all_load():
    rules = load_rules("rules")
    assert len(rules) >= 8
    assert all(r.severity in {"low", "medium", "high", "critical"} for r in rules)
    # Rule ids must be unique or the case summary becomes ambiguous.
    assert len({r.id for r in rules}) == len(rules)


def test_event_rule_matches_on_wildcard_destination():
    rule = Rule(
        id="cloud",
        title="Cloud upload",
        severity="medium",
        description="",
        match={"action": "upload", "destination": ["*dropbox.com"]},
    )
    events = [
        make_event(
            category=Category.NETWORK,
            action="upload",
            destination="files.dropbox.com",
            bytes=10_000,
        )
    ]
    feats = extract_daily_features(events)[("u001", BASE.date())]
    found = RuleEngine([rule]).evaluate("u001", BASE.date(), events, feats)
    assert len(found) == 1
    assert "Cloud upload" in found[0].explanation


def test_rule_does_not_fire_below_threshold():
    rule = Rule(
        id="many",
        title="Many",
        severity="low",
        description="",
        match={"action": "upload"},
        threshold=5,
    )
    events = [make_event(action="upload") for _ in range(3)]
    feats = extract_daily_features(events)[("u001", BASE.date())]
    assert RuleEngine([rule]).evaluate("u001", BASE.date(), events, feats) == []


def test_context_requirement_gates_the_rule():
    rule = Rule(
        id="departing_bulk",
        title="Departing bulk",
        severity="critical",
        description="",
        aggregate={"condition": ["file_read_count > 5"]},
        require_context=["departing"],
    )
    events = [make_event() for _ in range(10)]
    feats = extract_daily_features(events)[("u001", BASE.date())]
    engine = RuleEngine([rule])

    # No departure on record: must not fire.
    assert engine.evaluate("u001", BASE.date(), events, feats, Identity("u001")) == []

    departing = Identity(
        actor_id="u001",
        departure_notice_on=BASE - timedelta(days=5),
        last_day_on=BASE + timedelta(days=10),
    )
    assert len(engine.evaluate("u001", BASE.date(), events, feats, departing)) == 1


def test_all_conditions_must_hold():
    rule = Rule(
        id="both",
        title="Both",
        severity="high",
        description="",
        aggregate={"condition": ["file_read_count > 5", "total_bytes > 999999999"]},
    )
    events = [make_event() for _ in range(10)]
    feats = extract_daily_features(events)[("u001", BASE.date())]
    assert RuleEngine([rule]).evaluate("u001", BASE.date(), events, feats) == []


def test_malformed_condition_raises_loudly():
    rule = Rule(
        id="bad",
        title="Bad",
        severity="low",
        description="",
        aggregate={"condition": ["file_read_count is quite large"]},
    )
    events = [make_event()]
    feats = extract_daily_features(events)[("u001", BASE.date())]
    with pytest.raises(ValueError, match="cannot parse condition"):
        RuleEngine([rule]).evaluate("u001", BASE.date(), events, feats)


def test_canary_rule_fires_on_a_single_event():
    rules = [r for r in load_rules("rules") if r.id == "canary_file_access"]
    events = [
        make_event(action="canary_access", object_name="/finance/DO_NOT_OPEN.xlsx")
    ]
    feats = extract_daily_features(events)[("u001", BASE.date())]
    found = RuleEngine(rules).evaluate("u001", BASE.date(), events, feats)
    assert len(found) == 1
    assert found[0].severity == "critical"
