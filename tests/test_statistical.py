from datetime import timedelta

from conftest import BASE, make_event

from itds.baseline.profiler import Profiler, extract_daily_features
from itds.config import StatisticalConfig
from itds.detect.statistical import StatisticalDetector


def _profile(routine_events):
    return Profiler().fit(routine_events).self_profiles["u001"]


def test_normal_day_produces_nothing(routine_events):
    profile = _profile(routine_events)
    normal_day = [
        make_event(timestamp=BASE + timedelta(days=40, hours=h)) for h in range(20)
    ]
    feats = extract_daily_features(normal_day)[("u001", (BASE + timedelta(days=40)).date())]
    assert StatisticalDetector().evaluate(feats, profile) == []


def test_large_spike_is_detected(routine_events):
    profile = _profile(routine_events)
    spike_day = BASE + timedelta(days=40)
    events = [
        make_event(timestamp=spike_day.replace(hour=10), object_name=f"/ops/f{i}.xlsx")
        for i in range(600)
    ]
    feats = extract_daily_features(events)[("u001", spike_day.date())]
    found = StatisticalDetector().evaluate(feats, profile)
    names = {d.name for d in found}
    assert "anomalous_file_read_count" in names
    assert all(d.explanation for d in found)


def test_tiny_counts_do_not_produce_alerts():
    """Three events against a near-zero baseline is arithmetic, not a threat."""
    quiet = [make_event(timestamp=BASE + timedelta(days=d)) for d in range(15)]
    profile = Profiler().fit(quiet).self_profiles["u001"]
    day = BASE + timedelta(days=40)
    events = [make_event(timestamp=day) for _ in range(3)]
    feats = extract_daily_features(events)[("u001", day.date())]
    found = StatisticalDetector(StatisticalConfig(min_events_for_z=5)).evaluate(
        feats, profile
    )
    assert "anomalous_file_read_count" not in {d.name for d in found}


def test_absolute_floor_catches_high_baseline_user():
    """A user whose normal is already huge must still trip a ceiling."""
    heavy = []
    for d in range(20):
        day = BASE + timedelta(days=d)
        heavy.extend(make_event(timestamp=day, object_name=f"/x/{i}") for i in range(600))
    profile = Profiler().fit(heavy).self_profiles["u001"]

    day = BASE + timedelta(days=40)
    events = [make_event(timestamp=day, object_name=f"/x/{i}") for i in range(620)]
    feats = extract_daily_features(events)[("u001", day.date())]
    found = StatisticalDetector().evaluate(feats, profile)
    assert "absolute_file_volume" in {d.name for d in found}


def test_every_detection_carries_evidence(routine_events):
    profile = _profile(routine_events)
    day = BASE + timedelta(days=40)
    events = [make_event(timestamp=day, object_name=f"/ops/f{i}") for i in range(600)]
    feats = extract_daily_features(events)[("u001", day.date())]
    for d in StatisticalDetector().evaluate(feats, profile):
        assert d.evidence
        assert d.confidence <= 0.9  # statistics are evidence, never proof
