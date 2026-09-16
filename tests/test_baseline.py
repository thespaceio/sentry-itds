from datetime import timedelta

from conftest import BASE, make_event

from itds.baseline.profiler import Profiler, extract_daily_features
from itds.config import BaselineConfig


def test_features_split_by_user_and_day(routine_events):
    feats = extract_daily_features(routine_events)
    assert all(k[0] == "u001" for k in feats)
    assert len(feats) == len({e.timestamp.date() for e in routine_events})


def test_feature_vector_is_stable_length(routine_events):
    from itds.baseline.profiler import FEATURE_NAMES

    feats = list(extract_daily_features(routine_events).values())
    assert all(len(f.vector()) == len(FEATURE_NAMES) for f in feats)


def test_profile_learns_the_users_own_hours(routine_events):
    profiler = Profiler().fit(routine_events, peer_groups={"u001": "operations"})
    profile = profiler.self_profiles["u001"]
    # This user works 09:00-16:00 only.
    assert profile.is_off_hours(3, 0.05)
    assert not profile.is_off_hours(10, 0.05)


def test_zero_variance_feature_gives_no_z_score(routine_events):
    profiler = Profiler().fit(routine_events, peer_groups={"u001": "operations"})
    profile = profiler.self_profiles["u001"]
    # A feature the user never varies on must not produce an infinite score.
    z = profile.z_score("distinct_countries", 5.0)
    assert z == 0.0


def test_spike_produces_high_z_score(routine_events):
    profiler = Profiler().fit(routine_events, peer_groups={"u001": "operations"})
    profile = profiler.self_profiles["u001"]
    assert profile.z_score("file_read_count", 400) > 3.0


def test_new_joiner_falls_back_to_peer_baseline():
    """A user with no history must be assessed against their department."""
    events = []
    for u in range(8):
        for day in range(20):
            events.append(
                make_event(
                    actor_id=f"peer{u}",
                    timestamp=BASE + timedelta(days=day),
                )
            )
    # One day of history only.
    events.append(make_event(actor_id="newbie", timestamp=BASE))

    peers = {f"peer{u}": "finance" for u in range(8)}
    peers["newbie"] = "finance"

    profiler = Profiler(BaselineConfig(min_days_history=7)).fit(
        events, peer_groups=peers
    )
    assert profiler.baseline_kind("newbie") == "peer"
    assert profiler.baseline_kind("peer0") == "self"


def test_small_peer_group_falls_through_to_global():
    events = [make_event(actor_id="solo", timestamp=BASE + timedelta(days=d)) for d in range(2)]
    profiler = Profiler(BaselineConfig(min_days_history=7, min_peer_group_size=5)).fit(
        events, peer_groups={"solo": "tiny_team"}
    )
    assert profiler.baseline_kind("solo") == "global"


def test_as_of_excludes_future_events(routine_events):
    """Training must not absorb the behaviour it will later be asked to judge."""
    cutoff = BASE + timedelta(days=10)
    profiler = Profiler().fit(routine_events, as_of=cutoff)
    assert profiler.self_profiles["u001"].days_observed <= 10
