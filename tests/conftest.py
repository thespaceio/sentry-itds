from datetime import UTC, datetime, timedelta

import pytest

from itds.config import Config
from itds.schema import Category, Event, Identity, Sensitivity

BASE = datetime(2026, 6, 1, 9, 0, tzinfo=UTC)


@pytest.fixture
def config(tmp_path):
    cfg = Config()
    cfg.data_dir = tmp_path
    cfg.db_path = tmp_path / "test.db"
    return cfg


def make_event(**kwargs) -> Event:
    defaults = dict(
        timestamp=BASE,
        actor_id="u001",
        category=Category.FILE,
        action="file_read",
        object_sensitivity=Sensitivity.INTERNAL,
        bytes=1000,
    )
    defaults.update(kwargs)
    return Event(**defaults)


@pytest.fixture
def routine_events():
    """Thirty days of a consistent user, with the small day-to-day variance a
    real person has. A perfectly invariant user has zero standard deviation and
    therefore no meaningful z-score — which the profiler handles correctly, but
    which makes for a fixture that tests nothing."""
    import random

    rng = random.Random(1)
    events = []
    for day in range(30):
        ts = BASE + timedelta(days=day)
        if ts.weekday() >= 5:
            continue
        for i in range(rng.randint(16, 26)):
            events.append(
                make_event(
                    timestamp=ts.replace(hour=9 + (i % 8)),
                    object_name=f"/ops/doc_{i}.xlsx",
                    bytes=rng.randint(800, 1400),
                )
            )
    return events


@pytest.fixture
def identity():
    return Identity(
        actor_id="u001",
        display_name="Test User",
        department="operations",
        role="Ops coordinator",
    )
