from datetime import UTC, datetime, timedelta

from conftest import make_event

from itds.schema import Identity
from itds.storage import Store


def test_events_roundtrip(tmp_path):
    store = Store(tmp_path / "t.db")
    events = [make_event(object_name=f"/x/{i}") for i in range(10)]
    assert store.insert_events(events) == 10
    assert store.event_count() == 10
    back = list(store.iter_events())
    assert len(back) == 10
    assert back[0].object_name.startswith("/x/")


def test_extra_field_survives_the_roundtrip(tmp_path):
    store = Store(tmp_path / "t.db")
    store.insert_events([make_event(extra={"proxy_rule": "block"})])
    assert list(store.iter_events())[0].extra["proxy_rule"] == "block"


def test_identity_upsert_updates_rather_than_duplicates(tmp_path):
    store = Store(tmp_path / "t.db")
    store.upsert_identities([Identity(actor_id="u1", department="sales")])
    store.upsert_identities([Identity(actor_id="u1", department="finance")])
    loaded = store.load_identities()
    assert len(loaded) == 1
    assert loaded["u1"].department == "finance"


def test_retention_purges_old_events(tmp_path):
    store = Store(tmp_path / "t.db")
    now = datetime.now(UTC)
    store.insert_events(
        [
            make_event(timestamp=now - timedelta(days=200)),
            make_event(timestamp=now - timedelta(days=1)),
        ]
    )
    removed = store.purge_events_before(now - timedelta(days=90))
    assert removed == 1
    assert store.event_count() == 1
