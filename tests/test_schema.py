from datetime import UTC, datetime

from itds.schema import Category, Event, Identity, Sensitivity


def test_naive_timestamps_are_made_utc():
    e = Event(
        timestamp=datetime(2026, 6, 1, 3, 0),
        actor_id="u1",
        category=Category.FILE,
        action="file_read",
    )
    assert e.timestamp.tzinfo is UTC


def test_string_enums_are_coerced():
    e = Event(
        timestamp=datetime.now(UTC),
        actor_id="u1",
        category="file",
        action="file_read",
        object_sensitivity="restricted",
    )
    assert e.category is Category.FILE
    assert e.object_sensitivity is Sensitivity.RESTRICTED


def test_sensitivity_is_ordered():
    assert Sensitivity.rank(Sensitivity.RESTRICTED) > Sensitivity.rank(Sensitivity.PUBLIC)
    assert Sensitivity.rank(None) == 0
    assert Sensitivity.rank("nonsense") == 0


def test_roundtrip_through_dict():
    e = Event(
        timestamp=datetime(2026, 6, 1, 2, 30, tzinfo=UTC),
        actor_id="u1",
        category=Category.NETWORK,
        action="upload",
        destination="dropbox.com",
        bytes=5000,
        extra={"proxy_rule": "allow"},
    )
    back = Event.from_dict(e.to_dict())
    assert back.actor_id == e.actor_id
    assert back.destination == e.destination
    assert back.extra["proxy_rule"] == "allow"


def test_unknown_fields_land_in_extra():
    back = Event.from_dict(
        {
            "timestamp": "2026-06-01T09:00:00+00:00",
            "actor_id": "u1",
            "category": "file",
            "action": "file_read",
            "some_vendor_field": 42,
        }
    )
    assert back.extra["some_vendor_field"] == 42


def test_departing_window():
    at = datetime(2026, 6, 10, tzinfo=UTC)
    ident = Identity(
        actor_id="u1",
        departure_notice_on=datetime(2026, 6, 1, tzinfo=UTC),
        last_day_on=datetime(2026, 6, 30, tzinfo=UTC),
    )
    assert ident.is_departing(at)
    assert ident.days_to_departure(at) == 20
    # Before notice was given, not departing.
    assert not ident.is_departing(datetime(2026, 5, 20, tzinfo=UTC))
    # After the last day, no longer in the window.
    assert not ident.is_departing(datetime(2026, 7, 5, tzinfo=UTC))


def test_no_departure_record_means_not_departing():
    assert not Identity(actor_id="u1").is_departing(datetime.now(UTC))
