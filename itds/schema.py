"""Normalized event schema.

Every collected record — whatever its source — is mapped into a single flat
event shape before anything downstream touches it. Field names follow the
Elastic Common Schema (ECS) naming style so the events remain portable to
OpenSearch, Splunk or any SIEM without a second translation step.

Keeping this module dependency-free is deliberate: the schema is the contract
between collection and detection, and a contract should not need a framework.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Category(StrEnum):
    """Coarse event category. Detections are written against these."""

    AUTHENTICATION = "authentication"
    FILE = "file"
    NETWORK = "network"
    EMAIL = "email"
    PROCESS = "process"
    REMOVABLE_MEDIA = "removable_media"
    HR = "hr"


class Sensitivity(StrEnum):
    """Data classification of the object an action touched.

    Ordered. Use ``Sensitivity.rank()`` when you need a number.
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @classmethod
    def rank(cls, value: Sensitivity | str | None) -> int:
        order = {
            cls.PUBLIC: 0,
            cls.INTERNAL: 1,
            cls.CONFIDENTIAL: 2,
            cls.RESTRICTED: 3,
        }
        if value is None:
            return 0
        if isinstance(value, str):
            try:
                value = cls(value)
            except ValueError:
                return 0
        return order[value]


@dataclass(slots=True)
class Event:
    """A single normalized activity record.

    Only ``timestamp``, ``actor_id``, ``category`` and ``action`` are required.
    Everything else is optional because no single source populates every field,
    and detections must cope with sparse records rather than assume a full row.
    """

    timestamp: datetime
    actor_id: str
    category: Category
    action: str

    # Where it happened
    host: str | None = None
    source_ip: str | None = None
    destination: str | None = None
    country: str | None = None

    # What it touched
    object_name: str | None = None
    object_sensitivity: Sensitivity | None = None
    object_count: int = 1
    bytes: int = 0

    # Session and provenance
    session_id: str | None = None
    source_system: str | None = None

    # Anything source-specific that does not deserve a first-class field
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=UTC)
        if isinstance(self.category, str):
            self.category = Category(self.category)
        if isinstance(self.object_sensitivity, str):
            self.object_sensitivity = Sensitivity(self.object_sensitivity)

    @property
    def hour(self) -> int:
        return self.timestamp.hour

    @property
    def weekday(self) -> int:
        """Monday is 0, Sunday is 6."""
        return self.timestamp.weekday()

    @property
    def is_weekend(self) -> bool:
        return self.weekday >= 5

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["timestamp"] = self.timestamp.isoformat()
        out["category"] = self.category.value
        if self.object_sensitivity is not None:
            out["object_sensitivity"] = self.object_sensitivity.value
        return out

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Event:
        data = dict(raw)
        ts = data.pop("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        known = {f for f in cls.__dataclass_fields__ if f != "timestamp"}
        extra = data.pop("extra", {}) or {}
        for key in list(data):
            if key not in known:
                extra[key] = data.pop(key)
        return cls(timestamp=ts, extra=extra, **data)


@dataclass(slots=True)
class Identity:
    """An entity the system reasons about. Usually a person, sometimes a service
    account. Peer grouping and the departure signal both live here."""

    actor_id: str
    display_name: str | None = None
    department: str | None = None
    role: str | None = None
    manager_id: str | None = None
    is_privileged: bool = False
    joined_on: datetime | None = None
    # Set the moment HR records a resignation or termination notice. This one
    # field carries more detection value than any other piece of context.
    departure_notice_on: datetime | None = None
    last_day_on: datetime | None = None

    @property
    def peer_group(self) -> str:
        return self.department or "unassigned"

    def days_to_departure(self, at: datetime) -> int | None:
        """Days between ``at`` and the recorded last day. Negative after it."""
        if self.last_day_on is None:
            return None
        last = self.last_day_on
        if last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        if at.tzinfo is None:
            at = at.replace(tzinfo=UTC)
        return (last - at).days

    def is_departing(self, at: datetime) -> bool:
        """True once notice has been given and the last day has not passed."""
        if self.departure_notice_on is None:
            return False
        notice = self.departure_notice_on
        if notice.tzinfo is None:
            notice = notice.replace(tzinfo=UTC)
        if at.tzinfo is None:
            at = at.replace(tzinfo=UTC)
        if at < notice:
            return False
        days_left = self.days_to_departure(at)
        return days_left is None or days_left >= 0
