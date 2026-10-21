"""Baselines.

Turns raw events into one feature vector per person per day, then learns what
normal looks like at three levels:

* **self**: this person's own recent history. The most specific baseline and
  the one to trust once enough history exists.
* **peer**: everyone in the same peer group (department by default). Used for
  new joiners and for anyone without ``min_days_history`` days of activity.
* **global**: the whole organization. The fallback when a peer group is too
  small to say anything reliable.

``fit`` accepts an ``as_of`` cutoff and ignores every event at or after it, so
the behaviour being judged is never part of the definition of normal.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime

import numpy as np

from ..config import BaselineConfig
from ..normalize.normalizer import is_personal_cloud
from ..schema import Category, Event, Sensitivity

# Order matters: it is the column order of every feature vector.
FEATURE_NAMES: tuple[str, ...] = (
    "event_count",
    "file_read_count",
    "file_write_count",
    "distinct_files",
    "restricted_file_count",
    "confidential_file_count",
    "total_bytes",
    "upload_bytes",
    "personal_cloud_bytes",
    "external_email_count",
    "external_email_bytes",
    "external_share_count",
    "removable_media_count",
    "removable_media_bytes",
    "logon_count",
    "failed_logon_count",
    "distinct_hosts",
    "distinct_countries",
    "privileged_action_count",
    "night_event_count",
    "weekend",
)

READ_ACTIONS = frozenset({"file_read", "file_open", "file_copy", "file_download"})
WRITE_ACTIONS = frozenset({"file_write", "file_create", "file_modify", "file_delete"})
PRIVILEGED_ACTIONS = frozenset(
    {"privileged_command", "sudo", "admin_action", "group_membership_change",
     "service_install", "audit_policy_change", "log_cleared"}
)

# Hours treated as night for everyone, independent of personal routine.
NIGHT_HOURS = frozenset({22, 23, 0, 1, 2, 3, 4, 5})


@dataclass(slots=True)
class DailyFeatures:
    """Everything one person did on one day, reduced to numbers."""

    actor_id: str
    day: date
    values: dict[str, float]
    hours: Counter = field(default_factory=Counter)

    def __getitem__(self, name: str) -> float:
        return self.values[name]

    def get(self, name: str, default: float = 0.0) -> float:
        return self.values.get(name, default)

    def vector(self) -> np.ndarray:
        return np.array([self.values.get(n, 0.0) for n in FEATURE_NAMES], dtype=float)


def _is_external_email(e: Event) -> bool:
    return e.action.endswith("_external") or bool(e.extra.get("external"))


def extract_daily_features(events: Iterable[Event]) -> dict[tuple[str, date], DailyFeatures]:
    """Group events by (actor, day) and compute the feature vector for each."""
    buckets: dict[tuple[str, date], list[Event]] = defaultdict(list)
    for e in events:
        buckets[(e.actor_id, e.timestamp.date())].append(e)

    out: dict[tuple[str, date], DailyFeatures] = {}
    for (actor, day), evs in buckets.items():
        v = dict.fromkeys(FEATURE_NAMES, 0.0)
        files: set[str] = set()
        hosts: set[str] = set()
        countries: set[str] = set()
        hours: Counter = Counter()

        for e in evs:
            n = max(1, e.object_count)
            v["event_count"] += 1
            v["total_bytes"] += e.bytes
            hours[e.hour] += 1
            if e.hour in NIGHT_HOURS:
                v["night_event_count"] += 1
            if e.host:
                hosts.add(e.host)
            if e.country:
                countries.add(e.country)

            cat = e.category
            if cat is Category.FILE:
                if e.action in READ_ACTIONS:
                    v["file_read_count"] += n
                elif e.action in WRITE_ACTIONS:
                    v["file_write_count"] += n
                if e.object_name:
                    files.add(e.object_name)
                if e.object_sensitivity is Sensitivity.RESTRICTED:
                    v["restricted_file_count"] += n
                elif e.object_sensitivity is Sensitivity.CONFIDENTIAL:
                    v["confidential_file_count"] += n
            elif cat is Category.NETWORK:
                if e.action == "external_share":
                    v["external_share_count"] += 1
                if e.action == "upload":
                    v["upload_bytes"] += e.bytes
                    if is_personal_cloud(e.destination):
                        v["personal_cloud_bytes"] += e.bytes
            elif cat is Category.EMAIL:
                if _is_external_email(e):
                    v["external_email_count"] += 1
                    v["external_email_bytes"] += e.bytes
            elif cat is Category.REMOVABLE_MEDIA:
                v["removable_media_count"] += 1
                v["removable_media_bytes"] += e.bytes
            elif cat is Category.AUTHENTICATION:
                if e.action == "logon_success":
                    v["logon_count"] += 1
                elif e.action == "logon_failure":
                    v["failed_logon_count"] += 1
            elif cat is Category.PROCESS:
                if e.action in PRIVILEGED_ACTIONS or e.extra.get("privileged"):
                    v["privileged_action_count"] += 1

        v["distinct_files"] = float(len(files))
        v["distinct_hosts"] = float(len(hosts))
        v["distinct_countries"] = float(len(countries))
        v["weekend"] = 1.0 if day.weekday() >= 5 else 0.0
        out[(actor, day)] = DailyFeatures(actor, day, v, hours)
    return out


@dataclass
class Profile:
    """What normal looks like for one entity (or one group of entities)."""

    kind: str  # "self", "peer" or "global"
    days_observed: int
    mean: np.ndarray
    std: np.ndarray
    hour_share: np.ndarray  # share of all activity in each hour of the day

    def _index(self, feature: str) -> int:
        return FEATURE_NAMES.index(feature)

    def mean_of(self, feature: str) -> float:
        return float(self.mean[self._index(feature)]) if self.days_observed else 0.0

    def std_of(self, feature: str) -> float:
        return float(self.std[self._index(feature)]) if self.days_observed else 0.0

    def z_score(self, feature: str, value: float) -> float:
        """Standard deviations above (or below) normal.

        Zero when the baseline never varies: a perfectly constant feature has
        no spread to measure against, and dividing by zero is not evidence.
        """
        if self.days_observed < 2:
            return 0.0
        sd = self.std_of(feature)
        if sd < 1e-9:
            return 0.0
        return (value - self.mean_of(feature)) / sd

    def is_off_hours(self, hour: int, percentile: float) -> bool:
        """True if this hour holds less than ``percentile`` of normal activity."""
        if self.days_observed == 0:
            return hour in NIGHT_HOURS
        return float(self.hour_share[hour % 24]) < percentile

    @classmethod
    def from_days(cls, kind: str, days: list[DailyFeatures]) -> Profile:
        n = len(FEATURE_NAMES)
        if not days:
            return cls(kind, 0, np.zeros(n), np.zeros(n), np.zeros(24))
        matrix = np.vstack([d.vector() for d in days])
        hours = np.zeros(24)
        for d in days:
            for h, c in d.hours.items():
                hours[h] += c
        total = hours.sum()
        share = hours / total if total else hours
        std = matrix.std(axis=0, ddof=1) if len(days) > 1 else np.zeros(n)
        return cls(kind, len(days), matrix.mean(axis=0), std, share)


class Profiler:
    """Learns self, peer and global baselines and picks the right one."""

    def __init__(self, config: BaselineConfig | None = None) -> None:
        self.config = config or BaselineConfig()
        self.self_profiles: dict[str, Profile] = {}
        self.peer_profiles: dict[str, Profile] = {}
        self.global_profile: Profile = Profile.from_days("global", [])
        self.peer_groups: dict[str, str] = {}
        self._peer_sizes: dict[str, int] = {}

    def fit(
        self,
        events: Iterable[Event],
        *,
        peer_groups: dict[str, str] | None = None,
        as_of: datetime | None = None,
    ) -> Profiler:
        if as_of is not None:
            events = [e for e in events if e.timestamp < as_of]
        features = extract_daily_features(events)
        self.peer_groups = dict(peer_groups or {})

        by_actor: dict[str, list[DailyFeatures]] = defaultdict(list)
        for (actor, _day), f in features.items():
            by_actor[actor].append(f)

        window = self.config.window_days
        by_group: dict[str, list[DailyFeatures]] = defaultdict(list)
        members: dict[str, set[str]] = defaultdict(set)
        all_days: list[DailyFeatures] = []

        self.self_profiles = {}
        for actor, days in by_actor.items():
            days.sort(key=lambda f: f.day)
            recent = days
            if window and days:
                cutoff = days[-1].day.toordinal() - window
                recent = [d for d in days if d.day.toordinal() > cutoff]
            self.self_profiles[actor] = Profile.from_days("self", recent)
            group = self.peer_groups.get(actor)
            if group:
                by_group[group].extend(recent)
                members[group].add(actor)
            all_days.extend(recent)

        self.peer_profiles = {g: Profile.from_days("peer", d) for g, d in by_group.items()}
        self._peer_sizes = {g: len(m) for g, m in members.items()}
        self.global_profile = Profile.from_days("global", all_days)
        return self

    def baseline_kind(self, actor_id: str) -> str:
        own = self.self_profiles.get(actor_id)
        if own is not None and own.days_observed >= self.config.min_days_history:
            return "self"
        group = self.peer_groups.get(actor_id)
        if group and self._peer_sizes.get(group, 0) >= self.config.min_peer_group_size:
            return "peer"
        return "global"

    def profile_for(self, actor_id: str) -> Profile:
        kind = self.baseline_kind(actor_id)
        if kind == "self":
            return self.self_profiles[actor_id]
        if kind == "peer":
            return self.peer_profiles[self.peer_groups[actor_id]]
        return self.global_profile
