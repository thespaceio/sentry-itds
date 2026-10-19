"""Evaluation on benchmark data with known insiders (CERT r4.2 and similar).

Sentry is a batch system: every so often it fits baselines on recent history
and scores the latest window. ``rolling_evaluate`` replays a whole dataset that
way, window after window, and checks the case queue of each window against the
answer key:

* an insider counts as **detected** if they appear in the queue of any window
  that overlaps their malicious activity;
* every queued case in a window where that person was not acting maliciously
  is a **false positive** (including insiders outside their active period).

This is deliberately stricter than the per-day or per-user classification
metrics often reported on CERT, because it measures what an analyst would
actually see: a bounded queue, every two weeks.
"""

from __future__ import annotations

import bisect
import csv
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .config import Config
from .normalize.normalizer import canonical_key
from .pipeline import Pipeline
from .schema import Event, Identity

CERT_DATE = "%m/%d/%Y %H:%M:%S"


@dataclass
class Insider:
    actor_id: str
    scenario: int
    start: datetime
    end: datetime


@dataclass
class WindowResult:
    start: datetime
    end: datetime
    queue: list[str]
    active_insiders: list[str]
    true_positives: list[str] = field(default_factory=list)


# -- CERT metadata ---------------------------------------------------------------


def load_cert_insiders(answers_dir: str | Path, release: str = "4.2") -> list[Insider]:
    """Read ``answers/insiders.csv`` for one release (e.g. ``4.2``)."""
    path = Path(answers_dir) / "insiders.csv"
    out = []
    with open(path, encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            if str(row.get("dataset", "")).strip() not in (release, f"r{release}"):
                continue
            out.append(Insider(
                actor_id=canonical_key(row["user"]),
                scenario=int(row["scenario"]),
                start=datetime.strptime(row["start"].strip(), CERT_DATE).replace(tzinfo=UTC),
                end=datetime.strptime(row["end"].strip(), CERT_DATE).replace(tzinfo=UTC),
            ))
    return out


def load_cert_identities(ldap_dir: str | Path, *, departure_context: bool = True,
                         notice_days: int = 30) -> dict[str, Identity]:
    """Build identities from CERT's monthly LDAP snapshots (``LDAP/2010-01.csv``...).

    A person missing from every snapshot after a given month has left. With
    ``departure_context`` the last day is set to the end of their final month
    and the notice date ``notice_days`` before it, as an HR system would hold.
    That is hindsight relative to the raw logs, so results are reported both
    with and without it.
    """
    files = sorted(Path(ldap_dir).glob("*.csv"))
    seen: dict[str, dict] = {}
    last_month: dict[str, str] = {}
    months = []
    for f in files:
        month = f.stem  # "2010-01"
        months.append(month)
        with open(f, encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                uid = canonical_key(row.get("user_id") or "")
                if not uid:
                    continue
                seen.setdefault(uid, row)
                last_month[uid] = month
    final = months[-1] if months else None
    out = {}
    for uid, row in seen.items():
        dept = "/".join(p for p in (row.get("functional_unit"), row.get("department")) if p)
        ident = Identity(
            actor_id=uid,
            display_name=row.get("employee_name"),
            department=dept or None,
            role=row.get("role"),
            is_privileged=(row.get("role") or "").strip().lower() == "itadmin",
        )
        if departure_context and last_month[uid] != final:
            y, m = (int(x) for x in last_month[uid].split("-"))
            first_next = datetime(y + (m == 12), m % 12 + 1, 1, tzinfo=UTC)
            ident.last_day_on = first_next - timedelta(days=1)
            ident.departure_notice_on = ident.last_day_on - timedelta(days=notice_days)
        out[uid] = ident
    return out


# -- rolling evaluation ------------------------------------------------------------


def rolling_evaluate(
    events: list[Event],
    identities: dict[str, Identity],
    insiders: list[Insider],
    *,
    config: Config | None = None,
    window_days: int = 14,
    train_days: int = 60,
    progress=None,
) -> dict:
    """Replay the dataset window by window and score each queue."""
    config = config or Config()
    events = sorted(events, key=lambda e: e.timestamp)
    times = [e.timestamp for e in events]
    if not events:
        raise ValueError("no events")
    first, last = times[0], times[-1]
    start = datetime(first.year, first.month, first.day, tzinfo=UTC) + timedelta(days=train_days)

    by_actor = defaultdict(list)
    for ins in insiders:
        by_actor[ins.actor_id].append(ins)

    windows: list[WindowResult] = []
    detected: dict[str, datetime] = {}
    while start < last:
        end = start + timedelta(days=window_days)
        lo = bisect.bisect_left(times, start - timedelta(days=train_days))
        hi = bisect.bisect_left(times, end)
        chunk = events[lo:hi]
        if chunk:
            result = Pipeline(config).run(chunk, identities, train_until=start, score_from=start)
            queue = [c.actor_id for c in result["cases"]]
        else:
            queue = []
        active = sorted(a for a, lst in by_actor.items()
                        if any(i.start < end and i.end >= start for i in lst))
        tps = [a for a in queue if a in active]
        for a in tps:
            detected.setdefault(a, end)
        windows.append(WindowResult(start, end, queue, active, tps))
        if progress:
            progress(windows[-1])
        start = end

    insider_ids = sorted(by_actor)
    evaluable = [a for a in insider_ids
                 if any(w.start <= i.end and i.start < w.end
                        for i in by_actor[a] for w in windows)]
    queued = sum(len(w.queue) for w in windows)
    tp_cases = sum(len(w.true_positives) for w in windows)
    delays = []
    for a, when in detected.items():
        delays.append((when - min(i.start for i in by_actor[a])).days)
    per_scenario: dict[int, dict] = defaultdict(lambda: {"insiders": 0, "detected": 0})
    for a in evaluable:
        sc = by_actor[a][0].scenario
        per_scenario[sc]["insiders"] += 1
        per_scenario[sc]["detected"] += a in detected
    flagged_users = {a for w in windows for a in w.queue}
    return {
        "windows": len(windows),
        "window_days": window_days,
        "train_days": train_days,
        "alert_budget": config.risk.alert_budget,
        "users": len({e.actor_id for e in events}),
        "insiders_in_answer_key": len(insider_ids),
        "insiders_evaluable": len(evaluable),
        "insiders_detected": len([a for a in evaluable if a in detected]),
        "recall": round(len([a for a in evaluable if a in detected]) / len(evaluable), 3)
        if evaluable else None,
        "cases_queued": queued,
        "cases_per_window": round(queued / len(windows), 2) if windows else 0,
        "case_precision": round(tp_cases / queued, 3) if queued else None,
        "distinct_users_flagged": len(flagged_users),
        "innocent_users_flagged": len(flagged_users - set(insider_ids)),
        "median_days_to_detection": sorted(delays)[len(delays) // 2] if delays else None,
        "per_scenario": {str(k): v for k, v in sorted(per_scenario.items())},
        "window_detail": [
            {"start": w.start.date().isoformat(), "queue": len(w.queue),
             "active_insiders": len(w.active_insiders), "true_positives": len(w.true_positives)}
            for w in windows
        ],
    }
