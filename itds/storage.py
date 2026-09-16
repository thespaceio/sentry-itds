"""Storage.

SQLite via the standard library. No ORM, no migrations framework, no server to
run before the project does anything. The schema is small enough to read in one
sitting and the queries are plain SQL.

Swapping in ClickHouse or OpenSearch later means reimplementing this one class;
nothing above it touches SQL directly.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from .schema import Event, Identity

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    actor_id        TEXT    NOT NULL,
    category        TEXT    NOT NULL,
    action          TEXT    NOT NULL,
    host            TEXT,
    source_ip       TEXT,
    destination     TEXT,
    country         TEXT,
    object_name     TEXT,
    object_sensitivity TEXT,
    object_count    INTEGER DEFAULT 1,
    bytes           INTEGER DEFAULT 0,
    session_id      TEXT,
    source_system   TEXT,
    extra           TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_actor_time ON events(actor_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_time       ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_category   ON events(category);

CREATE TABLE IF NOT EXISTS identities (
    actor_id            TEXT PRIMARY KEY,
    display_name        TEXT,
    department          TEXT,
    role                TEXT,
    manager_id          TEXT,
    is_privileged       INTEGER DEFAULT 0,
    joined_on           TEXT,
    departure_notice_on TEXT,
    last_day_on         TEXT
);

CREATE TABLE IF NOT EXISTS detections (
    detection_id  TEXT PRIMARY KEY,
    actor_id      TEXT NOT NULL,
    day           TEXT NOT NULL,
    engine        TEXT NOT NULL,
    name          TEXT NOT NULL,
    severity      TEXT NOT NULL,
    base_weight   REAL NOT NULL,
    confidence    REAL NOT NULL,
    explanation   TEXT,
    evidence      TEXT,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_detections_actor_day ON detections(actor_id, day);

CREATE TABLE IF NOT EXISTS cases (
    case_id       TEXT PRIMARY KEY,
    actor_id      TEXT NOT NULL,
    pseudonym     TEXT,
    risk_score    REAL NOT NULL,
    status        TEXT NOT NULL DEFAULT 'open',
    opened_at     TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    closed_at     TEXT,
    disposition   TEXT,
    summary       TEXT,
    detection_ids TEXT
);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);

CREATE TABLE IF NOT EXISTS reveals (
    reveal_id    TEXT PRIMARY KEY,
    pseudonym    TEXT NOT NULL,
    actor_id     TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    approved_by  TEXT,
    reason       TEXT NOT NULL,
    case_id      TEXT,
    at           TEXT NOT NULL
);
"""

EVENT_COLUMNS = (
    "timestamp, actor_id, category, action, host, source_ip, destination, "
    "country, object_name, object_sensitivity, object_count, bytes, "
    "session_id, source_system, extra"
)


class Store:
    """Thin persistence wrapper. Safe to construct many times; cheap to open."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # -- events ---------------------------------------------------------

    def insert_events(self, events: Iterable[Event]) -> int:
        rows = []
        for e in events:
            rows.append(
                (
                    e.timestamp.isoformat(),
                    e.actor_id,
                    e.category.value,
                    e.action,
                    e.host,
                    e.source_ip,
                    e.destination,
                    e.country,
                    e.object_name,
                    e.object_sensitivity.value if e.object_sensitivity else None,
                    e.object_count,
                    e.bytes,
                    e.session_id,
                    e.source_system,
                    json.dumps(e.extra) if e.extra else None,
                )
            )
        if not rows:
            return 0
        placeholders = ",".join(["?"] * 15)
        with self.connect() as conn:
            conn.executemany(
                f"INSERT INTO events ({EVENT_COLUMNS}) VALUES ({placeholders})", rows
            )
        return len(rows)

    def iter_events(
        self,
        *,
        actor_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> Iterator[Event]:
        clauses, params = [], []
        if actor_id:
            clauses.append("actor_id = ?")
            params.append(actor_id)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since.isoformat())
        if until:
            clauses.append("timestamp < ?")
            params.append(until.isoformat())
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as conn:
            for row in conn.execute(
                f"SELECT {EVENT_COLUMNS} FROM events {where} ORDER BY timestamp", params
            ):
                data = dict(row)
                data["extra"] = json.loads(data["extra"]) if data["extra"] else {}
                yield Event.from_dict(data)

    def event_count(self) -> int:
        with self.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # -- identities -----------------------------------------------------

    def upsert_identities(self, identities: Iterable[Identity]) -> int:
        rows = [
            (
                i.actor_id,
                i.display_name,
                i.department,
                i.role,
                i.manager_id,
                int(i.is_privileged),
                i.joined_on.isoformat() if i.joined_on else None,
                i.departure_notice_on.isoformat() if i.departure_notice_on else None,
                i.last_day_on.isoformat() if i.last_day_on else None,
            )
            for i in identities
        ]
        if not rows:
            return 0
        with self.connect() as conn:
            conn.executemany(
                "INSERT INTO identities VALUES (?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(actor_id) DO UPDATE SET "
                "display_name=excluded.display_name, department=excluded.department, "
                "role=excluded.role, manager_id=excluded.manager_id, "
                "is_privileged=excluded.is_privileged, joined_on=excluded.joined_on, "
                "departure_notice_on=excluded.departure_notice_on, "
                "last_day_on=excluded.last_day_on",
                rows,
            )
        return len(rows)

    def load_identities(self) -> dict[str, Identity]:
        out: dict[str, Identity] = {}
        with self.connect() as conn:
            for row in conn.execute("SELECT * FROM identities"):
                d = dict(row)
                out[d["actor_id"]] = Identity(
                    actor_id=d["actor_id"],
                    display_name=d["display_name"],
                    department=d["department"],
                    role=d["role"],
                    manager_id=d["manager_id"],
                    is_privileged=bool(d["is_privileged"]),
                    joined_on=_parse(d["joined_on"]),
                    departure_notice_on=_parse(d["departure_notice_on"]),
                    last_day_on=_parse(d["last_day_on"]),
                )
        return out

    # -- detections and cases -------------------------------------------

    def insert_detections(self, detections: Iterable) -> int:
        rows = [
            (
                d.detection_id,
                d.actor_id,
                d.day.isoformat(),
                d.engine,
                d.name,
                d.severity,
                d.base_weight,
                d.confidence,
                d.explanation,
                json.dumps(d.evidence),
                datetime.now(UTC).isoformat(),
            )
            for d in detections
        ]
        if not rows:
            return 0
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows
            )
        return len(rows)

    def upsert_cases(self, cases: Iterable) -> int:
        rows = [
            (
                c.case_id,
                c.actor_id,
                c.pseudonym,
                c.risk_score,
                c.status,
                c.opened_at.isoformat(),
                c.updated_at.isoformat(),
                c.closed_at.isoformat() if c.closed_at else None,
                c.disposition,
                c.summary,
                json.dumps(c.detection_ids),
            )
            for c in cases
        ]
        if not rows:
            return 0
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows
            )
        return len(rows)

    def open_cases(self, limit: int = 50) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cases WHERE status = 'open' "
                "ORDER BY risk_score DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def detections_for(self, actor_id: str) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM detections WHERE actor_id = ? ORDER BY day DESC",
                (actor_id,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["evidence"] = json.loads(d["evidence"]) if d["evidence"] else {}
            out.append(d)
        return out

    def record_reveal(self, record) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO reveals VALUES (?,?,?,?,?,?,?,?)",
                (
                    record.reveal_id,
                    record.pseudonym,
                    record.actor_id,
                    record.requested_by,
                    record.approved_by,
                    record.reason,
                    record.case_id,
                    record.at.isoformat(),
                ),
            )

    # -- retention ------------------------------------------------------

    def purge_events_before(self, cutoff: datetime) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "DELETE FROM events WHERE timestamp < ?", (cutoff.isoformat(),)
            )
            return cur.rowcount

    def purge_closed_cases_before(self, cutoff: datetime) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "DELETE FROM cases WHERE status = 'closed' AND closed_at < ?",
                (cutoff.isoformat(),),
            )
            return cur.rowcount


def _parse(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None
