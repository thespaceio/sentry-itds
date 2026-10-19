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
    created_at    TEXT NOT NULL,
    title         TEXT,
    tags          TEXT,
    attack        TEXT
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
    detection_ids TEXT,
    context       TEXT,
    engines       TEXT,
    attack        TEXT,
    top_detections TEXT,
    breakdown     TEXT
);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);

CREATE TABLE IF NOT EXISTS feedback (
    feedback_id   TEXT PRIMARY KEY,
    case_id       TEXT NOT NULL,
    actor_id      TEXT NOT NULL,
    disposition   TEXT NOT NULL,
    analyst       TEXT NOT NULL,
    note          TEXT,
    detection_names TEXT,
    at            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feedback_case ON feedback(case_id);

CREATE TABLE IF NOT EXISTS suppressions (
    suppression_id TEXT PRIMARY KEY,
    actor_id       TEXT NOT NULL,
    detection_name TEXT NOT NULL,
    reason         TEXT NOT NULL,
    created_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    expires_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_notes (
    note_id   TEXT PRIMARY KEY,
    case_id   TEXT NOT NULL,
    author    TEXT NOT NULL,
    body      TEXT NOT NULL,
    at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reveal_requests (
    request_id   TEXT PRIMARY KEY,
    pseudonym    TEXT NOT NULL,
    case_id      TEXT,
    requested_by TEXT NOT NULL,
    reason       TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    decided_by   TEXT,
    decided_at   TEXT,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    role          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    at        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT,
    details   TEXT,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entity_days (
    actor_id TEXT NOT NULL,
    day      TEXT NOT NULL,
    features TEXT NOT NULL,
    scored   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (actor_id, day)
);

CREATE TABLE IF NOT EXISTS runs (
    run_id     TEXT PRIMARY KEY,
    at         TEXT NOT NULL,
    stats      TEXT NOT NULL
);

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
            _migrate(conn)

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
                json.dumps(d.evidence, default=str),
                datetime.now(UTC).isoformat(),
                getattr(d, "title", None),
                json.dumps(list(getattr(d, "tags", []))),
                json.dumps(list(getattr(d, "attack", []))),
            )
            for d in detections
        ]
        if not rows:
            return 0
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO detections (detection_id, actor_id, day, engine, "
                "name, severity, base_weight, confidence, explanation, evidence, "
                "created_at, title, tags, attack) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
        return len(rows)

    def upsert_cases(self, cases: Iterable) -> list[str]:
        """Insert new cases and refresh existing ones.

        Re-running the pipeline updates scores and evidence but never touches
        status, disposition or closure: an analyst's decision outlives the
        next batch run. Returns the ids of cases that are new.
        """
        new_ids: list[str] = []
        with self.connect() as conn:
            for c in cases:
                payload = (
                    c.actor_id,
                    c.pseudonym,
                    c.risk_score,
                    c.updated_at.isoformat(),
                    c.summary,
                    json.dumps(c.detection_ids),
                    json.dumps(list(getattr(c, "context", []))),
                    json.dumps(list(getattr(c, "engines", []))),
                    json.dumps(list(getattr(c, "attack", []))),
                    json.dumps([d.to_dict() for d in getattr(c, "top_detections", [])]),
                    json.dumps(getattr(c, "breakdown", {}), default=str),
                )
                exists = conn.execute(
                    "SELECT 1 FROM cases WHERE case_id = ?", (c.case_id,)
                ).fetchone()
                if exists:
                    conn.execute(
                        "UPDATE cases SET actor_id=?, pseudonym=?, risk_score=?, updated_at=?, "
                        "summary=?, detection_ids=?, context=?, engines=?, attack=?, "
                        "top_detections=?, breakdown=? WHERE case_id=?",
                        (*payload, c.case_id),
                    )
                else:
                    conn.execute(
                        "INSERT INTO cases (case_id, actor_id, pseudonym, risk_score, "
                        "updated_at, summary, detection_ids, context, engines, attack, "
                        "top_detections, breakdown, status, opened_at, closed_at, disposition) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (c.case_id, *payload, c.status, c.opened_at.isoformat(),
                         c.closed_at.isoformat() if c.closed_at else None, c.disposition),
                    )
                    new_ids.append(c.case_id)
        return new_ids

    def open_cases(self, limit: int = 50) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cases WHERE status = 'open' "
                "ORDER BY risk_score DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_case_row(r) for r in rows]

    def list_cases(self, status: str | None = None, limit: int = 200) -> list[dict]:
        sql, params = "SELECT * FROM cases", []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        sql += " ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, risk_score DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            return [_case_row(r) for r in conn.execute(sql, params).fetchall()]

    def get_case(self, case_id: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        return _case_row(row) if row else None

    def set_case_status(self, case_id: str, status: str, disposition: str | None = None) -> bool:
        closed_at = datetime.now(UTC).isoformat() if status == "closed" else None
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE cases SET status = ?, disposition = COALESCE(?, disposition), "
                "closed_at = ? WHERE case_id = ?",
                (status, disposition, closed_at, case_id),
            )
            return cur.rowcount == 1

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
            d["tags"] = json.loads(d["tags"]) if d.get("tags") else []
            d["attack"] = json.loads(d["attack"]) if d.get("attack") else []
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

    # -- entity timelines and run history ------------------------------

    def save_entity_days(self, actor_id: str, days: list[tuple[str, dict, bool]]) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM entity_days WHERE actor_id = ?", (actor_id,))
            conn.executemany(
                "INSERT INTO entity_days VALUES (?,?,?,?)",
                [(actor_id, day, json.dumps(f), int(scored)) for day, f, scored in days],
            )

    def entity_days(self, actor_id: str) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT day, features, scored FROM entity_days WHERE actor_id = ? ORDER BY day",
                (actor_id,),
            ).fetchall()
        return [{"day": r["day"], "features": json.loads(r["features"]),
                 "scored": bool(r["scored"])} for r in rows]

    def record_run(self, run_id: str, stats: dict) -> None:
        with self.connect() as conn:
            conn.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?)",
                         (run_id, datetime.now(UTC).isoformat(), json.dumps(stats, default=str)))

    def last_run(self) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM runs ORDER BY at DESC LIMIT 1").fetchone()
        if row is None:
            return None
        return {"run_id": row["run_id"], "at": row["at"], **json.loads(row["stats"])}

    def reveals_for_pseudonym(self, pseudonym: str) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM reveals WHERE pseudonym = ? ORDER BY at DESC",
                                (pseudonym,)).fetchall()
        return [dict(r) for r in rows]

    def actor_for_pseudonym(self, pseudonym: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT actor_id FROM cases WHERE pseudonym = ? LIMIT 1",
                               (pseudonym,)).fetchone()
        return row["actor_id"] if row else None

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


_CASE_JSON = ("detection_ids", "context", "engines", "attack", "top_detections", "breakdown")


def _case_row(row) -> dict:
    d = dict(row)
    for key in _CASE_JSON:
        raw = d.get(key)
        d[key] = json.loads(raw) if raw else ([] if key != "breakdown" else {})
    return d


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after 0.1.0 to an existing database."""
    wanted = {
        "cases": ["context", "engines", "attack", "top_detections", "breakdown"],
        "detections": ["title", "tags", "attack"],
    }
    for table, columns in wanted.items():
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        for col in columns:
            if col not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")


def _parse(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None
