"""Tamper-evident audit log.

Every action an analyst takes in Sentry (logging in, opening a case, asking to
see who is behind a pseudonym, approving that request, closing a case) is
written here. A monitoring tool that cannot show who monitored whom is asking
to be trusted without earning it.

Each entry stores the SHA-256 of the previous entry, forming a hash chain. Edit
or delete a row in the middle and every hash after it stops matching, which
``verify`` reports with the first broken sequence number. It does not stop a
database administrator from rewriting the whole chain, so for strong guarantees
export the latest hash somewhere they cannot reach (a SIEM, a ticket, a
printout) on a schedule: ``python -m itds audit head``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

GENESIS = "0" * 64


def _entry_hash(prev_hash: str, at: str, actor: str, action: str, target: str | None,
                details: str) -> str:
    material = json.dumps([prev_hash, at, actor, action, target, details], separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int
    first_bad_seq: int | None = None
    head: str = GENESIS

    def __str__(self) -> str:
        if self.ok:
            return f"Audit chain intact: {self.entries} entries, head {self.head[:16]}"
        return f"Audit chain BROKEN at entry {self.first_bad_seq} (of {self.entries})"


class AuditLog:
    def __init__(self, store) -> None:
        self.store = store

    def record(self, actor: str, action: str, target: str | None = None,
               details: dict[str, Any] | None = None) -> str:
        at = datetime.now(UTC).isoformat()
        body = json.dumps(details or {}, sort_keys=True, default=str)
        with self.store.connect() as conn:
            # BEGIN IMMEDIATE serialises writers so two entries never share a parent.
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            h = _entry_hash(prev, at, actor, action, target, body)
            conn.execute(
                "INSERT INTO audit_log (at, actor, action, target, details, prev_hash, hash) "
                "VALUES (?,?,?,?,?,?,?)",
                (at, actor, action, target, body, prev, h),
            )
        return h

    def entries(self, limit: int = 200, actor: str | None = None,
                action: str | None = None) -> list[dict]:
        sql, params = "SELECT * FROM audit_log", []
        where = []
        if actor:
            where.append("actor = ?")
            params.append(actor)
        if action:
            where.append("action = ?")
            params.append(action)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY seq DESC LIMIT ?"
        params.append(limit)
        with self.store.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d["details"]) if d["details"] else {}
            out.append(d)
        return out

    def head(self) -> str:
        with self.store.connect() as conn:
            row = conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def verify(self) -> VerifyResult:
        prev = GENESIS
        count = 0
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT seq, at, actor, action, target, details, prev_hash, hash "
                "FROM audit_log ORDER BY seq"
            ).fetchall()
        for r in rows:
            count += 1
            expected = _entry_hash(prev, r["at"], r["actor"], r["action"], r["target"],
                                   r["details"])
            if r["prev_hash"] != prev or r["hash"] != expected:
                return VerifyResult(False, len(rows), r["seq"], prev)
            prev = r["hash"]
        return VerifyResult(True, count, None, prev)
