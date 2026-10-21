"""The analyst feedback loop.

Alert fatigue is the failure Sentry is designed around, so analysts' verdicts
are first-class data rather than notes nobody reads. Three things use them:

1. **Suppressions.** Marking a case a false positive can suppress the
   detections that caused it, for that person only, for a fixed period
   (30 days by default). Suppressions expire on their own: a permanent
   exception is how a real threat hides behind last year's false alarm.
2. **Rule health.** For every detection, the share of reviewed cases where it
   was part of a true positive. A rule with many verdicts and low precision is
   flagged for tuning.
3. **Learned weights.** Once a detection has enough verdicts, its weight in
   the risk score moves between x0.5 and x1.5 according to its precision.
   Bounded on purpose: feedback adjusts the score, it never silences a rule.

Dispositions:
* ``true_positive``   a real policy violation or threat.
* ``benign_positive`` real behaviour, but authorized or explained.
* ``false_positive``  the detection was wrong.
"""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta

DISPOSITIONS = ("true_positive", "benign_positive", "false_positive")
MIN_VERDICTS_FOR_WEIGHT = 5
MIN_VERDICTS_FOR_HEALTH = 5
UNHEALTHY_PRECISION = 0.2
DEFAULT_SUPPRESSION_DAYS = 30


def _now() -> datetime:
    return datetime.now(UTC)


class FeedbackStore:
    def __init__(self, store) -> None:
        self.store = store

    def record(self, case_id: str, disposition: str, analyst: str, note: str = "",
               *, suppress_days: int | None = None) -> dict:
        if disposition not in DISPOSITIONS:
            raise ValueError(f"disposition must be one of {DISPOSITIONS}")
        case = self.store.get_case(case_id)
        if case is None:
            raise KeyError(case_id)
        names = sorted({d["name"] for d in case.get("top_detections", [])})
        if not names:
            names = sorted({d["name"] for d in self.store.detections_for(case["actor_id"])})
        fid = str(uuid.uuid4())
        with self.store.connect() as conn:
            conn.execute(
                "INSERT INTO feedback VALUES (?,?,?,?,?,?,?,?)",
                (fid, case_id, case["actor_id"], disposition, analyst, note or None,
                 json.dumps(names), _now().isoformat()),
            )
        suppressed = []
        if disposition == "false_positive" and suppress_days:
            for name in names:
                self.add_suppression(case["actor_id"], name,
                                     f"False positive on case {case_id}: {note or 'no note'}",
                                     analyst, days=suppress_days)
                suppressed.append(name)
        return {"feedback_id": fid, "detections": names, "suppressed": suppressed}

    def for_case(self, case_id: str) -> list[dict]:
        with self.store.connect() as conn:
            rows = conn.execute("SELECT * FROM feedback WHERE case_id = ? ORDER BY at DESC",
                                (case_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["detection_names"] = json.loads(d["detection_names"] or "[]")
            out.append(d)
        return out

    # -- suppressions

    def add_suppression(self, actor_id: str, detection_name: str, reason: str,
                        created_by: str, *, days: int = DEFAULT_SUPPRESSION_DAYS) -> str:
        if days < 1 or days > 180:
            raise ValueError("suppressions last between 1 and 180 days")
        sid = str(uuid.uuid4())
        with self.store.connect() as conn:
            conn.execute(
                "INSERT INTO suppressions VALUES (?,?,?,?,?,?,?)",
                (sid, actor_id, detection_name, reason, created_by, _now().isoformat(),
                 (_now() + timedelta(days=days)).isoformat()),
            )
        return sid

    def remove_suppression(self, suppression_id: str) -> bool:
        with self.store.connect() as conn:
            cur = conn.execute("DELETE FROM suppressions WHERE suppression_id = ?",
                               (suppression_id,))
            return cur.rowcount == 1

    def active_suppressions(self, at: datetime | None = None) -> list[dict]:
        at = at or _now()
        with self.store.connect() as conn:
            rows = conn.execute("SELECT * FROM suppressions WHERE expires_at > ? "
                                "ORDER BY expires_at", (at.isoformat(),)).fetchall()
        return [dict(r) for r in rows]

    def suppression_set(self, at: datetime | None = None) -> set[tuple[str, str]]:
        return {(s["actor_id"], s["detection_name"]) for s in self.active_suppressions(at)}

    # -- learning from verdicts

    def detection_stats(self) -> dict[str, dict]:
        stats: dict[str, dict] = defaultdict(lambda: dict.fromkeys(DISPOSITIONS, 0))
        with self.store.connect() as conn:
            rows = conn.execute("SELECT disposition, detection_names FROM feedback").fetchall()
        for r in rows:
            for name in json.loads(r["detection_names"] or "[]"):
                stats[name][r["disposition"]] += 1
        out = {}
        for name, counts in stats.items():
            total = sum(counts.values())
            # Benign positives are correct detections of real behaviour: they
            # count towards precision, but not as threats.
            correct = counts["true_positive"] + counts["benign_positive"]
            precision = correct / total if total else None
            out[name] = {
                **counts,
                "verdicts": total,
                "precision": round(precision, 3) if precision is not None else None,
                "needs_tuning": total >= MIN_VERDICTS_FOR_HEALTH
                and precision is not None and precision < UNHEALTHY_PRECISION,
            }
        return out

    def learned_weights(self) -> dict[str, float]:
        """Per-detection multipliers in [0.5, 1.5], only with enough verdicts."""
        weights = {}
        for name, s in self.detection_stats().items():
            if s["verdicts"] >= MIN_VERDICTS_FOR_WEIGHT and s["precision"] is not None:
                weights[name] = round(0.5 + s["precision"], 3)
        return weights
