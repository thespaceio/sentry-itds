"""Risk scoring.

Detections are evidence; cases are decisions. This module turns the first into
the second, and is where most of the design effort in Sentry lives, because
this is where behavioural monitoring usually fails: it detects unusual
activity accurately, discovers most unusual activity is innocent, floods the
queue and gets ignored.

For each entity:

1. Each detection contributes ``severity weight x confidence``.
2. **Decay.** Contributions halve every ``half_life_days``. Old news fades.
3. **Context.** Findings involving restricted data or off-hours activity are
   multiplied. So is everything about a departing or privileged person.
4. **Repetition is not corroboration.** The same detection on many days is one
   behaviour seen many times. Repeats are discounted geometrically: the second
   is worth a third of the first, the third a ninth, and so on.
5. **Diversity is corroboration.** Findings from two engines earn x1.1, from
   all three x1.25, because the engines fail in different ways.
6. The raw total is mapped to 0-100 with a saturating curve, so scores stay
   comparable and one entity cannot run away to infinity.

Cases open at ``case_threshold`` and the queue is truncated to the alert
budget: the number of cases one analyst can genuinely review in a day.
"""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time
from typing import Any

from ..config import RiskConfig
from ..detect.base import Detection
from ..schema import Identity

REPEAT_DISCOUNT = 1 / 3
DIVERSITY_BONUS = {1: 1.0, 2: 1.1, 3: 1.25}
# Raw risk at which the score reaches ~63% of the maximum.
SATURATION = 60.0

# Planted labels that describe careless but innocent behaviour. A queue that
# ranks these above real threats is failing, but they are not threats.
BENIGN_LABEL_PREFIXES = ("negligent",)


def is_threat_label(label: str) -> bool:
    return not label.startswith(BENIGN_LABEL_PREFIXES)


@dataclass
class Case:
    case_id: str
    actor_id: str
    risk_score: float
    opened_at: datetime
    updated_at: datetime
    pseudonym: str | None = None
    status: str = "open"
    closed_at: datetime | None = None
    disposition: str | None = None
    summary: str = ""
    detection_ids: list[str] = field(default_factory=list)
    top_detections: list[Detection] = field(default_factory=list)
    context: list[str] = field(default_factory=list)
    engines: list[str] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)
    breakdown: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "actor_id": self.actor_id,
            "pseudonym": self.pseudonym,
            "risk_score": self.risk_score,
            "status": self.status,
            "opened_at": self.opened_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "disposition": self.disposition,
            "summary": self.summary,
            "detection_ids": list(self.detection_ids),
            "top_detections": [d.to_dict() for d in self.top_detections],
            "context": list(self.context),
            "engines": list(self.engines),
            "attack": list(self.attack),
            "breakdown": self.breakdown,
        }


class RiskScorer:
    def __init__(self, config: RiskConfig | None = None,
                 learned_weights: dict[str, float] | None = None) -> None:
        self.config = config or RiskConfig()
        # Per-detection multipliers learned from analyst verdicts (see feedback.py).
        self.learned_weights: dict[str, float] = dict(learned_weights or {})

    def decay_factor(self, age_days: float) -> float:
        return 0.5 ** (max(0.0, age_days) / self.config.half_life_days)

    def _detection_weight(self, d: Detection, as_of: datetime) -> float:
        c = self.config
        age = (as_of.date() - d.day).days
        w = d.base_weight * d.confidence * self.decay_factor(age)
        w *= self.learned_weights.get(d.name, 1.0)
        ctx = d.context
        if "restricted_data" in ctx:
            w *= c.multiplier_restricted_data
        if "off_hours" in ctx:
            w *= c.multiplier_off_hours
        return w

    def entity_context(self, identity: Identity | None, as_of: datetime) -> list[str]:
        ctx = []
        if identity is not None:
            if identity.is_departing(as_of):
                ctx.append("departing")
            if identity.is_privileged:
                ctx.append("privileged")
        return ctx

    def score_entity(
        self,
        actor_id: str,
        detections: list[Detection],
        identity: Identity | None = None,
        *,
        as_of: datetime,
    ) -> tuple[float, dict[str, Any]]:
        """Return (score 0..max_score, breakdown)."""
        c = self.config
        if as_of.tzinfo is None:
            as_of = as_of.replace(tzinfo=UTC)
        if not detections:
            return 0.0, {"raw": 0.0, "contributions": {}}

        by_name: dict[str, list[float]] = defaultdict(list)
        for d in detections:
            by_name[d.name].append(self._detection_weight(d, as_of))

        contributions: dict[str, float] = {}
        for name, weights in by_name.items():
            weights.sort(reverse=True)
            contributions[name] = sum(w * REPEAT_DISCOUNT**i for i, w in enumerate(weights))

        raw = sum(contributions.values())
        engines = {d.engine for d in detections}
        diversity = DIVERSITY_BONUS.get(min(len(engines), 3), 1.0)
        raw *= diversity

        ctx = self.entity_context(identity, as_of)
        if "departing" in ctx:
            raw *= c.multiplier_departing
        if "privileged" in ctx:
            raw *= c.multiplier_privileged

        score = c.max_score * (1 - math.exp(-raw / SATURATION))
        score = round(min(c.max_score, score), 1)
        return score, {
            "raw": round(raw, 2),
            "diversity_multiplier": diversity,
            "entity_context": ctx,
            "contributions": {k: round(v, 2) for k, v in sorted(
                contributions.items(), key=lambda kv: -kv[1])},
        }

    def build_cases(
        self,
        detections_by_actor: dict[str, list[Detection]],
        identities: dict[str, Identity] | None = None,
        *,
        as_of: datetime,
        pseudonymizer=None,
    ) -> list[Case]:
        identities = identities or {}
        if as_of.tzinfo is None:
            as_of = as_of.replace(tzinfo=UTC)
        cases: list[Case] = []
        for actor_id, dets in detections_by_actor.items():
            if not dets:
                continue
            identity = identities.get(actor_id)
            score, breakdown = self.score_entity(actor_id, dets, identity, as_of=as_of)
            if score < self.config.case_threshold:
                continue
            cases.append(self._make_case(actor_id, dets, identity, score, breakdown,
                                         as_of, pseudonymizer))
        cases.sort(key=lambda c: (-c.risk_score, c.actor_id))
        return cases[: self.config.alert_budget]

    def _make_case(self, actor_id, dets, identity, score, breakdown, as_of, pseudonymizer):
        # Rank detections by their individual contribution, one per name.
        weighted = sorted(dets, key=lambda d: -self._detection_weight(d, as_of))
        top: list[Detection] = []
        seen: set[str] = set()
        for d in weighted:
            if d.name not in seen:
                top.append(d)
                seen.add(d.name)
            if len(top) == 5:
                break

        context = self.entity_context(identity, as_of)
        for d in dets:
            for ctx in sorted(d.context):
                if ctx not in context:
                    context.append(ctx)
        engines = sorted({d.engine for d in dets})
        attack: list[str] = []
        for d in top + weighted:
            for t in d.attack:
                if t not in attack:
                    attack.append(t)

        first_day: date = min(d.day for d in dets)
        case_id = "C-" + hashlib.sha1(f"{actor_id}|{first_day}".encode()).hexdigest()[:8]
        pseudonym = pseudonymizer.pseudonym(actor_id) if pseudonymizer else None

        lines = [
            f"Risk {score:.0f} from {len(dets)} finding{'s' if len(dets) != 1 else ''} "
            f"across {', '.join(engines)}."
        ]
        for d in top[:3]:
            text = d.explanation
            if not text.startswith(d.title or ""):
                text = f"{d.title}: {text}"
            lines.append(f"• {text}")

        return Case(
            case_id=case_id,
            actor_id=actor_id,
            risk_score=score,
            opened_at=datetime.combine(first_day, time(0), tzinfo=UTC),
            updated_at=as_of,
            pseudonym=pseudonym,
            summary="\n".join(lines),
            detection_ids=[d.detection_id for d in dets],
            top_detections=top,
            context=context,
            engines=engines,
            attack=attack,
            breakdown=breakdown,
        )


def evaluate_queue(cases: list[Case], labels: dict[str, str], alert_budget: int) -> dict:
    """Precision, recall and rank of each planted threat within the budget."""
    queue = cases[:alert_budget]
    threats = {a for a, label in labels.items() if is_threat_label(label)}
    ranks = {c.actor_id: i for i, c in enumerate(queue, start=1)}
    found = threats & set(ranks)
    precision = len(found) / len(queue) if queue else 0.0
    recall = len(found) / len(threats) if threats else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision_at_budget": round(precision, 3),
        "recall_at_budget": round(recall, 3),
        "f1_at_budget": round(f1, 3),
        "threats_planted": len(threats),
        "threats_found": len(found),
        "cases_opened": len(queue),
        "alert_budget": alert_budget,
        "threat_ranks": {a: ranks[a] for a in found},
        "false_positives": [c.actor_id for c in queue if c.actor_id not in threats],
    }
