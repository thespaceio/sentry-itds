"""Rule engine.

Rules are YAML, so a detection engineer can add one without touching Python.
There are two kinds, and a rule may use either or both:

* ``match``: count the day's events that match every field. Fires when the
  count reaches ``threshold``. Values may be a single pattern or a list of
  alternatives; patterns use shell wildcards (``*dropbox.com``).
* ``aggregate``: conditions on the day's feature vector, e.g.
  ``file_read_count > 250``. Every condition must hold.

``require_context`` gates a rule on facts about the person rather than the
activity (``departing``, ``privileged``, ``new_joiner``). That is how the same
volume can be routine for one person and the strongest signal there is for
another.

See docs/DETECTION_RULES.md for the full reference.
"""

from __future__ import annotations

import operator
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from ..baseline.profiler import FEATURE_NAMES, DailyFeatures
from ..schema import Event, Identity
from .attack import validate as validate_attack
from .base import FEATURE_LABELS, SEVERITIES, Detection, fmt_value

_OPS = {
    ">=": operator.ge,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    "<": operator.lt,
}
_COND = re.compile(r"^\s*([a-z_][a-z0-9_]*)\s*(>=|<=|==|!=|>|<)\s*(-?\d+(?:\.\d+)?)\s*$")

KNOWN_CONTEXT = {"departing", "privileged", "new_joiner"}


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    description: str = ""
    match: dict[str, Any] | None = None
    aggregate: dict[str, Any] | None = None
    threshold: int = 1
    require_context: list[str] = field(default_factory=list)
    confidence: float = 0.8
    tags: list[str] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"rule {self.id}: severity must be one of {SEVERITIES}")
        if not self.match and not self.aggregate:
            raise ValueError(f"rule {self.id}: needs a 'match' or an 'aggregate' block")
        # YAML files nest require_context under aggregate; accept both.
        if self.aggregate and "require_context" in self.aggregate:
            extra = self.aggregate.get("require_context") or []
            self.require_context = list(dict.fromkeys([*self.require_context, *extra]))
        unknown = set(self.require_context) - KNOWN_CONTEXT
        if unknown:
            raise ValueError(f"rule {self.id}: unknown context {sorted(unknown)}")

    @property
    def conditions(self) -> list[str]:
        if not self.aggregate:
            return []
        cond = self.aggregate.get("condition") or []
        return [cond] if isinstance(cond, str) else list(cond)


def parse_condition(text: str) -> tuple[str, Any, float]:
    m = _COND.match(text)
    if not m:
        raise ValueError(f"cannot parse condition {text!r}; expected 'feature > number'")
    name, op, number = m.groups()
    if name not in FEATURE_NAMES:
        raise ValueError(f"cannot parse condition {text!r}; unknown feature {name!r}")
    return name, _OPS[op], float(number)


def load_rules(directory: str | Path) -> list[Rule]:
    """Load and validate every ``*.yml``/``*.yaml`` rule in a directory."""
    directory = Path(directory)
    rules: list[Rule] = []
    seen: set[str] = set()
    for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        allowed = Rule.__dataclass_fields__.keys()
        unknown = set(raw) - set(allowed)
        if unknown:
            raise ValueError(f"{path.name}: unknown keys {sorted(unknown)}")
        rule = Rule(**raw)
        if rule.id in seen:
            raise ValueError(f"{path.name}: duplicate rule id {rule.id!r}")
        bad = validate_attack(rule.attack)
        if bad:
            raise ValueError(f"{path.name}: unknown ATT&CK technique(s) {bad}")
        for c in rule.conditions:
            parse_condition(c)
        seen.add(rule.id)
        if rule.enabled:
            rules.append(rule)
    return rules


def _field_matches(value: Any, pattern: Any) -> bool:
    if isinstance(pattern, list):
        return any(_field_matches(value, p) for p in pattern)
    if value is None:
        return False
    if isinstance(pattern, (int, float, bool)) and not isinstance(value, str):
        return value == pattern
    return fnmatchcase(str(value).lower(), str(pattern).lower())


def _event_matches(event: Event, match: dict[str, Any]) -> bool:
    for key, pattern in match.items():
        if key.startswith("extra."):
            value = event.extra.get(key[6:])
        else:
            value = getattr(event, key, None)
            if hasattr(value, "value"):  # enums
                value = value.value
        if not _field_matches(value, pattern):
            return False
    return True


class RuleEngine:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    @staticmethod
    def _context_holds(rule: Rule, identity: Identity | None, day: date) -> bool:
        if not rule.require_context:
            return True
        if identity is None:
            return False
        at = datetime.combine(day, time(12), tzinfo=UTC)
        for ctx in rule.require_context:
            if ctx == "departing" and not identity.is_departing(at):
                return False
            if ctx == "privileged" and not identity.is_privileged:
                return False
            if ctx == "new_joiner":
                joined = identity.joined_on
                if joined is None:
                    return False
                if joined.tzinfo is None:
                    joined = joined.replace(tzinfo=UTC)
                if (at - joined).days > 30:
                    return False
        return True

    def evaluate(
        self,
        actor_id: str,
        day: date,
        events: list[Event],
        features: DailyFeatures,
        identity: Identity | None = None,
    ) -> list[Detection]:
        found: list[Detection] = []
        for rule in self.rules:
            if not self._context_holds(rule, identity, day):
                continue
            evidence: dict[str, Any] = {}
            reasons: list[str] = []

            if rule.match:
                hits = [e for e in events if _event_matches(e, rule.match)]
                if len(hits) < max(1, rule.threshold):
                    continue
                evidence["matching_events"] = len(hits)
                sample = hits[0]
                evidence["example"] = {
                    k: v
                    for k, v in {
                        "time": sample.timestamp.strftime("%H:%M"),
                        "action": sample.action,
                        "destination": sample.destination,
                        "object": sample.object_name,
                        "bytes": sample.bytes or None,
                    }.items()
                    if v
                }
                total = sum(e.bytes for e in hits)
                desc = f"{len(hits)} matching event{'s' if len(hits) != 1 else ''}"
                if total:
                    desc += f" ({fmt_value('upload_bytes', total)})"
                if sample.destination:
                    desc += f", e.g. to {sample.destination}"
                elif sample.object_name:
                    desc += f", e.g. {sample.object_name}"
                reasons.append(desc)

            if rule.aggregate:
                ok = True
                for cond in rule.conditions:
                    name, op, number = parse_condition(cond)
                    value = features.get(name)
                    if not op(value, number):
                        ok = False
                        break
                    evidence[name] = value
                    if name != "weekend":
                        reasons.append(f"{fmt_value(name, value)} {FEATURE_LABELS[name]}")
                if not ok:
                    continue
                if any(c.startswith("weekend") for c in rule.conditions):
                    reasons.append("on a weekend")

            if rule.require_context:
                evidence["context"] = list(rule.require_context)

            when = f"{day.day} {day.strftime('%b %Y')}"
            explanation = f"{rule.title}: {', '.join(reasons)} on {when}."
            found.append(
                Detection(
                    actor_id=actor_id,
                    day=day,
                    engine="rules",
                    name=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    explanation=explanation,
                    evidence=evidence,
                    tags=list(rule.tags),
                    attack=list(rule.attack),
                )
            )
        return found
