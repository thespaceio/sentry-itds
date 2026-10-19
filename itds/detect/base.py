"""The detection record every engine produces.

A detection is a single piece of evidence about one entity on one day. It is
not an alert: alerts (cases) come from accumulating detections in
``scoring.risk``. Keeping the two separate is what lets the system collect
plenty of weak evidence without paging anyone about each piece.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import date
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")

# Base contribution of one detection to an entity's raw risk, before
# confidence, decay and context multipliers.
SEVERITY_WEIGHTS: dict[str, float] = {
    "low": 6.0,
    "medium": 15.0,
    "high": 30.0,
    "critical": 60.0,
}

# Tags the risk scorer understands as context.
CONTEXT_TAGS = {
    "off-hours": "off_hours",
    "off_hours": "off_hours",
    "sensitive-data": "restricted_data",
    "restricted_data": "restricted_data",
}


@dataclass(slots=True)
class Detection:
    """One explained finding. An empty explanation is a constructor error."""

    actor_id: str
    day: date
    engine: str
    name: str
    severity: str
    explanation: str
    confidence: float = 1.0
    title: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)
    base_weight: float = 0.0
    detection_id: str = ""

    def __post_init__(self) -> None:
        if not self.explanation or not self.explanation.strip():
            raise ValueError(
                f"detection {self.name!r} has no explanation; every finding must say why"
            )
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}, got {self.severity!r}")
        self.confidence = float(min(1.0, max(0.0, self.confidence)))
        if not self.base_weight:
            self.base_weight = SEVERITY_WEIGHTS[self.severity]
        if not self.title:
            self.title = self.name.replace("_", " ").capitalize()
        if not self.detection_id:
            raw = f"{self.actor_id}|{self.day.isoformat()}|{self.engine}|{self.name}"
            self.detection_id = hashlib.sha1(raw.encode()).hexdigest()[:16]

    @property
    def context(self) -> set[str]:
        return {CONTEXT_TAGS[t] for t in self.tags if t in CONTEXT_TAGS}

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "actor_id": self.actor_id,
            "day": self.day.isoformat(),
            "engine": self.engine,
            "name": self.name,
            "title": self.title,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "base_weight": self.base_weight,
            "explanation": self.explanation,
            "evidence": self.evidence,
            "tags": list(self.tags),
            "attack": list(self.attack),
        }


def fmt_value(feature: str, value: float) -> str:
    """Human-readable feature value: bytes as GB/MB, counts as integers."""
    if feature.endswith("_bytes"):
        if value >= 1e9:
            return f"{value / 1e9:.1f} GB"
        if value >= 1e6:
            return f"{value / 1e6:.0f} MB"
        if value >= 1e3:
            return f"{value / 1e3:.0f} KB"
        return f"{value:.0f} B"
    if float(value).is_integer():
        return f"{int(value):,}"
    return f"{value:.1f}"


FEATURE_LABELS: dict[str, str] = {
    "event_count": "events",
    "file_read_count": "files read",
    "file_write_count": "files written",
    "distinct_files": "distinct files touched",
    "restricted_file_count": "restricted files read",
    "confidential_file_count": "confidential files read",
    "total_bytes": "data moved",
    "upload_bytes": "data uploaded",
    "personal_cloud_bytes": "data uploaded to personal cloud",
    "external_email_count": "external emails",
    "external_email_bytes": "data emailed externally",
    "external_share_count": "external sharing links created",
    "removable_media_count": "removable media events",
    "removable_media_bytes": "data written to removable media",
    "logon_count": "logons",
    "failed_logon_count": "failed logons",
    "distinct_hosts": "distinct hosts used",
    "distinct_countries": "countries logged in from",
    "privileged_action_count": "privileged commands",
    "night_event_count": "night-time events",
    "weekend": "weekend activity",
}
