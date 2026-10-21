"""Statistical detector.

Z-scores against the entity's baseline: cheap, fast and easy to explain
("222 restricted files read, 3.8x your usual 58"). Two guards keep it honest:

* **Minimum counts.** Twelve files against a baseline of two is an enormous
  z-score and means nothing. Below ``min_events_for_z`` (or a byte floor for
  volume features) no z-score is computed.
* **Absolute ceilings.** A user whose normal is already huge can move a lot
  without shifting their z-score. Fixed floors catch that case.

Confidence is capped at 0.9. An outlier is evidence, never proof.
"""

from __future__ import annotations

from ..baseline.profiler import DailyFeatures, Profile
from ..config import StatisticalConfig
from .attack import techniques_for_features
from .base import FEATURE_LABELS, Detection, fmt_value

MAX_CONFIDENCE = 0.9

# Features worth a z-score, with the severity of a large deviation.
MONITORED: dict[str, str] = {
    "file_read_count": "medium",
    "distinct_files": "low",
    "restricted_file_count": "high",
    "confidential_file_count": "medium",
    "total_bytes": "medium",
    "upload_bytes": "medium",
    "personal_cloud_bytes": "high",
    "external_email_bytes": "medium",
    "external_share_count": "medium",
    "removable_media_count": "medium",
    "removable_media_bytes": "high",
    "failed_logon_count": "medium",
    "distinct_hosts": "medium",
    "privileged_action_count": "high",
    "night_event_count": "medium",
}

# Minimum value before a byte feature is even considered (bytes are never
# "five events"). 50 MB.
MIN_BYTES_FOR_Z = 50_000_000


class StatisticalDetector:
    def __init__(self, config: StatisticalConfig | None = None) -> None:
        self.config = config or StatisticalConfig()

    def _eligible(self, feature: str, value: float) -> bool:
        if feature.endswith("_bytes"):
            return value >= MIN_BYTES_FOR_Z
        return value >= self.config.min_events_for_z

    def evaluate(
        self,
        features: DailyFeatures,
        profile: Profile,
        *,
        baseline_kind: str = "self",
    ) -> list[Detection]:
        c = self.config
        found: list[Detection] = []
        who = {"self": "their own", "peer": "their peer group's", "global": "the organization's"}[
            baseline_kind
        ]
        night = features.get("night_event_count") >= 10
        restricted = features.get("restricted_file_count") >= 10

        def tags_for(feature: str) -> list[str]:
            tags = []
            if night or feature == "night_event_count":
                tags.append("off_hours")
            if restricted or feature == "restricted_file_count":
                tags.append("restricted_data")
            return tags

        for feature, severity in MONITORED.items():
            value = features.get(feature)
            if not self._eligible(feature, value):
                continue
            z = profile.z_score(feature, value)
            if z < c.z_threshold:
                continue
            mean = profile.mean_of(feature)
            ratio = value / mean if mean > 0 else float("inf")
            ratio_txt = f"{ratio:.1f}x" if ratio != float("inf") else "far above"
            # Confidence rises with the size of the deviation, never above 0.9.
            confidence = min(MAX_CONFIDENCE, 0.45 + 0.05 * (z - c.z_threshold))
            if baseline_kind != "self":
                confidence *= 0.8
            explanation = (
                f"{fmt_value(feature, value)} {FEATURE_LABELS[feature]}, {ratio_txt} "
                f"{who} baseline of {fmt_value(feature, mean)} "
                f"({z:.1f} standard deviations out)."
            )
            found.append(
                Detection(
                    actor_id=features.actor_id,
                    day=features.day,
                    engine="statistical",
                    name=f"anomalous_{feature}",
                    title=f"Unusual {FEATURE_LABELS[feature]}",
                    severity=severity,
                    confidence=confidence,
                    explanation=explanation,
                    evidence={
                        "feature": feature,
                        "value": value,
                        "baseline_mean": round(mean, 2),
                        "baseline_std": round(profile.std_of(feature), 2),
                        "z_score": round(z, 2),
                        "baseline": baseline_kind,
                    },
                    tags=tags_for(feature),
                    attack=techniques_for_features([feature]),
                )
            )

        # Absolute ceilings: independent of the baseline.
        reads = features.get("file_read_count")
        if reads >= c.absolute_file_access_floor:
            found.append(
                Detection(
                    actor_id=features.actor_id,
                    day=features.day,
                    engine="statistical",
                    name="absolute_file_volume",
                    title="File access above the absolute ceiling",
                    severity="medium",
                    confidence=0.6,
                    explanation=(
                        f"{fmt_value('file_read_count', reads)} files read in one day, "
                        f"above the fixed ceiling of {c.absolute_file_access_floor:,} "
                        "that applies to everyone regardless of baseline."
                    ),
                    evidence={"file_read_count": reads, "ceiling": c.absolute_file_access_floor},
                    tags=tags_for("file_read_count"),
                    attack=techniques_for_features(["file_read_count"]),
                )
            )
        moved = features.get("total_bytes")
        if moved >= c.absolute_bytes_floor:
            found.append(
                Detection(
                    actor_id=features.actor_id,
                    day=features.day,
                    engine="statistical",
                    name="absolute_data_volume",
                    title="Data volume above the absolute ceiling",
                    severity="medium",
                    confidence=0.6,
                    explanation=(
                        f"{fmt_value('total_bytes', moved)} moved in one day, above the "
                        f"fixed ceiling of {fmt_value('total_bytes', c.absolute_bytes_floor)}."
                    ),
                    evidence={"total_bytes": moved, "ceiling": c.absolute_bytes_floor},
                    tags=tags_for("total_bytes"),
                    attack=techniques_for_features(["total_bytes"]),
                )
            )
        return found
