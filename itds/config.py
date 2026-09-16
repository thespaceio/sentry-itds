"""Configuration.

Every threshold the system reasons with lives here rather than scattered
through the detection code. Tuning a deployment should mean editing one file
or setting environment variables, never editing logic.

Environment variables use the ``ITDS_`` prefix and map to the field name in
upper case, e.g. ``ITDS_ALERT_BUDGET=30``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default):
    raw = os.environ.get(f"ITDS_{name.upper()}")
    if raw is None:
        return default
    if isinstance(default, bool):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(default, int):
        return int(raw)
    if isinstance(default, float):
        return float(raw)
    return raw


@dataclass
class BaselineConfig:
    """How much history a profile needs before it is trusted."""

    # Rolling window used to build each user's normal behaviour.
    window_days: int = 30
    # Below this, a user has no usable profile. Statistical and ML detections
    # are suppressed for them and the case is tagged INSUFFICIENT_HISTORY.
    min_days_history: int = 7
    # An hour is "off-hours" for a user if it falls below this share of their
    # own historical activity.
    off_hours_percentile: float = 0.05
    # Peer groups smaller than this are unreliable; fall back to global.
    min_peer_group_size: int = 5


@dataclass
class StatisticalConfig:
    """Z-score and volume thresholds."""

    z_threshold: float = 3.0
    # Below this many events, a z-score is noise. Small numbers produce huge
    # z-scores against a near-zero baseline; this is the guard.
    min_events_for_z: int = 5
    # Absolute floors, so a user with a genuinely high baseline still trips.
    absolute_file_access_floor: int = 500
    absolute_bytes_floor: int = 2_000_000_000  # 2 GB in a day


@dataclass
class MLConfig:
    """Isolation Forest settings."""

    contamination: float = 0.02
    n_estimators: int = 200
    max_samples: str | int = "auto"
    random_state: int = 42
    # Anomaly scores below this are ignored entirely. Keeps the case queue
    # from filling with marginal outliers.
    score_threshold: float = 0.55


@dataclass
class RiskConfig:
    """Risk accumulation and case creation."""

    # Days for a detection's contribution to halve.
    half_life_days: float = 7.0
    # Score at or above which an entity becomes a case.
    case_threshold: float = 60.0
    # Hard cap so one noisy day cannot pin a user at maximum forever.
    max_score: float = 100.0
    # Multipliers applied to a detection's base weight.
    multiplier_departing: float = 2.0
    multiplier_privileged: float = 1.5
    multiplier_restricted_data: float = 1.6
    multiplier_off_hours: float = 1.3
    # The most important number in the system. See docs/ARCHITECTURE.md.
    # Cases per day one analyst can genuinely review. Tune everything to fit.
    alert_budget: int = 20


@dataclass
class PrivacyConfig:
    """Privacy controls. These are defaults, not suggestions — see docs/PRIVACY.md."""

    # Analysts see pseudonyms until a documented reveal.
    pseudonymize_by_default: bool = True
    # Salt for the pseudonym HMAC. MUST be overridden in any real deployment.
    pseudonym_salt: str = "change-me-before-you-deploy-this"
    # Content is never collected, only metadata. Flipping this to True is not
    # supported; the flag exists so the choice is visible in config review.
    collect_content: bool = False
    # Days before raw events are deleted.
    event_retention_days: int = 90
    # Days before closed cases are deleted.
    case_retention_days: int = 365
    # Reveals require a second approver.
    require_dual_approval_for_reveal: bool = True


@dataclass
class Config:
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    statistical: StatisticalConfig = field(default_factory=StatisticalConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)

    rules_dir: Path = REPO_ROOT / "rules"
    data_dir: Path = REPO_ROOT / "data"
    db_path: Path = REPO_ROOT / "data" / "itds.db"

    @classmethod
    def from_env(cls) -> Config:
        cfg = cls()
        for section_name in ("baseline", "statistical", "ml", "risk", "privacy"):
            section = getattr(cfg, section_name)
            for f in fields(section):
                current = getattr(section, f.name)
                setattr(section, f.name, _env(f.name, current))
        cfg.db_path = Path(_env("db_path", str(cfg.db_path)))
        cfg.rules_dir = Path(_env("rules_dir", str(cfg.rules_dir)))
        cfg.data_dir = Path(_env("data_dir", str(cfg.data_dir)))
        return cfg


DEFAULT_CONFIG = Config()
