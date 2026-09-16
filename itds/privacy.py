"""Privacy controls.

Monitoring employees is lawful in most jurisdictions and corrosive in all of
them if done carelessly. This module is what stops the system from becoming
the thing it was built to prevent.

Three mechanisms:

1. **Pseudonymization.** Analysts triage ``EMP-3f8a2c`` — a stable, salted HMAC
   of the real identifier. Investigation happens on behaviour, not on who the
   person is, which removes the most common source of biased triage.
2. **Break-glass reveal.** Re-identification is an explicit, recorded action
   requiring a stated reason and (by default) a second approver.
3. **Reveal auditing.** Every reveal is itself an event. The watchers are
   watched, and the audit log is append-only.

Retention is enforced here too, because a system that keeps everything forever
cannot honestly claim data minimization.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from .config import PrivacyConfig


def _now() -> datetime:
    return datetime.now(UTC)


class RevealDenied(Exception):
    """Raised when a re-identification attempt does not meet policy."""


@dataclass(frozen=True, slots=True)
class RevealRecord:
    """An immutable record of one re-identification."""

    reveal_id: str
    pseudonym: str
    actor_id: str
    requested_by: str
    approved_by: str | None
    reason: str
    case_id: str | None
    at: datetime

    def to_dict(self) -> dict:
        return {
            "reveal_id": self.reveal_id,
            "pseudonym": self.pseudonym,
            "actor_id": self.actor_id,
            "requested_by": self.requested_by,
            "approved_by": self.approved_by,
            "reason": self.reason,
            "case_id": self.case_id,
            "at": self.at.isoformat(),
        }


class Pseudonymizer:
    """Maps real identifiers to stable pseudonyms and back, under audit.

    The mapping is deterministic, so the same person always gets the same
    pseudonym across runs and baselines stay attached to the right entity.
    It is keyed on a salt, so a leaked database of pseudonyms is not a leaked
    database of employees.
    """

    def __init__(self, config: PrivacyConfig | None = None) -> None:
        self.config = config or PrivacyConfig()
        self._reverse: dict[str, str] = {}
        self._audit: list[RevealRecord] = []

    def pseudonym(self, actor_id: str) -> str:
        """Return the stable pseudonym for a real identifier."""
        if not self.config.pseudonymize_by_default:
            return actor_id
        digest = hmac.new(
            self.config.pseudonym_salt.encode("utf-8"),
            actor_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:6]
        pseud = f"EMP-{digest}"
        self._reverse[pseud] = actor_id
        return pseud

    def reveal(
        self,
        pseudonym: str,
        *,
        requested_by: str,
        reason: str,
        approved_by: str | None = None,
        case_id: str | None = None,
    ) -> str:
        """Re-identify a pseudonym. Recorded, and refused without a reason.

        Raises ``RevealDenied`` if policy is not satisfied.
        """
        if not reason or not reason.strip():
            raise RevealDenied("A written reason is required to re-identify a user.")
        if len(reason.strip()) < 15:
            raise RevealDenied(
                "The reason must describe the investigation, not just name it."
            )
        if self.config.require_dual_approval_for_reveal and not approved_by:
            raise RevealDenied("A second approver is required to re-identify a user.")
        if approved_by and approved_by == requested_by:
            raise RevealDenied("The approver must be someone other than the requester.")

        actor_id = self._reverse.get(pseudonym)
        if actor_id is None:
            raise RevealDenied(f"Unknown pseudonym: {pseudonym}")

        record = RevealRecord(
            reveal_id=str(uuid.uuid4()),
            pseudonym=pseudonym,
            actor_id=actor_id,
            requested_by=requested_by,
            approved_by=approved_by,
            reason=reason.strip(),
            case_id=case_id,
            at=_now(),
        )
        self._audit.append(record)
        return actor_id

    @property
    def audit_log(self) -> list[RevealRecord]:
        """Append-only view of every reveal performed."""
        return list(self._audit)

    def register(self, actor_id: str) -> str:
        """Pre-register an identifier so it can be revealed later."""
        return self.pseudonym(actor_id)


@dataclass(slots=True)
class CollectionPolicy:
    """What the collectors are permitted to gather.

    Enforced at ingest. A source that tries to supply a forbidden field has
    that field stripped rather than the event dropped, so the behavioural
    signal survives while the intrusive detail does not.
    """

    # Never collected, under any configuration.
    forbidden_fields: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "file_content",
                "message_body",
                "email_body",
                "keystrokes",
                "screenshot",
                "webcam",
                "microphone",
                "clipboard_content",
                "browser_history_personal",
                "password",
                "private_message",
            }
        )
    )
    # Hosts and paths excluded from monitoring entirely.
    excluded_hosts: frozenset[str] = field(default_factory=frozenset)
    excluded_path_prefixes: tuple[str, ...] = (
        "/home/*/Personal/",
        "C:\\Users\\*\\Personal\\",
    )

    def scrub(self, raw: dict) -> tuple[dict, list[str]]:
        """Remove forbidden fields. Returns the clean record and what was cut."""
        removed = [k for k in raw if k.lower() in self.forbidden_fields]
        clean = {k: v for k, v in raw.items() if k.lower() not in self.forbidden_fields}
        return clean, removed


def expired_before(retention_days: int, *, now: datetime | None = None) -> datetime:
    """The cutoff timestamp for a retention window."""
    now = now or _now()
    return now - timedelta(days=retention_days)
