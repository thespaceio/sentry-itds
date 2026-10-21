"""Normalization.

Every source names things differently. One system logs ``CORP\\falabi``, another
``faith.alabi@corp.example``, a third ``FALABI``. Before anything is baselined,
those must become one actor, and every record must become an ``Event``.

This module owns three jobs:

* **Identity resolution**: collapse identifier variants into one canonical id.
* **Classification**: assign a sensitivity to the object an event touched.
  Path heuristics are a stand-in: real deployments should feed labels from a
  DLP or data classification system.
* **Mapping**: translate source rows (CERT, generic CSV/JSONL) into events,
  stripping forbidden fields on the way in.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime
from typing import Any

from ..privacy import CollectionPolicy
from ..schema import Category, Event, Sensitivity

# -- identity -----------------------------------------------------------------


def canonical_key(identifier: str) -> str:
    """Reduce an identifier to a comparable key.

    ``CORP\\jdoe``, ``j.doe@corp.example`` and ``J.Doe`` all become ``jdoe``.
    """
    s = identifier.strip().lower()
    s = re.split(r"[\\/]", s)[-1]
    s = s.split("@", 1)[0]
    return re.sub(r"[._\-\s]", "", s)


class IdentityResolver:
    """Maps every known variant of an identifier to one canonical actor id."""

    def __init__(self) -> None:
        self._map: dict[str, str] = {}

    def register(self, canonical: str, *aliases: str) -> None:
        for name in (canonical, *aliases):
            self._map[canonical_key(name)] = canonical

    def resolve(self, identifier: str) -> str:
        key = canonical_key(identifier)
        return self._map.get(key, key)


# -- classification -----------------------------------------------------------

_RESTRICTED = re.compile(
    r"(/hr/|personnel|payroll|salary|salaries|/legal/|board|/exec|merger|acquisition"
    r"|m&a|credential|password|secret|private[_ -]?key|\.pem$|\.kdbx$|medical|disciplinary)",
    re.I,
)
_CONFIDENTIAL = re.compile(
    r"(/finance/|ledger|invoice|budget|forecast|customer|client|pricing|contract"
    r"|roadmap|/design/|source|/src/|/research/|strategy)",
    re.I,
)
_PUBLIC = re.compile(r"(/public/|/press/|/marketing/assets|logo|brochure)", re.I)


def classify_sensitivity(path: str | None) -> Sensitivity:
    """Best-effort sensitivity from a file path or object name."""
    if not path:
        return Sensitivity.INTERNAL
    path = path.replace("\\", "/")  # Windows and UNC paths
    if _RESTRICTED.search(path):
        return Sensitivity.RESTRICTED
    if _CONFIDENTIAL.search(path):
        return Sensitivity.CONFIDENTIAL
    if _PUBLIC.search(path):
        return Sensitivity.PUBLIC
    return Sensitivity.INTERNAL


PERSONAL_CLOUD_DOMAINS: tuple[str, ...] = (
    "dropbox.com",
    "drive.google.com",
    "docs.google.com",
    "mega.nz",
    "mega.io",
    "wetransfer.com",
    "pcloud.com",
    "onedrive.live.com",
    "icloud.com",
    "mediafire.com",
    "box.com",
    "sendspace.com",
    "transfer.sh",
    "anonfiles.com",
    "gofile.io",
)


def is_personal_cloud(destination: str | None) -> bool:
    """True if the destination is a consumer file-sharing service."""
    if not destination:
        return False
    d = destination.lower()
    d = re.sub(r"^[a-z]+://", "", d)
    host = d.split("/", 1)[0]
    path_host = d  # e.g. "drive.google.com/upload"
    for domain in PERSONAL_CLOUD_DOMAINS:
        if host == domain or host.endswith("." + domain) or path_host.startswith(domain):
            return True
    return False


# -- mapping ------------------------------------------------------------------

CERT_DATE = "%m/%d/%Y %H:%M:%S"
CERT_INTERNAL_DOMAIN = "dtaa.com"


def _parse_cert_date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.strptime(raw.strip(), CERT_DATE).replace(tzinfo=UTC)
    except ValueError:
        return None


def _parse_any_date(raw: Any) -> datetime | None:
    if raw is None or raw == "":
        return None
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(float(raw), UTC)
    s = str(raw).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return _parse_cert_date(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class Normalizer:
    """Turns source rows into events and keeps count of what it threw away."""

    def __init__(
        self,
        resolver: IdentityResolver | None = None,
        policy: CollectionPolicy | None = None,
    ) -> None:
        self.resolver = resolver or IdentityResolver()
        self.policy = policy or CollectionPolicy()
        self.dropped_fields: Counter = Counter()
        self.dropped_rows = 0
        self.mapped_rows = 0

    # -- driver

    def normalize_many(
        self, rows: Iterable[dict], mapper: Callable[[dict], Event | None]
    ) -> Iterator[Event]:
        """Scrub each row, map it, and yield the events that survive."""
        for raw in rows:
            clean, removed = self.policy.scrub(raw)
            for name in removed:
                self.dropped_fields[name.lower()] += 1
            try:
                event = mapper(clean)
            except (KeyError, ValueError, TypeError):
                event = None
            if event is None:
                self.dropped_rows += 1
                continue
            self.mapped_rows += 1
            yield event

    # -- CERT Insider Threat Test Dataset (r4.2 and later)

    def map_cert(self, row: dict) -> Event | None:
        """Map one row of a CERT CSV, tagged with ``_cert_source``."""
        source = (row.get("_cert_source") or "").lower()
        user = row.get("user")
        ts = _parse_cert_date(row.get("date"))
        if not user or ts is None:
            return None
        actor = self.resolver.resolve(user)
        host = row.get("pc")
        base = dict(timestamp=ts, actor_id=actor, host=host, source_system="cert")

        if source.startswith("logon"):
            activity = (row.get("activity") or "").lower()
            action = "logon_success" if activity == "logon" else "logoff"
            return Event(category=Category.AUTHENTICATION, action=action, **base)

        if source.startswith("file"):
            name = row.get("filename")
            activity = (row.get("activity") or "file open").lower()
            to_removable = str(row.get("to_removable_media", "")).lower() == "true"
            action = {
                "file open": "file_read",
                "file copy": "file_copy",
                "file write": "file_write",
                "file delete": "file_delete",
            }.get(activity, "file_read")
            extra = {"to_removable_media": True} if to_removable else {}
            return Event(
                category=Category.FILE,
                action=action,
                object_name=name,
                object_sensitivity=classify_sensitivity(name),
                extra=extra,
                **base,
            )

        if source.startswith("device"):
            activity = (row.get("activity") or "").lower()
            action = "usb_connect" if activity == "connect" else "usb_disconnect"
            return Event(category=Category.REMOVABLE_MEDIA, action=action, **base)

        if source.startswith("http"):
            url = row.get("url") or ""
            activity = (row.get("activity") or "www visit").lower()
            action = "upload" if "upload" in activity else (
                "download" if "download" in activity else "web_visit"
            )
            return Event(
                category=Category.NETWORK, action=action, destination=url, **base
            )

        if source.startswith("email"):
            recipients = ";".join(
                str(row.get(k) or "") for k in ("to", "cc", "bcc")
            ).lower()
            domains = {
                r.split("@", 1)[1].strip()
                for r in re.split(r"[;,]", recipients)
                if "@" in r
            }
            external = any(d and d != CERT_INTERNAL_DOMAIN for d in domains)
            size = int(float(row.get("size") or 0))
            attachments = row.get("attachments")
            n_attach = (
                int(attachments)
                if str(attachments or "").isdigit()
                else len([a for a in str(attachments or "").split(";") if a])
            )
            return Event(
                category=Category.EMAIL,
                action="email_send_external" if external else "email_send",
                bytes=size,
                destination=",".join(sorted(domains)) or None,
                extra={"attachments": n_attach, "external": external},
                **base,
            )
        return None

    # -- generic records (CSV / JSONL already close to the schema)

    def map_generic(self, row: dict) -> Event | None:
        """Map a row that already uses (most of) the Sentry field names."""
        ts = _parse_any_date(row.get("timestamp") or row.get("@timestamp") or row.get("time"))
        actor = row.get("actor_id") or row.get("user") or row.get("user.name")
        category = row.get("category") or row.get("event.category")
        action = row.get("action") or row.get("event.action")
        if ts is None or not actor or not category or not action:
            return None
        obj = row.get("object_name") or row.get("file.path")
        sens = row.get("object_sensitivity") or classify_sensitivity(obj).value
        known = {
            "timestamp", "@timestamp", "time", "actor_id", "user", "user.name",
            "category", "event.category", "action", "event.action", "object_name",
            "file.path", "object_sensitivity",
        }
        fields = {k: v for k, v in row.items() if k not in known and v not in (None, "")}
        event = Event.from_dict(
            {
                "timestamp": ts.isoformat(),
                "actor_id": self.resolver.resolve(str(actor)),
                "category": str(category).lower(),
                "action": str(action).lower(),
                "object_name": obj,
                "object_sensitivity": sens,
                **fields,
            }
        )
        for int_field in ("bytes", "object_count"):
            value = getattr(event, int_field)
            if isinstance(value, str):
                setattr(event, int_field, int(float(value or 0)))
        return event
