"""Importers for real log sources.

Each importer reads a common export format, maps the records that carry
behavioural signal into ``Event`` objects, and ignores the rest. Everything
passes through the normalizer's privacy gate, so forbidden fields are dropped
whatever the source supplies.

Supported:

* ``windows``  Windows Security log as JSON or JSONL. Accepts the shapes
               produced by Winlogbeat/Elastic (``winlog.event_data``),
               EVTX-to-JSON tools (``Event.System`` / ``Event.EventData``) and
               flat ``Get-WinEvent`` exports with an ``EventData`` object.
* ``auditd``   Linux ``/var/log/audit/audit.log`` (raw or ENRICHED format).
* ``m365``     Microsoft 365 unified audit log CSV export (Purview).
* ``cert``     a CERT Insider Threat Test Dataset release directory.
* ``jsonl`` / ``csv``  records that already use Sentry field names.

See docs/DATASET.md for what each source needs to be configured to log.
"""

from __future__ import annotations

import json
import re
import shlex
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..normalize.normalizer import IdentityResolver, Normalizer, classify_sensitivity
from ..schema import Category, Event, Identity
from .loaders import load_cert, load_csv, load_jsonl

# -- helpers -----------------------------------------------------------------


def _dig(obj: Any, path: str) -> Any:
    """Get a dotted path from nested dicts; also accepts flat dotted keys."""
    if isinstance(obj, dict) and path in obj:
        return obj[path]
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _first(obj: Any, *paths: str) -> Any:
    for p in paths:
        v = _dig(obj, p)
        if v not in (None, "", "-"):
            return v
    return None


def _parse_time(raw: Any) -> datetime | None:
    if raw is None:
        return None
    if isinstance(raw, dict):  # {"SystemTime": "..."} or {"#attributes": {...}}
        raw = _first(raw, "SystemTime", "#attributes.SystemTime", "@SystemTime")
        if raw is None:
            return None
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw / 1000 if raw > 1e11 else raw, UTC)
    s = str(raw).strip()
    m = re.match(r"^/Date\((\d+)\)/$", s)  # PowerShell ConvertTo-Json
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, UTC)
    s = s.replace("Z", "+00:00")
    # Trim sub-microsecond precision that fromisoformat rejects.
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        for fmt in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _read_json_records(path: Path) -> Iterator[dict]:
    text = path.read_text(encoding="utf-8-sig", errors="replace").strip()
    if not text:
        return
    if text[0] == "[":
        data = json.loads(text)
        yield from (r for r in data if isinstance(r, dict))
    elif text[0] == "{" and "\n{" not in text:
        data = json.loads(text)
        if isinstance(data, dict) and isinstance(data.get("Events"), list):
            yield from data["Events"]
        else:
            yield data
    else:
        yield from load_jsonl(path)


IGNORED_ACCOUNTS = {"system", "local service", "network service", "anonymous logon",
                    "dwm-1", "dwm-2", "umfd-0", "umfd-1", "-", ""}


def _real_user(name: Any) -> str | None:
    if not name:
        return None
    s = str(name).strip()
    if s.endswith("$") or s.lower() in IGNORED_ACCOUNTS:
        return None
    return s


# -- Windows Security --------------------------------------------------------

WINDOWS_LOGON_TYPES = {"2": "interactive", "3": "network", "7": "unlock",
                       "10": "remote_interactive", "11": "cached"}


class WindowsSecurityMapper:
    """Maps Windows Security events by ID. Unlisted IDs are ignored."""

    def __init__(self, resolver: IdentityResolver) -> None:
        self.resolver = resolver
        self.ignored: Counter = Counter()

    def __call__(self, rec: dict) -> Event | None:
        eid = _first(rec, "EventID", "Id", "event.code", "winlog.event_id",
                     "Event.System.EventID", "System.EventID")
        if isinstance(eid, dict):
            eid = eid.get("#text") or eid.get("value")
        try:
            eid = int(str(eid))
        except (TypeError, ValueError):
            return None
        data = (_first(rec, "winlog.event_data", "Event.EventData", "EventData",
                       "Event.UserData.LogFileCleared", "UserData.LogFileCleared") or {})
        if not isinstance(data, dict):
            data = {}
        get = lambda *k: _first(data, *k) or _first(rec, *k)  # noqa: E731
        ts = _parse_time(_first(rec, "TimeCreated", "@timestamp", "timestamp",
                                "Event.System.TimeCreated", "System.TimeCreated"))
        host = _first(rec, "Computer", "MachineName", "host.name", "Event.System.Computer",
                      "System.Computer", "computer_name")
        if ts is None:
            return None

        def ev(user, category, action, **kw) -> Event | None:
            user = _real_user(user)
            if not user:
                return None
            return Event(timestamp=ts, actor_id=self.resolver.resolve(user), category=category,
                         action=action, host=host, source_system="windows",
                         extra={"event_id": eid, **kw.pop("extra", {})}, **kw)

        if eid in (4624, 4625):
            logon_type = str(get("LogonType") or "")
            ip = get("IpAddress", "source.ip")
            return ev(get("TargetUserName"), Category.AUTHENTICATION,
                      "logon_success" if eid == 4624 else "logon_failure",
                      source_ip=None if ip in ("-", "::1", "127.0.0.1") else ip,
                      extra={"logon_type": WINDOWS_LOGON_TYPES.get(logon_type, logon_type)})
        if eid in (4663, 5145):
            obj = get("ObjectName") or "\\".join(
                p for p in (get("ShareName"), get("RelativeTargetName")) if p)
            access = f"{get('AccessList') or ''} {get('AccessMask') or ''}".lower()
            write = any(k in access for k in ("writedata", "%%4417", "0x2", "appenddata"))
            delete = "delete" in access or "%%1537" in access
            action = "file_delete" if delete else ("file_write" if write else "file_read")
            return ev(get("SubjectUserName"), Category.FILE, action, object_name=obj or None,
                      object_sensitivity=classify_sensitivity(obj))
        if eid == 4688:
            elevated = str(get("TokenElevationType") or "") in ("%%1937", "TokenElevationTypeFull")
            if not elevated:
                self.ignored["4688 (not elevated)"] += 1
                return None
            return ev(get("SubjectUserName"), Category.PROCESS, "privileged_command",
                      extra={"process": get("NewProcessName"), "privileged": True})
        if eid == 1102:
            return ev(get("SubjectUserName"), Category.PROCESS, "log_cleared")
        if eid == 4719:
            return ev(get("SubjectUserName"), Category.PROCESS, "audit_policy_change")
        if eid in (4728, 4732, 4756):
            return ev(get("SubjectUserName"), Category.PROCESS, "group_membership_change",
                      extra={"group": get("TargetUserName"), "member": get("MemberName")})
        if eid == 6416:
            return ev(get("SubjectUserName"), Category.REMOVABLE_MEDIA, "usb_connect",
                      extra={"device": get("DeviceDescription")})
        self.ignored[str(eid)] += 1
        return None


# -- Linux auditd ------------------------------------------------------------

_AUDIT_HEAD = re.compile(r"type=(\S+)\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s*(.*)")


def _audit_fields(body: str) -> dict[str, str]:
    """Parse key=value pairs, including the msg='...' block of USER_* records
    and the uppercase enriched fields after the \\x1d separator."""
    body = body.replace("\x1d", " ")
    m = re.search(r"msg='(.*)'", body)
    if m:
        body = body[: m.start()] + " " + m.group(1) + " " + body[m.end():]
    out: dict[str, str] = {}
    try:
        parts = shlex.split(body, posix=True)
    except ValueError:
        parts = body.split()
    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v.strip('"')
    return out


def read_auditd(path: Path, resolver: IdentityResolver, host_default: str | None) -> Iterator[Event]:
    groups: dict[str, list[tuple[str, float, dict]]] = defaultdict(list)
    order: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = _AUDIT_HEAD.search(line)
            if not m:
                continue
            rtype, ts, serial, body = m.groups()
            key = f"{ts}:{serial}"
            if key not in groups:
                order.append(key)
            groups[key].append((rtype, float(ts), _audit_fields(body)))

    for key in order:
        records = groups[key]
        types = {r[0] for r in records}
        ts = datetime.fromtimestamp(records[0][1], UTC)
        merged: dict[str, str] = {}
        for _, _, f in records:
            for k, v in f.items():
                merged.setdefault(k, v)
        user = (merged.get("acct") if merged.get("acct") not in (None, "(unknown)") else None) \
            or merged.get("AUID") or (
                f"uid{merged['auid']}" if merged.get("auid") not in (None, "4294967295") else None)
        user = _real_user(user)
        if not user or user == "root":
            # Activity attributed only to root cannot be tied to a person.
            continue
        host = merged.get("node") or merged.get("hostname") or host_default
        if host in ("?", ""):
            host = host_default
        ip = merged.get("addr") if merged.get("addr") not in (None, "?") else None
        actor = resolver.resolve(user)
        success = merged.get("res", "").startswith("success")

        if "USER_LOGIN" in types:
            yield Event(timestamp=ts, actor_id=actor, category=Category.AUTHENTICATION,
                        action="logon_success" if success else "logon_failure",
                        host=host, source_ip=ip, source_system="auditd",
                        extra={"terminal": merged.get("terminal")})
        elif "USER_AUTH" in types and not success:
            yield Event(timestamp=ts, actor_id=actor, category=Category.AUTHENTICATION,
                        action="logon_failure", host=host, source_ip=ip, source_system="auditd")
        elif "USER_CMD" in types:
            cmd = merged.get("cmd", "")
            if re.fullmatch(r"[0-9A-Fa-f]+", cmd or "") and len(cmd) % 2 == 0:
                try:
                    cmd = bytes.fromhex(cmd).decode("utf-8", "replace")
                except ValueError:
                    pass
            yield Event(timestamp=ts, actor_id=actor, category=Category.PROCESS,
                        action="privileged_command", host=host, source_system="auditd",
                        extra={"command": cmd[:200], "privileged": True})
        elif "SYSCALL" in types and merged.get("key") not in (None, "(null)"):
            paths = [f.get("name") for t, _, f in records if t == "PATH" and f.get("name")]
            obj = next((p for p in paths if p.startswith("/")), paths[0] if paths else None)
            k = merged.get("key", "")
            action = "file_write" if "write" in k or "modify" in k else "file_read"
            if "usb" in k or "removable" in k:
                yield Event(timestamp=ts, actor_id=actor, category=Category.REMOVABLE_MEDIA,
                            action="usb_write", host=host, object_name=obj, source_system="auditd")
            else:
                yield Event(timestamp=ts, actor_id=actor, category=Category.FILE, action=action,
                            host=host, object_name=obj,
                            object_sensitivity=classify_sensitivity(obj),
                            source_system="auditd", extra={"audit_key": k})


# -- Microsoft 365 unified audit log ------------------------------------------

M365_ACTIONS: dict[str, tuple[Category, str]] = {
    "UserLoggedIn": (Category.AUTHENTICATION, "logon_success"),
    "UserLoginFailed": (Category.AUTHENTICATION, "logon_failure"),
    "FileAccessed": (Category.FILE, "file_read"),
    "FilePreviewed": (Category.FILE, "file_read"),
    "FileDownloaded": (Category.FILE, "file_download"),
    "FileSyncDownloadedFull": (Category.FILE, "file_download"),
    "FileCopied": (Category.FILE, "file_copy"),
    "FileUploaded": (Category.FILE, "file_write"),
    "FileModified": (Category.FILE, "file_write"),
    "FileDeleted": (Category.FILE, "file_delete"),
    "AnonymousLinkCreated": (Category.NETWORK, "external_share"),
    "SharingInvitationCreated": (Category.NETWORK, "external_share"),
    "AddedToSecureLink": (Category.NETWORK, "external_share"),
    "Send": (Category.EMAIL, "email_send"),
}


class M365Mapper:
    def __init__(self, resolver: IdentityResolver, internal_domains: set[str]) -> None:
        self.resolver = resolver
        self.internal = {d.lower() for d in internal_domains}
        self.ignored: Counter = Counter()

    def __call__(self, row: dict) -> Event | None:
        op = row.get("Operations") or row.get("Operation") or ""
        user = row.get("UserIds") or row.get("UserId") or ""
        ts = _parse_time(row.get("CreationDate") or row.get("CreationTime"))
        try:
            data = json.loads(row.get("AuditData") or "{}")
        except json.JSONDecodeError:
            data = {}
        user = _real_user(user or data.get("UserId"))
        if ts is None or not user:
            return None
        actor = self.resolver.resolve(user)
        ip = data.get("ClientIP") or data.get("ActorIpAddress")
        base = dict(timestamp=ts, actor_id=actor, source_ip=ip, source_system="m365")

        if op in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules"):
            params = {p.get("Name"): str(p.get("Value", "")) for p in data.get("Parameters", [])
                      if isinstance(p, dict)}
            fwd = " ".join(params.get(k, "") for k in
                           ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo"))
            domains = set(re.findall(r"@([\w.-]+)", fwd.lower()))
            if domains and (not self.internal or domains - self.internal):
                return Event(category=Category.EMAIL, action="mail_forward_rule_external",
                             destination=",".join(sorted(domains)),
                             extra={"rule": params.get("Name")}, **base)
            self.ignored[op] += 1
            return None

        mapped = M365_ACTIONS.get(op)
        if mapped is None:
            self.ignored[op or "(blank)"] += 1
            return None
        category, action = mapped
        obj = data.get("ObjectId") or data.get("SourceRelativeUrl")
        if data.get("SourceFileName") and obj and not str(obj).endswith(data["SourceFileName"]):
            obj = f"{obj}/{data['SourceFileName']}"
        extra: dict[str, Any] = {}
        if data.get("SensitivityLabelId"):
            extra["sensitivity_label"] = data["SensitivityLabelId"]
        if category is Category.NETWORK:
            extra["target"] = data.get("TargetUserOrGroupName")
        return Event(category=category, action=action, object_name=obj,
                     object_sensitivity=classify_sensitivity(obj) if category is Category.FILE
                     else None, extra=extra, **base)


# -- identities --------------------------------------------------------------

def load_identities_csv(path: str | Path) -> dict[str, Identity]:
    """HR extract: actor_id, display_name, department, role, is_privileged,
    joined_on, departure_notice_on, last_day_on, aliases (';' separated)."""
    def dt(v):
        return _parse_time(v) if v else None

    out = {}
    for row in load_csv(path):
        actor = (row.get("actor_id") or "").strip()
        if not actor:
            continue
        out[actor] = Identity(
            actor_id=actor,
            display_name=row.get("display_name") or None,
            department=row.get("department") or None,
            role=row.get("role") or None,
            manager_id=row.get("manager_id") or None,
            is_privileged=str(row.get("is_privileged", "")).lower() in {"1", "true", "yes"},
            joined_on=dt(row.get("joined_on")),
            departure_notice_on=dt(row.get("departure_notice_on")),
            last_day_on=dt(row.get("last_day_on")),
        )
    return out


def resolver_from_identities(path: str | Path | None) -> IdentityResolver:
    resolver = IdentityResolver()
    if path:
        for row in load_csv(path):
            actor = (row.get("actor_id") or "").strip()
            if actor:
                aliases = [a.strip() for a in (row.get("aliases") or "").split(";") if a.strip()]
                resolver.register(actor, *aliases)
    return resolver


# -- driver ------------------------------------------------------------------

def import_files(fmt: str, paths: Iterable[str | Path], *, identities: str | Path | None = None,
                 cert_users: list[str] | None = None,
                 internal_domains: set[str] | None = None) -> tuple[list[Event], dict]:
    resolver = resolver_from_identities(identities)
    normalizer = Normalizer(resolver=resolver)
    events: list[Event] = []
    ignored: Counter = Counter()
    for raw_path in paths:
        path = Path(raw_path)
        if fmt == "windows":
            mapper = WindowsSecurityMapper(resolver)
            events.extend(normalizer.normalize_many(_read_json_records(path), mapper))
            ignored.update(mapper.ignored)
        elif fmt == "auditd":
            for e in read_auditd(path, resolver, host_default=path.stem):
                clean, removed = normalizer.policy.scrub(e.extra)
                for k in removed:
                    normalizer.dropped_fields[k] += 1
                e.extra = clean
                events.append(e)
        elif fmt == "m365":
            mapper = M365Mapper(resolver, internal_domains or set())
            events.extend(normalizer.normalize_many(load_csv(path), mapper))
            ignored.update(mapper.ignored)
        elif fmt == "cert":
            rows = load_cert(path, users=set(cert_users) if cert_users else None)
            events.extend(normalizer.normalize_many(rows, normalizer.map_cert))
        elif fmt == "jsonl":
            events.extend(normalizer.normalize_many(load_jsonl(path), normalizer.map_generic))
        elif fmt == "csv":
            events.extend(normalizer.normalize_many(load_csv(path), normalizer.map_generic))
        else:
            raise ValueError(f"unknown format {fmt!r}")
    events.sort(key=lambda e: e.timestamp)
    report = {
        "events": len(events),
        "actors": len({e.actor_id for e in events}),
        "unmapped records": normalizer.dropped_rows + sum(ignored.values()),
        "forbidden fields removed": dict(normalizer.dropped_fields) or "none",
    }
    if ignored:
        report["ignored by type"] = dict(ignored.most_common(8))
    return events, report
