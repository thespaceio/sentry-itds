"""Importers: Windows Security, Linux auditd, Microsoft 365, generic records."""

from pathlib import Path

from itds.baseline.profiler import extract_daily_features
from itds.detect.rules import RuleEngine, load_rules
from itds.ingest.sources import import_files, load_identities_csv
from itds.schema import Category

EX = Path(__file__).resolve().parent.parent / "examples"
HR = EX / "hr_identities.csv"


def test_windows_events_map_to_hr_identities():
    events, report = import_files("windows", [EX / "windows_security.json"], identities=HR)
    actors = {e.actor_id for e in events}
    assert actors <= {"u101", "u102", "u103"}
    actions = [e.action for e in events]
    assert "logon_success" in actions and "logon_failure" in actions
    assert "file_read" in actions and "file_write" in actions
    assert {"log_cleared", "group_membership_change", "privileged_command"} <= set(actions)
    assert any(e.category is Category.REMOVABLE_MEDIA for e in events)
    # Machine accounts and non-elevated processes are ignored.
    assert not any(e.actor_id.endswith("$") for e in events)
    assert actions.count("privileged_command") == 1
    assert report["unmapped records"] >= 2


def test_windows_file_access_is_classified():
    events, _ = import_files("windows", [EX / "windows_security.json"], identities=HR)
    hr_read = next(e for e in events if e.object_name and "salary_review" in e.object_name)
    assert hr_read.object_sensitivity.value == "restricted"


def test_windows_log_clear_trips_the_rule():
    events, _ = import_files("windows", [EX / "windows_security.json"], identities=HR)
    rules = [r for r in load_rules("rules") if r.id == "audit_log_cleared"]
    kelechi = [e for e in events if e.actor_id == "u103"]
    day = kelechi[0].timestamp.date()
    feats = extract_daily_features(kelechi)[("u103", day)]
    found = RuleEngine(rules).evaluate("u103", day, kelechi, feats)
    assert found and found[0].attack == ["T1070"]


def test_auditd_login_sudo_and_watched_file():
    events, _ = import_files("auditd", [EX / "audit.log"], identities=HR)
    assert {e.actor_id for e in events} == {"u104"}
    actions = [e.action for e in events]
    assert actions.count("logon_success") == 1
    assert actions.count("logon_failure") == 1
    sudo = next(e for e in events if e.action == "privileged_command")
    assert sudo.extra["command"] == "cat /etc/shadow"  # hex-decoded
    watched = next(e for e in events if e.category is Category.FILE)
    assert watched.object_name == "/srv/hr/personnel/contracts.csv"
    # root-only activity (cron) cannot be attributed to a person and is skipped
    assert not any(e.object_name == "/etc/crontab" for e in events)


def test_m365_mapping_and_external_forwarding():
    events, report = import_files("m365", [EX / "m365_audit.csv"], identities=HR,
                                  internal_domains={"corp.example"})
    assert {e.actor_id for e in events} == {"u101"}
    actions = [e.action for e in events]
    assert "file_download" in actions
    assert "external_share" in actions
    # Only the rule forwarding to gmail.com counts; the internal one does not.
    assert actions.count("mail_forward_rule_external") == 1
    rules = [r for r in load_rules("rules") if r.id == "mail_forwarding_external"]
    day = events[0].timestamp.date()
    feats = extract_daily_features(events)[("u101", day)]
    assert RuleEngine(rules).evaluate("u101", day, events, feats)
    assert feats["external_share_count"] == 1


def test_identity_csv():
    ids = load_identities_csv(HR)
    assert ids["u103"].is_privileged
    assert ids["u102"].departure_notice_on is not None


def test_generic_jsonl_roundtrip(tmp_path):
    p = tmp_path / "e.jsonl"
    p.write_text(
        '{"timestamp": "2026-09-01T10:00:00Z", "user": "CORP\\\\aokafor", "category": "file",'
        ' "action": "file_read", "file.path": "/hr/personnel/x.pdf", "bytes": "2048",'
        ' "keystrokes": "never stored"}\n'
    )
    events, report = import_files("jsonl", [p], identities=HR)
    assert len(events) == 1
    e = events[0]
    assert e.actor_id == "u101"
    assert e.bytes == 2048
    assert e.object_sensitivity.value == "restricted"
    assert "keystrokes" not in e.extra
    assert report["forbidden fields removed"] == {"keystrokes": 1}
