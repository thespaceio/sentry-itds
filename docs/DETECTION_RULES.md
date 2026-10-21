# Writing detection rules

Rules live in `rules/` as YAML. They load at startup and are validated: an unknown feature, context, severity or ATT&CK id stops the load with a clear error rather than silently never firing.

## Two kinds of rule

**Event match.** Count today's events that match every field; fire at `threshold`.

```yaml
id: personal_cloud_upload
title: Upload to consumer file-sharing service
severity: medium          # low | medium | high | critical
confidence: 0.7           # 0..1, how often this is a real problem when it fires
description: >
  Data moved to Dropbox, Google Drive, MEGA or similar from a corporate host.
match:
  action: upload
  destination: ["*dropbox.com", "*drive.google.com", "*mega.nz"]
threshold: 1
tags: [exfiltration, cloud]
attack: [T1567.002]
```

Match fields are any `Event` attribute (`action`, `category`, `destination`, `object_name`, `host`, `country`, `source_system`, ...) or `extra.<key>`. Values are shell wildcards, case-insensitive; a list means any of them.

**Daily aggregate.** Conditions on the person's feature vector for the day. All must hold.

```yaml
id: departing_employee_bulk_access
title: Departing employee accessing files in bulk
severity: critical
confidence: 0.95
aggregate:
  window: day
  condition:
    - file_read_count > 250
  require_context:
    - departing
attack: [T1039, T1213, T1074]
```

Operators: `>`, `>=`, `<`, `<=`, `==`, `!=`. Features:

| Feature | Meaning |
|---|---|
| `event_count` | all events |
| `file_read_count`, `file_write_count`, `distinct_files` | file activity |
| `restricted_file_count`, `confidential_file_count` | by sensitivity |
| `total_bytes`, `upload_bytes`, `personal_cloud_bytes` | data movement |
| `external_email_count`, `external_email_bytes` | mail leaving the organisation |
| `external_share_count` | anonymous or external sharing links (Microsoft 365) |
| `removable_media_count`, `removable_media_bytes` | USB |
| `logon_count`, `failed_logon_count`, `distinct_hosts`, `distinct_countries` | authentication |
| `privileged_action_count` | elevated commands, admin actions |
| `night_event_count` | events between 22:00 and 06:00 |
| `weekend` | 1 on Saturday and Sunday |

## Context

`require_context` gates a rule on facts about the person rather than the activity:

* `departing`: notice given and last day not yet passed (from HR data)
* `privileged`: an administrator account
* `new_joiner`: joined in the last 30 days

The same volume can be routine for one person and the strongest signal there is for another. Context is how a rule says so.

## Tags that change the score

`off-hours` and `sensitive-data` (or `off_hours`, `restricted_data`) apply the off-hours (x1.3) and restricted data (x1.6) multipliers to the finding.

## Choosing severity and confidence

* **critical**: almost never innocent (canary file, audit log cleared, departing employee uploading gigabytes). One finding should come close to opening a case.
* **high**: often a real problem, sometimes routine for a role.
* **medium**: context for a case, rarely enough on its own.
* **low**: background colour.

Confidence is your honest estimate of precision. Once analysts have recorded verdicts on a rule, `python -m itds rules` shows its measured precision, and the dashboard marks rules under 20% precision with five or more verdicts for tuning.

## ATT&CK

Every shipped rule maps to at least one technique from the catalogue in `itds/detect/attack.py`. Only claim a technique the rule's evidence actually supports. `python -m itds attack` prints the coverage matrix.

## Testing a rule

```python
from itds.baseline.profiler import extract_daily_features
from itds.detect.rules import RuleEngine, load_rules

rules = [r for r in load_rules("rules") if r.id == "my_rule"]
feats = extract_daily_features(events)[("u001", day)]
print(RuleEngine(rules).evaluate("u001", day, events, feats, identity))
```

Add a test in `tests/test_rules.py` with one event list that should fire and one that should not.
