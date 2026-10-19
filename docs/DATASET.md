# Datasets and log sources

## Synthetic (built in)

```bash
python -m itds generate --users 60 --days 60 --seed 42
```

A synthetic organisation with routine noise and planted scenarios with known ground truth. The generator is built to break naive systems:

| Scenario | Label | What happens in the scored window |
|---|---|---|
| Departing exfiltration | `departing_exfil` (threat) | Resigned; copies 300 to 700 files on four evenings, uploads gigabytes to Dropbox and MEGA, writes to USB once |
| Data hoarder | `data_hoarder` (threat) | Not leaving; reads other departments' restricted files late at night, a little more every week |
| Compromised account | `compromised_account` (threat) | Stolen credential: logons from two countries, failed logons, 20 to 45 privileged commands on up to 30 servers, at 01:00 to 04:00 |
| Negligent sharer | `negligent_sharer` (innocent) | Salesperson who emails large attachments and uses WeTransfer every day, as they always have |
| Negligent USB | `negligent_usb` (innocent) | Backs files up to a USB stick every Friday |
| Clean leavers | none | Two people resign and keep working normally. They must never open a case |
| New joiner | none | Joins nine days before the end; assessed against their department |

Plus everyday noise: weekend workers, late workers, occasional personal Dropbox uploads, sick days, failed logons.

**Caveat:** the generator and the detectors were built by the same people. Synthetic results show that the logic works on data designed to stress it, not how Sentry would perform on your network.

## CERT Insider Threat Test Dataset

Carnegie Mellon University's synthetic insider threat corpus, the standard public benchmark for this problem. Licence CC BY 4.0, doi:[10.1184/R1/12841247](https://doi.org/10.1184/R1/12841247).

Release r4.2: about 1,000 users over 17 months and around 70 insiders across three scenarios (after-hours USB and leak-site uploads; job hunting then data theft before leaving; a disgruntled administrator who plants a keylogger and uses a supervisor's credentials).

Sentry reads `logon.csv`, `device.csv`, `file.csv`, `email.csv` and the monthly `LDAP/` staff lists. `http.csv` (about 14 GB) is skipped by default, so web-based signals such as leak-site uploads and job-site browsing are not available to the detectors. That is a real handicap on scenarios 1 and 2 and is stated with every result.

Run it on GitHub Actions: **Actions > Accuracy (CERT r4.2) > Run workflow**. Or locally:

```bash
python scripts/evaluate_cert.py --data path/to/r4.2 --answers path/to/answers --out results/cert
```

The evaluation replays the dataset in 14-day windows, each trained on the 60 days before it, and checks every window's case queue against the answer key. It runs twice: with HR departure dates derived from the LDAP files (hindsight relative to the logs, but what an HR system would know) and from logs alone.

## Your own logs

```bash
python -m itds import --format windows security.json --identities hr.csv
python -m itds import --format auditd /var/log/audit/audit.log --append
python -m itds import --format m365 audit_export.csv --internal-domain corp.example --append
python -m itds run
```

### HR identities (`--identities`)

CSV with `actor_id, display_name, department, role, is_privileged, joined_on, departure_notice_on, last_day_on, aliases`. Aliases (`;` separated) map every login name, email address and Linux uid to one person. See `examples/hr_identities.csv`.

### Windows Security log

JSON or JSONL from Winlogbeat or Elastic Agent, EVTX converters, or `Get-WinEvent | ConvertTo-Json`. Mapped events:

| Event | Becomes |
|---|---|
| 4624 / 4625 | logon success / failure |
| 4663, 5145 | file read, write or delete (enable object access auditing on sensitive folders) |
| 4688 with an elevated token | privileged command |
| 1102 | audit log cleared |
| 4719 | audit policy changed |
| 4728, 4732, 4756 | member added to a security group |
| 6416 | external device recognised (USB) |

Machine accounts (`WS-1042$`), `SYSTEM` and similar are ignored.

### Linux auditd

Raw or ENRICHED `audit.log`. Logins (`USER_LOGIN`), failed authentication, `sudo` commands (`USER_CMD`, hex-decoded) and watched files. Watch sensitive paths with a key containing `sentry`:

```
-w /srv/hr -p r -k sentry_sensitive
-w /srv/finance -p wa -k sentry_write
```

Activity attributed only to root is skipped: it cannot be tied to a person.

### Microsoft 365 unified audit log

CSV exported from Microsoft Purview audit search (`CreationDate, UserIds, Operations, AuditData`). Sign-ins, file access, downloads, uploads, external and anonymous sharing links, sent mail, and inbox rules that forward mail outside the organisation (pass `--internal-domain`).

### Generic CSV or JSONL

Records that already use Sentry's field names (`timestamp, actor_id, category, action, ...`) or the common ECS names (`@timestamp, user.name, event.category, event.action, file.path`).
