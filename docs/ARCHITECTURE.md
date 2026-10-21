# Architecture

Sentry turns activity logs into a short, ranked, explained queue of people worth an analyst's time. Every layer exists because of a specific way that behavioural monitoring fails without it.

```
 logs ─► ingest ─► normalize ─► baseline ─► detect ─────────► score ─► cases ─► dashboard / API
         (sources)  (identity,   (self,      rules              (decay,   (budget)  (pseudonyms,
                     privacy     peer,       statistics         context,           reveal,
                     gate)       global)     isolation forest   diversity)         feedback, audit)
                                                 ▲                   ▲
                                                 └── suppressions ◄──┴── analyst verdicts
```

## 1. Ingest (`itds/ingest/`)

Readers for Windows Security events, Linux auditd, Microsoft 365 audit exports, the CERT dataset and generic CSV or JSONL, plus a synthetic generator with planted scenarios.

**Without it:** detections get written against one vendor's field names and break the day the log source changes.

## 2. Normalize (`itds/normalize/`)

Every record becomes one `Event` (ECS-style field names). Identifiers are resolved to one actor (`CORP\aokafor`, `adaeze.okafor@corp.example` and `uid1001` become `u101`), objects get a sensitivity class, and **forbidden fields are stripped before anything is stored**: message bodies, file contents, keystrokes, screenshots and similar never enter the system, whatever the source sends.

**Without it:** one person looks like three quiet people, and the system quietly collects content it has no business holding.

## 3. Baseline (`itds/baseline/`)

Each person's activity is reduced to one feature vector per day (21 features: files read, restricted files, data moved, personal cloud bytes, external email, USB, logons, failed logons, hosts, privileged commands, night activity and so on). Three baselines are learned:

| Baseline | Question | Used when |
|---|---|---|
| Self | Is this odd *for them*? | At least 7 days of history |
| Peer | Is this odd *for their department*? | New joiners, sparse history |
| Global | Is this odd *anywhere*? | Peer group smaller than 5 |

Baselines are fitted strictly on data **before** the window being scored (`as_of`).

**Without it:** a user's anomalous fortnight is absorbed into their definition of normal, and the system stops detecting anything while still looking healthy.

## 4. Detect (`itds/detect/`)

Three engines, because they fail in different ways:

| Engine | Strength | Weakness | Guardrails |
|---|---|---|---|
| Rules (YAML) | Precise, readable, context-aware (`require_context: departing`) | Only finds what someone wrote down | Unknown features, contexts and ATT&CK ids fail at load time |
| Statistics (z-scores) | Cheap, explainable ("13x their usual") | One feature at a time; noisy at small counts | Minimum counts, absolute ceilings, confidence capped at 0.9 |
| Isolation Forest | Catches unusual *combinations* | Opaque by default | Leave-one-out attribution names the drivers; ATT&CK claimed only for genuinely elevated drivers |

Every detection carries an explanation (a constructor error otherwise), evidence and MITRE ATT&CK technique ids.

## 5. Score (`itds/scoring/`)

Detections are evidence; cases are decisions. Per person:

1. weight = severity x confidence
2. halved every 7 days (decay)
3. multiplied for restricted data (x1.6) and off-hours activity (x1.3)
4. **repeats discounted geometrically** (the second instance of the same detection is worth a third of the first)
5. corroboration across engines rewarded (x1.1 for two, x1.25 for three)
6. departing (x2) and privileged (x1.5) context applied to the whole entity
7. mapped to 0 to 100 with a saturating curve
8. learned weights from analyst verdicts applied, bounded to x0.5 to x1.5

A case opens at 60, and the queue is cut to the **alert budget** (20 by default): what one analyst can genuinely review in a day.

**Without step 4:** the noisiest innocent person in the company wins the queue every day. **Without the budget:** the queue grows until nobody reads it.

## 6. Cases, feedback and audit

* `storage.py` keeps cases across runs. Re-running the pipeline refreshes scores and evidence but never overwrites an analyst's status or verdict.
* `feedback.py` records verdicts (real threat, real but authorised, false alarm), turns a false alarm into a time-limited suppression for that person only (1 to 180 days), computes per-rule precision and flags rules for tuning.
* `audit.py` is a SHA-256 hash chain over every action. `python -m itds audit verify` reports the first altered entry.
* `alerts.py` sends new cases to a webhook, Slack or email, with the pseudonym only.

## 7. API and dashboard (`itds/api/`, `itds/dashboard/`)

FastAPI with session cookies (HttpOnly, SameSite=Strict), scrypt password hashes, lockout after five failed logins, and three roles:

| Role | Can |
|---|---|
| analyst | read pseudonymous cases, add notes and verdicts, request an identity |
| lead | everything an analyst can, plus approve or deny other people's identity requests, close cases, suppress detections, read the audit log |
| admin | manage accounts and read the audit log; **cannot** read cases or approve identity requests |

The dashboard is plain JavaScript with no third-party code, served under a strict Content-Security-Policy. All text reaches the page through DOM text nodes, never `innerHTML`, so a hostile file name in a log cannot inject markup.

## Design limits

* **Batch, not streaming.** Real-time detection is a different architecture.
* **Path-based classification.** Feed labels from a DLP or classification system in production.
* **Peer groups from departments.** Behavioural clustering would group people better than the org chart.
* **Leave-one-out attribution, not Shapley values.** Good enough to rank drivers; not exact.
